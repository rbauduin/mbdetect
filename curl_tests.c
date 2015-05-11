#include <stdio.h>
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>
#include <libconfig.h>
#include "utils/mbd_utils.h"
#include "utils/mbd_version.h"

// stuff to write output to file
// *****************************
void payload_specs_init(payload_specs* specs) {
	specs->control_headers=NULL;
	specs->fd=NULL;
	specs->path=NULL;
	specs->curl_path=NULL;
}

void collect_curl_info(CURL *curl, queries_info_t *queries_info){
	long l;
	int i;
	double d;
	curl_easy_getinfo(curl,CURLINFO_LOCAL_PORT, &l);
	queries_info->info[LOCAL_PORT].llval=l;

	curl_easy_getinfo(curl,CURLINFO_NUM_CONNECTS, &l);
	queries_info->info[NUM_CONNECTS].llval=l;

	curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE, &l);
	queries_info->info[RESPONSE_CODE].llval=l;

	curl_easy_getinfo(curl,CURLINFO_SIZE_DOWNLOAD, &d);
	queries_info->info[SIZE_DOWNLOAD].fval=d;
}

// Finalise sha computation when payload received
// store string value in specs->sha
void hash_final(payload_specs* specs) {
	unsigned char out[crypto_hash_sha256_BYTES];
	crypto_hash_sha256_final(&(specs->sha_state), out);
	sodium_bin2hex(specs->sha, sizeof(out)*2+1, out, sizeof(out));
}
// extract protocol from the url
void extract_protocol(char* contents, char** protocol){
	char* separator;
	int len;
	// find the "://" separator between protocol and location
	if ((separator=strstr(contents, "://"))!=NULL) {
		// +1: strlcpy requires to take \0 in account
		len = separator-contents+1;
		*protocol=(char *)malloc(len);
		memset(*protocol, 0, len+1);
		strlcpy(*protocol,contents,len);
	}
	else{
		//FIXME
		// error, malformed url?
		*protocol = NULL;
	}
}

// extract an http header's name and value
void extract_header(char* contents, char** name, char** value){
	char* separator;
	int len;
	// find the ": " separator between name and value
	if ((separator=strstr(contents, ": "))!=NULL) {
		//name
		// +1: strlcpy requires to take \0 in account
		len = separator-contents+1;
		*name=(char *)malloc(len);
		memset(*name, 0, len);
		strlcpy(*name,contents,len);
		// value
		// length of  header value, ie starting after ": "
		// +1: strlcpy requires to take \0 in account
		// -2: do not include \r\n
		len = strlen(separator+2)+1-2;
		*value=(char *)malloc(len);
		memset(*value, 0, len);
		strlcpy(*value, separator+2, len);
	}
	else{
		//FIXME
		// error, malformed header?
		*name = NULL;
		*value = NULL;

	}
}

// Check that the headers we got correspond to what was expected:
// - sha of headers ok
// - sha of body ok
// - server received our headers correctly
// errors are added to the message string
int validate_http_headers(payload_specs *headers_specs, payload_specs *body_specs, char **message) {
	// FIXME: Maybe we can make this code more compact somehow
	int res = validate_header(headers_specs->control_headers, HEADER_HEADERS_HASH, headers_specs->sha);
	if (headers_specs->control_headers==NULL || res < 0 ) {
		snprintf(eos(*message), VALIDATION_MESSAGE_LENGTH-strlen(*message), KRED "HEADERS SPECS NOT COLLECTED, NOTHING FOUND. FIX SERVER? (server -> client)\n" KNON);
				return 0;
	} 
	if (res==HEADER_NOT_FOUND){
		snprintf(eos(*message), VALIDATION_MESSAGE_LENGTH-strlen(*message), KRED "Headers %s not found!! (server -> client)\n" KNON, HEADER_HEADERS_HASH);
	}
	else if (!res) {
		char *headers_h;
		get_header_value(headers_specs->control_headers, HEADER_HEADERS_HASH, &headers_h);
		snprintf(eos(*message), VALIDATION_MESSAGE_LENGTH-strlen(*message), KRED "DIFFERENT SHA, headers modified!! (server -> client)\n" KNON);
		snprintf(eos(*message), VALIDATION_MESSAGE_LENGTH-strlen(*message), "transmitted headers hash: *%s*\n", headers_h);
		snprintf(eos(*message), VALIDATION_MESSAGE_LENGTH-strlen(*message), "computed headers sha256 :\n*%s*\n", headers_specs->sha);
	}
	else {
		snprintf(eos(*message), VALIDATION_MESSAGE_LENGTH-strlen(*message), KGRN "Expected SHA received, headers were not modified!! (server -> client)\n" KNON);
	}

	res = validate_header(headers_specs->control_headers, HEADER_BODY_HASH, body_specs->sha);
	if (res==HEADER_NOT_FOUND){
		snprintf(eos(*message), VALIDATION_MESSAGE_LENGTH-strlen(*message), KRED "Headers %s not found!!\n" KNON, HEADER_BODY_HASH);
	}
	else if (!res) {
		char *headers_h;
		get_header_value(headers_specs->control_headers, HEADER_HEADERS_HASH, &headers_h);
		snprintf(eos(*message), VALIDATION_MESSAGE_LENGTH-strlen(*message), KRED "DIFFERENT SHA, BODY modified!! (server -> client)\n" KNON);
		snprintf(eos(*message), VALIDATION_MESSAGE_LENGTH-strlen(*message), "transmitted body hash: *%s*\n", headers_h);
		snprintf(eos(*message), VALIDATION_MESSAGE_LENGTH-strlen(*message), "computed body sha256 :\n*%s*\n", body_specs->sha);
	}
	else {
		snprintf(eos(*message), VALIDATION_MESSAGE_LENGTH-strlen(*message), KGRN "Expected SHA received, body was not modified!! (server -> client)\n" KNON);
	}

	res = validate_header(headers_specs->control_headers, HEADER_SERVER_RCVD_HEADERS, "1");
	if (res==HEADER_NOT_FOUND){
		snprintf(eos(*message), VALIDATION_MESSAGE_LENGTH-strlen(*message), KRED "Headers %s not found!!\n" KNON, HEADER_SERVER_RCVD_HEADERS);
	}
	else if (res==NO_MATCH) {
		snprintf(eos(*message), VALIDATION_MESSAGE_LENGTH-strlen(*message), KRED "SERVER GOT MODIFIED HEADERS!! (client -> server)\n" KNON);
	}
	//snprintf(eos(*message), VALIDATION_MESSAGE_LENGTH-strlen(*message), "HEADERS VALIDATIONS DONE\n");
}



// Check that the headers with header_name has the expected value
int validate_header(control_header *list, char* header_name, char* expected_value) {
	char* header_value=NULL;
	if (list==NULL || expected_value==NULL || header_name==NULL){
		client_log("null values\n");
		return NULL_OPERANDS;
	}
	get_header_value(list, header_name, &header_value);
	if (header_value==NULL) {
		return HEADER_NOT_FOUND;
	}
	if (!strcmp(expected_value,header_value)) {
		return MATCH;
	}
	else {
		return NO_MATCH;
	}
}


// add an entry in the control_headers linked list of the payload spec
void store_control_header(char* contents, control_header **list) {
	// name and value of the header
	char* name; char* value;
	
	// initialise header struct
	control_header *header = (control_header *) malloc(sizeof(control_header));
	header->next = NULL;
	extract_header(contents, &(header->name), &(header->value));

	// add it to the linked list
	if (header->name!=NULL) {
			*list = control_headers_prepend(*list, header);
	}
	else
	{
		free_control_header(header);
		free(header);
	}
}

// Works on one header line:
// - adds it to the headers sha computation (except if it is the header containing the expect sha value) 
// - stores it in the collected headers (except if it is the http status line)
void process_header(char* contents, size_t size, size_t nmemb, payload_specs *specs){
	if (!is_empty_line(contents)){
		if (!is_headers_hash_control_header(contents)){
			crypto_hash_sha256_update(&(specs->sha_state), contents, size*nmemb);
		}
		if (!is_http_status_header(contents)) {
			store_control_header(contents,&(specs->control_headers));
		}
	}
}

// callback discarding data, HTTP VERSION
// the http version handles headers in a particular way, collecting them and computing the hash
static size_t discard_data_http(void *contents, size_t size, size_t nmemb, payload_specs *specs){


	// for headers only complete lines are passed
	// if this is a control header, store it
	if (specs->type == 'H') {
		process_header(contents, size, nmemb, specs);
	}
	else{
		crypto_hash_sha256_update(&(specs->sha_state), contents, size*nmemb);
	}
	return size*nmemb;
}


// callback discarding data, GENERIC version
static size_t discard_data_generic(void *contents, size_t size, size_t nmemb, payload_specs *specs){
	return size*nmemb;
}

// callback writing data to file, HTTP version
// the http version handles headers in a particular way, collecting them and computing the hash
static size_t
write_in_file_http(void *contents, size_t size, size_t nmemb, payload_specs *specs)
{
	size_t realsize = size * nmemb, written;

	// for headers only complete lines are passed.
	// control headers are stored and added to the hash value
	if (specs->type == 'H') {
		process_header(contents,size, nmemb,  specs);
	}
	else{
		crypto_hash_sha256_update(&(specs->sha_state), contents, size*nmemb);
	}
	written = fwrite(contents, size, nmemb, specs->fd);
	return written*size;
}

// callback writing data to file, GENERIC version
static size_t
write_in_file_generic(void *contents, size_t size, size_t nmemb, payload_specs *specs)
{
	int written = fwrite(contents, size, nmemb, specs->fd);
	return written*size;
}
//------------------------------------
//





// If this is a POST, we add the header Content-Type and add it to the sha computation
// If we didn't, curl would do it automatically and screw up sha computation server side
// sale from Content-Length
void handle_post_options(control_header **additional_headers, const char * name, long value_long) {
	if (!strncmp(name, "CURLOPT_POST", max(strlen(name), strlen("CURLOPT_POST")) && value_long!=0)){
		collect_control_header_components(additional_headers, "Content-Type", "application/x-www-form-urlencoded"); 
	}
	else if(!strncmp(name, "CURLOPT_POSTFIELDSIZE", strlen("CURLOPT_POSTFIELDSIZE"))){
		// convert the long to a string
		char value[MAX_HEADER_VALUE_SIZE];
		snprintf(value, MAX_HEADER_VALUE_SIZE,"%ld", value_long);
		// add the header to the list
		collect_control_header_components(additional_headers, "Content-Length", value); 
	}
}

// set curl options
// headers to be set later by set_headers are collected in additional_header
void set_options(CURL* curl, config_setting_t *query, config_setting_t *test, int repeat, control_header **additional_headers){
	int j, options_count;
	// an option, its name and its value
	config_setting_t *option, *name, *value;
	// all options
	config_setting_t *options;
	// option's name as string, and option's string value
	const char * name_str, *value_str;
	// options's long value
	long value_long;
	// result of mapping search
	int mapping_found;
	mapping m;

	// set the options required for the code to work correctly
	// do not include headers when printing the body
	curl_easy_setopt(curl, CURLOPT_HEADER, 0L); 
	// get all debug info possible
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

	// iterate over options
	options = config_setting_get_member(query, "options");
	options_count = config_setting_length(options);
	for (j=0; j<options_count; j++){
		// get the option's entry, its name item and its value item.
		option=config_setting_get_elem(options,j);
		name = config_setting_get_member(option, "name");
		value = config_setting_get_member(option, "value");

		// get the option's name string from the option's name item.
		// then extract the mapping to know the type of its value,
		// so we call the right function (config_setting_get_string or _get_long)
		// before we finally set the option on curl
		name_str = config_setting_get_string(name);
		mapping m;
		mapping_found = find_mapping(name_str,&m);
		if (!mapping_found) {
			client_log("ERROR, no mapping was found!\n");
			exit(1);
		}
		//printf("mapping : %s %s\n",m.name,m.type);
		if (!strncmp(m.type,"str",3)) {
			// set curl option
			value_str = config_setting_get_string(value);
			curl_easy_setopt(curl, find_code(name_str), value_str); 
		}
		else if (!strncmp(m.type,"long",4)){
			// set curl option
			value_long = config_setting_get_int64(value);
			curl_easy_setopt(curl, (long) find_code(name_str), value_long); 
			// set additional headers if this is a post option
			handle_post_options(additional_headers, name_str, value_long);
		}
		else {
			client_log("NO option type MATCH\n____________________________________\n");
		}
	}
}


// add a curl header line, adding it the the headers' sha, and writing it in the file handle f.
// to not add it to the sha, or to not write to the file handle, pass NULL as their respective value
void add_curl_sha_header(CURL *curl, crypto_hash_sha256_state *state, struct curl_slist **headers, const char *header_line){
	if (state !=NULL) {
		add_sha_headers_content(state,header_line);
	}
	*headers = curl_slist_append(*headers, header_line); 
}

// build a header line from the name and value received,
// then pass that line to add_curl_sha_header
void add_curl_sha_header_components(CURL *curl, crypto_hash_sha256_state *state, struct curl_slist **headers, const char *name, const char *value){
	char header_line[MAX_HEADER_SIZE];
	build_header_line(header_line, name, value);
	add_curl_sha_header(curl, state, headers, (char*)header_line);
}
// set http headers sent by curl
// additional_headers are to be set in addition of those found in the config file. 
// This is notably use for POST headers
int set_headers(CURL* curl, config_setting_t *query, struct curl_slist* headers, config_setting_t *test, int repeat, const char *prefix, control_header *additional_headers ){
	// index, curl result, number of headers
	int j,res, headers_count;
	// the header string
	const char *header;

	crypto_hash_sha256_state headers_state;

	// we immediately initialise the body state
	crypto_hash_sha256_init(&headers_state);



	int host_set=0, accept_set=0;
	
	
	// get headers from config file
	config_setting_t *cfg_headers = config_setting_get_member(query, "headers");
	//FIXME: if no header specified, need account for default headers by curl
	if (cfg_headers!=NULL){
		// iterate over the list of header strings and add each to the curl_slist *headers
		headers_count = config_setting_length(cfg_headers);
		for (j=0; j<headers_count; j++){
			header=config_setting_get_string_elem(cfg_headers,j);
			add_curl_sha_header(curl, &headers_state, &headers, header);
			// record if we have set the host header
			if (!strncasecmp(header,"host: ", 6)) {
				host_set = 1;
			}
			if (!strncasecmp(header,"accept: ", 8)) {
				accept_set = 1;
			}
		}
	}

	// set a host header and an accept header if not already set
	// if we do not set it here, curl adds it itself which screws our sha computation
	// If we want to delete the header, we can with setting the header to "Accept:"
	if (is_protocol(curl,"http://")){
		if (!host_set){
			char host_header[1024];
			get_host_header(curl, &host_header);
			add_curl_sha_header(curl, &headers_state, &headers, host_header);
		}
		if (!accept_set){
			char accept_header[1024]="Accept: */*";
			add_curl_sha_header(curl, &headers_state, &headers, accept_header);
		}
	}

	// additional headers
	control_header * head;
	while (additional_headers!=NULL) {
		head = additional_headers;
		additional_headers=additional_headers->next;
		add_curl_sha_header_components(curl, &headers_state, &headers, head->name, head->value);
	}

	// header with commit hash (software version)
	add_curl_sha_header_components(curl, &headers_state, &headers, HEADER_COMMIT_HASH_CLIENT, GIT_COMMIT);

	// header with test_id
        const char* test_id = get_test_id(test);
	add_curl_sha_header_components(curl, &headers_state, &headers, HEADER_TEST_ID, test_id);

	// header with repetition number
	char r[4];
	snprintf(r,4, "%03d", repeat);
	add_curl_sha_header_components(curl, &headers_state, &headers, HEADER_REPETITION, r);

	// header with prefix (mptcp, csum, ...)
	add_curl_sha_header_components(curl, &headers_state, &headers, HEADER_PREFIX, prefix);
	// header with run_id
	char *run_id;
	get_run_id(&run_id);
	add_curl_sha_header_components(curl, &headers_state, &headers, HEADER_RUN_ID, run_id);


	// sha string
	char sha[crypto_hash_sha256_BYTES*2+1];
        // string of header containing sha.
	// +2 : ": "
	// +strlen(HEADER_HEADERS_HASH): name of the header
	char sha_header[crypto_hash_sha256_BYTES*2+1+2+strlen(HEADER_HEADERS_HASH)];
	// compute sha and add header
	sha_from_state(&headers_state,&sha);
	add_curl_sha_header_components(curl, NULL, &headers, HEADER_HEADERS_HASH, sha);
	
	// add the headers list to curl
    	res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers); 
	return res;
}

// returns 1 if we have the url starting with protocol
int is_protocol(CURL* curl, char* protocol) {
	char *url;
	curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &url);
	if (strspn(url,protocol)==strlen(protocol)) {
		return 1;
	}
	else {
		return 0;
	}
}

// Extracts the host part of an http url
// drops the http:// protocol part, and reads the host 
// until the fist / or the end of the string
// returns a null string if not http
int host_from_curl(CURL *curl,char (*host)[1024] ){
	int start, length, i;
	memset(host,0,1024);
	if (is_protocol(curl, "http://")){
		char *url;
		curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &url);
		start = 7;
		i=start;
		while (url[i]!='/' && url[i]!='\0')
			i++;
		length=i-start;
		strncpy(*host, url+7, length);
	}
}

// Builds the HTTP Host: header line from the url held by curl
// Returns empty string if no host extracted from curl
int get_host_header(CURL* curl, char (*host_header)[1024]){
	char host[1024];
	// get host fomr curl's url
	host_from_curl(curl, &host);
	// empty destination string
	memset(*host_header,0,sizeof(host_header));
	// copy into destination string if host was found
	if (strlen(host)>0){
		snprintf(*host_header, min(strlen(host)+7, sizeof(*host_header)),"Host: %s", host);  
	}
}

// determines the callbacks to be called according to the protocol, 
// both when data is discarded and when data is written to a file
void get_data_handlers(CURL* curl, 
		       size_t (**discard_data_function)(void*, size_t, size_t, struct write_dest*),
		       size_t (**write_in_file_function)(void*, size_t, size_t, struct write_dest*)) {
	if (is_protocol(curl,"http://")) {
		*discard_data_function=discard_data_http;
		*write_in_file_function=write_in_file_http;
	}
	else {
		*discard_data_function=discard_data_generic;
		*write_in_file_function=write_in_file_generic;
	}
}


// set the functions that curl will pass the received data to
void set_curl_data_handlers(CURL *curl, 
		            size_t (*handle_data_function)(void*, size_t, size_t, struct write_dest*),
			    payload_specs *headers_specs,
			    payload_specs *body_specs) {

		// set function handling headers and body
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, handle_data_function);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, handle_data_function);
		// set user pointer passed to these respective functions
		// Headers
		curl_easy_setopt(curl, CURLOPT_HEADERDATA, headers_specs);
		// Body
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, body_specs);

}

// when writing to a file, this function sets up the payload_specs with
// the file handle and the path it writes to
void setup_payload_spec_file(payload_specs *specs, char* path) {
		FILE *f = fopen(path,"w");
		specs->fd=f;
		specs->path=path;
}

// include curl logs references in payload_specs
void set_curl_logs_in_spec(payload_specs *specs, char *path, FILE *curl_logs) {
	specs->curl_path=(char *)malloc(strlen(path)+1);
	memset(specs->curl_path, 0, strlen(path)+1);
	strncpy(specs->curl_path, path,strlen(path));
	specs->curl_fd=curl_logs;
}

// sets up things to handle the data reaceived by curl
void set_output(CURL* curl, config_setting_t *output_dir, payload_specs *headers_specs, payload_specs *body_specs, config_setting_t *test, int repeat, const char *suffix){


	// extract test id
	const char *test_id = get_test_id(test);
	// path string retrieved from output_dir setting
	char *headers_path, *body_path;

	// FIXME : code duplicated from function build_file_paths. Should be improved
	//configure curl debug logs
	char *base_path;
	get_run_log_dir(output_dir, &base_path);
	//this is the run log path 
	mkpath(base_path);

	// setup curl logs to file with -curl suffix
	char * curl_logs_path;
	char *full_suffix;
	build_suffix(&full_suffix, suffix, "-curl");
	build_log_file_path(base_path, test_id, repeat, NULL, full_suffix, &curl_logs_path);
	free(full_suffix);
	FILE *curl_logs=fopen(curl_logs_path, "w");
	curl_easy_setopt(curl, CURLOPT_STDERR, curl_logs);

	// we put the curl logs path in both headers_specs and body_specs
	set_curl_logs_in_spec(headers_specs, curl_logs_path, curl_logs);
	set_curl_logs_in_spec(body_specs, curl_logs_path, curl_logs);


	free(curl_logs_path);
	free(base_path);

	// pointers to function that will handle the data received
	size_t (*discard_data_function)(void*, size_t, size_t, struct write_dest*);
	size_t (*write_in_file_function)(void*, size_t, size_t, struct write_dest*);
	// get data handlers, based on protocol
	get_data_handlers(curl, &discard_data_function, &write_in_file_function);

	// and initialise the sha state
	crypto_hash_sha256_init(&(body_specs->sha_state));
	crypto_hash_sha256_init(&(headers_specs->sha_state));

	// discard data if output_dir is "none"
	// immediately return in that case
	if (output_dir!=NULL) {
		const char *output_str = config_setting_get_string(output_dir);
		if (!strcmp(output_str,DISCARD_OUTPUT)){
			set_curl_data_handlers(curl,discard_data_function,headers_specs, body_specs );
			return;
		}
	}
	// we get here either if output_dir is NULL, or it is not NULL but different from DISCARD_OUTPUT
	// setup the config structure passed to successive call of the callback
	// get paths where to save headers and body respectively
	build_file_paths(output_dir, &headers_path, &body_path, test_id, repeat, suffix);

	// open file handle, setup struct and passit to curl
	// Body
	setup_payload_spec_file(body_specs, body_path);
	// Headers
	setup_payload_spec_file(headers_specs, headers_path);

	set_curl_data_handlers(curl,write_in_file_function, headers_specs, body_specs);
}





// cleans things up when curl query is done. 
void clean_output(config_setting_t *test, payload_specs *headers_specs,payload_specs  *body_specs ){
	// control headers are awlays collected, free them
	// // not here anymore, after all repetitions are done
	//control_headers_free(headers_specs->control_headers);

	// close file handles
	fclose(body_specs->fd);
	fclose(headers_specs->fd);
	// FIXME: reset user structure to empty
	// free memory allocated in set_output, and reset struct members
	body_specs->fd=NULL;
	body_specs->size=0;
	headers_specs->fd=NULL;
	headers_specs->size=0;
	upload_log(body_specs->path);
	upload_log(headers_specs->path);



	// This cannot be done here with older versions of curl.
	// This is replaced by code after a call too curl_easy_cleanup
	// Look for comment "Closing curl logs fd and uploading files"
	//
	// fclose(headers_specs->curl_fd);
	// upload_log(headers_specs->curl_path);
	// free(body_specs->curl_path);
	// free(headers_specs->curl_path);

	free(body_specs->path);
	free(headers_specs->path);
}


void run_lib_test(config_setting_t *test, config_setting_t *output_dir, const char* suffix) {
  CURL *curl;
  CURLcode res;

  // queries of a test entry, and the setting entry giving the number of time it should be issued
  config_setting_t *queries, *repeat_setting;
  // number of queries in queries config entry, its index in loop, 
  // number of time to repeat query and its index in loop
  int queries_count, k, repeat_query, l;

  // validations list entry, validation entry and validation name entry
  config_setting_t *validations, *validation, *type_entry;
  // string value of name_setting, and validation type as string
  const char * validation_str, *type_str;
  // validations number and its index in loop
  int validations_count, m;

  // headers to be set on query
  struct curl_slist * curl_headers;

  
  // char array used to get message from validation and header checks functions.
  //char message[VALIDATION_MESSAGE_LENGTH];
  char *message = malloc(VALIDATION_MESSAGE_LENGTH);
	    // extract queries
	    queries = config_setting_get_member(test, "queries");
	    queries_count = config_setting_length(queries);
	    // iterate on queries
	    for(k=0;k<queries_count;k++){

		    
		    // get query of this iteration
		    config_setting_t *query = config_setting_get_elem(queries, k);

		    // determine repetitions
		    repeat_setting = config_setting_get_member(query, "repeat");
		    if (repeat_setting!=NULL) {
			    repeat_query = config_setting_get_int(repeat_setting);
		    }
		    else {
			    repeat_query = 1;
		    }

		    queries_info_t *queries_info=NULL;
		    queries_info_t *current_query_info=queries_info;

		    //current_query_info=queries_info;
		    
		    // initialise curl
		    // Do it outside the repetition loop to reuse
		    // same connection if keep-alive
		    curl = curl_easy_init();

		    /* Perform the request(s), res will get the return code */ 
		    for(l=0; l<repeat_query; l++) {
				    if (queries_info==NULL) {
					    current_query_info = (queries_info_t *)malloc(sizeof(queries_info_t));
					    queries_info = current_query_info;
				    }
				    else {
					    current_query_info->next= (queries_info_t *)malloc(sizeof(queries_info_t));
					    current_query_info=current_query_info->next;
				    }
				    current_query_info->headers_specs=NULL;
				    current_query_info->body_specs=NULL;
				    current_query_info->next = NULL;
			    
			    // initialise body and headers structures passed to curl callbacks
			    payload_specs *body_specs = (payload_specs*) malloc(sizeof(payload_specs));
			    payload_specs *headers_specs = (payload_specs*) malloc(sizeof(payload_specs));
			    // initialise payload specs
			    payload_specs_init(body_specs);
			    body_specs->type='D';
			    payload_specs_init(headers_specs);
			    headers_specs->type='H';
		    
			    // set options and headers
			    control_header *additional_headers=NULL;
			    set_options(curl, query, test, l, &additional_headers);
			    set_output(curl, output_dir, headers_specs, body_specs, test, l, suffix);
			    curl_headers=NULL;
			    set_headers(curl, query, curl_headers, test, l, suffix, additional_headers);

			    // Perform query
			    res = curl_easy_perform(curl);
			    /* Check for errors */ 
			    double content_len;
			    if(res != CURLE_OK){
				    client_log("curl_easy_perform() failed: %s\n",
						    curl_easy_strerror(res));
			    }
			    else {
				    
				    // compute headers and body hash 
				    hash_final(body_specs);
				    hash_final(headers_specs);

				    // reset message, to wipe validations messages
				    memset(message,0,sizeof(message));
				    // validate headers for http queries
				    if (is_protocol(curl, "http://")) {
					    if (!validate_http_headers(headers_specs, body_specs, &message)) {
						    client_log(KRED "FAILURE!\n" KNON);
						    client_log("%s", message);
					    }
					    else {
						    client_log("%s", message);
					    }
				    }

				    // collect data of this query
				    current_query_info->headers_specs = headers_specs;
				    current_query_info->body_specs    = body_specs;
				    collect_curl_info(curl, current_query_info);



				    // cleanup after each query, but keep info collected
				    control_headers_free(additional_headers);
				    clean_output(query, headers_specs, body_specs);

			    }
		    }
		    curl_slist_free_all(curl_headers);
		    curl_easy_cleanup(curl);


		    // Closing curl logs fd and uploading files
		    queries_info_t *head = queries_info;
		    while (head!=NULL){
			    fclose(head->headers_specs->curl_fd);
			    upload_log(head->headers_specs->curl_path);
			    head = head->next;
		    }


		    // extract validations for the query
		    validations = config_setting_get_member(query, "validations");
		    if (validations != NULL) {
			    //printf("Performing validations\n");
			    validations_count = config_setting_length(validations);
			    // iterate over validation of this query
			    for(m=0;m<validations_count;m++){
				    validation = config_setting_get_elem(validations, m);
				    // wipe message from previous validation
				    memset(message,0,sizeof(message));
				    perform_validation(queries_info, validation, &message);
				    client_log("%s",message);

			    }
		    }
		    // end of validations in config file





		    queries_info_t *p= queries_info, *previous=NULL;
		    //if (validate_info_same_port(queries_info, NULL)) {
		    //        printf("USED SAME PORT\n");
		    //}
		    //else {
		    //        printf("USED DIFFERENT PORT\n");
		    //}
		    while (p!=NULL){
			    //printf("Port was %lu\n", p->info.local_port);
			    //printf("Body hash was %s\n", p->body_specs->sha);
			    //printf("Headers hash was %s\n", p->headers_specs->sha);
			    //printf("Number of connections was %lu\n", p->info.num_connects);
			    if (p->headers_specs!=NULL) {
				control_headers_free(p->headers_specs->control_headers);
			    }
			    free(p->headers_specs);
			    free(p->body_specs);
			    previous= p;
			    p=p->next;
			    free(previous);
		    }
	    }

    // free the message collector
    free(message);
}

void init_options() {
	mapping additions[]= {
	{"CURLOPT_URL", CURLOPT_URL, "str"}
// We don not support CURLOPT_HEADER, as it interferes with body sha256 computation
//	,{"CURLOPT_HEADER", CURLOPT_HEADER, "long"}
	,{"CURLOPT_FOLLOWLOCATION", CURLOPT_FOLLOWLOCATION, "long"}
	,{"CURLOPT_POST", CURLOPT_POST, "long"}
	,{"CURLOPT_POSTFIELDSIZE", CURLOPT_POSTFIELDSIZE, "long"}
	,{"CURLOPT_POSTFIELDS",CURLOPT_POSTFIELDS,"str"}
	,{"CURLINFO_SIZE_DOWNLOAD",CURLINFO_SIZE_DOWNLOAD,"double"}
	,{"CURLINFO_RESPONSE_CODE",CURLINFO_RESPONSE_CODE ,"int"}
	,{"CURLINFO_EFFECTIVE_URL",CURLINFO_EFFECTIVE_URL ,"string"}
	,{"CURLOPT_CUSTOMREQUEST", CURLOPT_CUSTOMREQUEST, "string"}
	,{"CURLOPT_TIMEOUT", CURLOPT_TIMEOUT, "long"}
	};
	append_mappings(additions, sizeof(additions)/sizeof(additions[0])); 
}


