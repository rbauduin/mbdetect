#include <stdio.h>
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>
#include <libconfig.h>
#include "utils/mbd_utils.h"

// libsodium for hash computation
#include <sodium.h>


typedef struct {
	char *name;
	int code;
	char *type;
} mapping;
mapping mappings[] =  {
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
	
}; 

int mappings_len = sizeof(mappings)/sizeof(mappings[0]);


// stuff to write output to file
// *****************************


// structure keeping where we write
typedef struct write_dest {
	// file descriptor curl writes the payload to
	FILE *fd;
	// used by curl to keep trace of what was already written
	size_t size;
	// path to save payload to
	char *path;
	// payload type, D for body, H for headers 
	char type; 
	crypto_hash_sha256_state sha_state;
	char sha[2*crypto_hash_sha256_BYTES+1];
	// FIXME: this is only for headers, and will never happen for body. Should we have 2 distinct struct? 
	// // however, this has an impact on the rest of the code, with the type of arguments changed....
	// hash of body sent by server
	control_header* control_headers;
} payload_specs;


void payload_specs_init(payload_specs* specs) {
	specs->control_headers=NULL;
	specs->fd=NULL;
	specs->path=NULL;
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
		memset(*name, 0, len+1);
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
int validate_http_headers(payload_specs headers_specs, payload_specs body_specs, char (*message)[VALIDATION_MESSAGE_LENGTH]) {
	// FIXME: Maybe we can make this code more compact somehow
	int res = validate_header(headers_specs.control_headers, HEADER_HEADERS_HASH, headers_specs.sha);
	if (headers_specs.control_headers==NULL || res < 0 ) {
		snprintf(eos(*message), VALIDATION_MESSAGE_LENGTH-strlen(*message), "HEADERS SPECS NOT COLLECTED, NOTHING FOUND. FIX SERVER?\n");
				return 0;
	} 
	if (res==HEADER_NOT_FOUND){
		snprintf(eos(*message), VALIDATION_MESSAGE_LENGTH-strlen(*message), "Headers %s not found!!\n", HEADER_HEADERS_HASH);
	}
	else if (!res) {
		char *headers_h;
		get_header_value(headers_specs.control_headers, HEADER_HEADERS_HASH, &headers_h);
		snprintf(eos(*message), VALIDATION_MESSAGE_LENGTH-strlen(*message), "DIFFERENT SHA, headers modified!!\n");
		snprintf(eos(*message), VALIDATION_MESSAGE_LENGTH-strlen(*message), "transmitted headers hash: *%s*\n", headers_h);
		snprintf(eos(*message), VALIDATION_MESSAGE_LENGTH-strlen(*message), "computed headers sha256 :\n*%s*\n", headers_specs.sha);
	}

	res = validate_header(headers_specs.control_headers, HEADER_BODY_HASH, body_specs.sha);
	if (res==HEADER_NOT_FOUND){
		snprintf(eos(*message), VALIDATION_MESSAGE_LENGTH-strlen(*message), "Headers %s not found!!\n", HEADER_BODY_HASH);
	}
	else if (!res) {
		char *headers_h;
		get_header_value(headers_specs.control_headers, HEADER_HEADERS_HASH, &headers_h);
		snprintf(eos(*message), VALIDATION_MESSAGE_LENGTH-strlen(*message), "DIFFERENT SHA, BODY modified!!\n");
		snprintf(eos(*message), VALIDATION_MESSAGE_LENGTH-strlen(*message), "transmitted body hash: *%s*\n", headers_h);
		snprintf(eos(*message), VALIDATION_MESSAGE_LENGTH-strlen(*message), "computed body sha256 :\n*%s*\n", body_specs.sha);
	}

	res = validate_header(headers_specs.control_headers, HEADER_SERVER_RCVD_HEADERS, "1");
	if (res==HEADER_NOT_FOUND){
		snprintf(eos(*message), VALIDATION_MESSAGE_LENGTH-strlen(*message), "Headers %s not found!!\n", HEADER_SERVER_RCVD_HEADERS);
	}
	else if (res==NO_MATCH) {
		snprintf(eos(*message), VALIDATION_MESSAGE_LENGTH-strlen(*message), "SERVER GOT MODIFIED HEADERS!!\n");
	}
	//snprintf(eos(*message), VALIDATION_MESSAGE_LENGTH-strlen(*message), "HEADERS VALIDATIONS DONE\n");
}


// Check that the headers with header_name has the expected value
int validate_header(control_header *list, char* header_name, char* expected_value) {
	char* header_value=NULL;
	if (list==NULL || expected_value==NULL || header_name==NULL){
		printf("null values\n");
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

// union type capable of holding each type of value found in validations
typedef union validation_value_t {
		int ival;
		long long llval;
		double fval;
		char *sval;
} validation_value_t;

// check that the validation specified in entry passes.
// Returns 0 if it fails, 1 if it passes
// Also sets the message detailing what happened, both in case of success and failure
// // FIXME: add other comparisons than equality
int perform_validation(CURL *curl,config_setting_t* entry, char (*message)[2048]) {
	// value to return
	int res;
	
	// actual value we got in this run
	validation_value_t actual;

	// value entry from the config file. 
	// value_entry->value contains the union typed value we need to compare to expected value
	config_setting_t *value_entry = config_setting_get_member(entry, "value");

	// name entry from the config file, and its string value.
	// Its value is the name of the option passed to curl_easy_getinfo, which we get from the mappings
	config_setting_t *name_entry = config_setting_get_member(entry, "name");
	const char * name_str=config_setting_get_string(name_entry);
	// mapping of the option name to its value
	mapping m;
	int mapping_found = find_mapping(name_str,&m);
	if (mapping_found) {
		printf("ERROR, no mapping found!\n");
		exit(1);
	}

	if (value_entry == NULL) {
		return -1;
	}
	// for each type of value:
	// - get the actual value from curl
	// - compare it to the expected value found in the config file
	// - set message accordingly
	switch(value_entry->type)
	{ 
		case CONFIG_TYPE_FLOAT:
			curl_easy_getinfo(curl, m.code, &(actual.fval));
			if (res = (value_entry->value.fval == actual.fval)) {
				snprintf(*message, VALIDATION_MESSAGE_LENGTH, "PASS, %s = %f\n", name_str, actual.fval);
			}
			else {
				snprintf(*message, VALIDATION_MESSAGE_LENGTH, "FAIL, %s expected %f but is %f\n", name_str, value_entry->value.fval, actual.fval);
			}
			break;
		case CONFIG_TYPE_INT:
			curl_easy_getinfo(curl, m.code, &(actual.ival));
			if (res = (value_entry->value.ival == actual.ival)) {
				snprintf(*message, VALIDATION_MESSAGE_LENGTH, "PASS, %s = %d\n", name_str, actual.ival);
			}
			else {
				snprintf(*message, VALIDATION_MESSAGE_LENGTH, "FAIL, %s expected %d but is %d\n", name_str, value_entry->value.ival, actual.ival);
			}
			break;
		case CONFIG_TYPE_INT64:
			curl_easy_getinfo(curl, m.code, &(actual.llval));
			if (res = (value_entry->value.llval == actual.llval)) {
				snprintf(*message, VALIDATION_MESSAGE_LENGTH, "PASS, %s = %lld\n", name_str, actual.llval);
			}
			else {
				snprintf(*message, VALIDATION_MESSAGE_LENGTH, "FAIL, %s expected %lld but is %lld\n", name_str, value_entry->value.llval, actual.llval);
			}
			break;
		case CONFIG_TYPE_STRING:
			curl_easy_getinfo(curl, m.code, &(actual.sval));
			if (res = (!strcmp(value_entry->value.sval,actual.sval))) {
				snprintf(*message, VALIDATION_MESSAGE_LENGTH, "PASS, %s = %s\n", name_str, actual.sval);
			}
			else {
				snprintf(*message, VALIDATION_MESSAGE_LENGTH, "FAIL, %s expected %s but is %s\n", name_str, value_entry->value.sval, actual.sval);
			}
			break;
	}
	return res;
}


// find a mapping options as string -> option symbol
int find_mapping(const char* option, mapping* m) {
	int i=0;
	mapping found;
	while (i<mappings_len && strcmp(mappings[i].name, option)) {
		i++;
	}
	if (i<mappings_len) {
		*m = mappings[i];
		return 0;
	}
	else {
		printf("Options %s not handled by this code\n", option);
		return -1;
	}

}
 
// return the value of the symbol whose name is passed as string
int find_code(const char* option) {
	int i=0;
	while (i<mappings_len && strcmp(mappings[i].name,option)) {
		i++;
	}
	if (i<mappings_len) {
		return mappings[i].code;
	}
	else {
		error("Options %s not handled by this code\n", option);
		return -1;
	}

}


// read the config file containing test specs
int read_config(char* path, config_t * cfg) {
  config_init(cfg);

  /* Read the file. If there is an error, report it and exit. */
  if(! config_read_file(cfg, path))
  {
    fprintf(stderr, "%s:%d - %s\n", config_error_file(cfg),
            config_error_line(cfg), config_error_text(cfg));
    config_destroy(cfg);
    return(-1);
  }
  return 0;
}

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
void set_options(CURL* curl, config_setting_t *test, control_header **additional_headers){
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

	// iterate over options
	options = config_setting_get_member(test, "options");
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
		if (mapping_found) {
			printf("ERROR, no mapping found!\n");
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
			curl_easy_setopt(curl, find_code(name_str), value_long); 
			// set additional headers if this is a post option
			handle_post_options(additional_headers, name_str, value_long);
		}
		else {
			printf("NO MATCH\n____________________________________\n");
		}
	}
}

// set http headers sent by curl
// additional_headers are to be set in addition of those found in the config file. 
// This is notably use for POST headers
int set_headers(CURL* curl, config_setting_t *test, struct curl_slist* headers, control_header *additional_headers ){
	// index, curl result, number of headers
	int j,res, headers_count;
	// the header string
	const char *header;

	crypto_hash_sha256_state headers_state;

	// we immediately initialise the body state
	crypto_hash_sha256_init(&headers_state);



	FILE *f;
	f = fopen("/tmp/curl-headers","w");

	int host_set=0, accept_set=0;
	
	
	// get headers from config file
	config_setting_t *cfg_headers = config_setting_get_member(test, "headers");
	//FIXME: if no header specified, need account for default headers by curl
	if (cfg_headers!=NULL){
		// iterate over the list of header strings and add each to the curl_slist *headers
		headers_count = config_setting_length(cfg_headers);
		for (j=0; j<headers_count; j++){
			header=config_setting_get_string_elem(cfg_headers,j);
			add_sha_headers_content(&headers_state,header);
			headers = curl_slist_append(headers, header); 
			// record if we have set the host header
			if (!strncasecmp(header,"host: ", 6)) {
				host_set = 1;
			}
			if (!strncasecmp(header,"accept: ", 8)) {
				accept_set = 1;
			}
			fwrite(header, strlen(header), 1, f);
		}
	}

	// set a host header and an accept header if not already set
	// if we do not set it here, curl adds it itself which screws our sha computation
	// If we want to delete the header, we can with setting the header to "Accept:"
	if (is_protocol(curl,"http://")){
		if (!host_set){
			char host_header[1024];
			get_host_header(curl, &host_header);
			headers = curl_slist_append(headers, host_header); 
			add_sha_headers_content(&headers_state,host_header);
			fwrite(host_header, strlen(host_header), 1, f);
		}
		if (!accept_set){
			char accept_header[1024]="Accept: */*";
			headers = curl_slist_append(headers, accept_header); 
			add_sha_headers_content(&headers_state,accept_header);
			fwrite(accept_header, strlen(accept_header), 1, f);
		}
	}
	control_header * head;
	char header_line[MAX_HEADER_SIZE];
	while (additional_headers!=NULL) {
		head = additional_headers;
		additional_headers=additional_headers->next;
		snprintf(header_line, MAX_HEADER_SIZE, "%s: %s", head->name, head->value);
		add_sha_headers_content(&headers_state,header_line);
		fwrite(header_line, strlen(header_line), 1, f);
		headers = curl_slist_append(headers, header_line); 

	}
	//headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded"); 
	//headers = curl_slist_append(headers, "Content-Length: 20"); 
	fclose(f);
	// sha string
	char sha[crypto_hash_sha256_BYTES*2+1];
        // string of header containing sha.
	// +2 : ": "
	// +strlen(HEADER_HEADERS_HASH): name of the header
	char sha_header[crypto_hash_sha256_BYTES*2+1+2+strlen(HEADER_HEADERS_HASH)];
	// compute sha
	sha_from_state(&headers_state,&sha);
	// build header and add it the the curl headers
	snprintf(sha_header, sizeof(sha_header), "%s: %s", HEADER_HEADERS_HASH, sha);
	headers = curl_slist_append(headers, sha_header); 
	
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

// builds the paths where the body and headers of the query will be saved
void build_file_paths(config_setting_t *output_file, char** headers_path, char** body_path){
		// the base_path is found in the config file. To that
		// we append -D for the body, and -H for the headers,
		// and we have the files paths where we write to
		const char* base_path = config_setting_get_string(output_file);
		// length of the paths we will write to, ie with the -H and -D suffix appended
		int final_path_len = strlen(base_path)+2;

		// +1 for \0
		*headers_path = malloc(final_path_len+1);
		*body_path = malloc(final_path_len+1);

		// concatenate path and suffix
		strncpy(*headers_path, base_path, final_path_len+1);
		strncat(*headers_path, "-H", final_path_len+1);

		strncpy(*body_path, base_path, final_path_len+1);
		strncat(*body_path, "-D", final_path_len+1);
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

// sets up things to handle the data reaceived by curl
void set_output(CURL* curl, config_setting_t *test, payload_specs *headers_specs, payload_specs *body_specs){
	

	// output_file setting
	config_setting_t *output_file = config_setting_get_member(test, "output_file");
	// path string retrieved from output_file setting
	char *headers_path, *body_path;

	// pointers to function that will handle the data received
	size_t (*discard_data_function)(void*, size_t, size_t, struct write_dest*);
	size_t (*write_in_file_function)(void*, size_t, size_t, struct write_dest*);
	// get data handlers, based on protocol
	get_data_handlers(curl, &discard_data_function, &write_in_file_function);

	// and initialise the sha state
	crypto_hash_sha256_init(&(body_specs->sha_state));
	crypto_hash_sha256_init(&(headers_specs->sha_state));

	// discard data if no output_file present
	if (output_file==NULL){
		set_curl_data_handlers(curl,discard_data_function,headers_specs, body_specs );
	}
	else {

		// setup the config structure passed to successive call of the callback
		// get paths where to save headers and body respectively
		build_file_paths(output_file, &headers_path, &body_path);

		// open file handle, setup struct and passit to curl
		// Body
		setup_payload_spec_file(body_specs, body_path);
		// Headers
		setup_payload_spec_file(headers_specs, headers_path);

		set_curl_data_handlers(curl,write_in_file_function, headers_specs, body_specs);
	}
}

// cleans things up when curl query is done. 
void clean_output(config_setting_t *test, payload_specs *headers_specs,payload_specs  *body_specs ){
	// control headers are awlays collected, free them
	control_headers_free(headers_specs->control_headers);
	
	// if there was output written to a file, clean stuff
	config_setting_t *output_file = config_setting_get_member(test, "output_file");
	if (output_file==NULL){
	    return;
	}
	else {
		// close file handles
		fclose(body_specs->fd);	
		fclose(headers_specs->fd);	
		// FIXME: reset user structure to empty
		// free memory allocated in set_output, and reset struct members
		body_specs->fd=NULL;
		body_specs->size=0;
		headers_specs->fd=NULL;
		headers_specs->size=0;
		free(body_specs->path);
		free(headers_specs->path);
	}
}

#define add_mapping(tab,code,type) tab[(code)] = (mapping) {#code, code, type} 
int main(int argc, char *argv[])
{
  CURL *curl;
  CURLcode res;
  // config root
  config_t cfg;
  // tests list entry
  config_setting_t *tests;
  // number of tests and index in loop
  int tests_count, i;
  //test entry and test name string
  config_setting_t *test, *name_setting;
  // string value of name_setting
  const char * name_str;

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

  // path to config file
  char *tests_file;
  // was config reas successfully?
  int config_read;
  
  // char array used to get message from validation and header checks functions.
  char message[VALIDATION_MESSAGE_LENGTH];

  if (argc<2){
	  tests_file="one_test.cfg";
  } else {
	  tests_file=argv[1];
  }

  printf("test file = %s\n", tests_file);

 
  // read config
  config_read = read_config(tests_file, &cfg);
  if(config_read==0) {
    //extract tests
    tests = config_lookup(&cfg, "tests");
    if(tests != NULL) {
      tests_count = config_setting_length(tests);
       
      printf("found %d tests\n", tests_count);
    }
    // iterate on tests
    for (i=0; i<tests_count; i++){
	    test = config_setting_get_elem(tests, i);
	    name_setting = config_setting_get_member(test, "name");
	    if (name_setting!=NULL){
		    name_str = config_setting_get_string(name_setting);
		    printf("%s running...\n", name_str);
	    }
	    // extract queries
	    queries = config_setting_get_member(test, "queries");
	    queries_count = config_setting_length(queries);
	    // iterate on queries
	    for(k=0;k<queries_count;k++){
		    // initialise body and headers structures passed to curl callbacks
		    payload_specs body_specs;
		    payload_specs headers_specs;

		    
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
		    /* Perform the request(s), res will get the return code */ 
		    for(l=0; l<repeat_query; l++) {
			    // initialise curl
			    curl = curl_easy_init();
			    // initialise payload specs
			    payload_specs_init(&body_specs);
			    body_specs.type='D';
			    payload_specs_init(&headers_specs);
			    headers_specs.type='H';
		    
			    // set options and headers
			    control_header *additional_headers=NULL;
			    set_options(curl, query, &additional_headers);
			    set_output(curl, query, &headers_specs, &body_specs);
			    curl_headers=NULL;
			    set_headers(curl, query, curl_headers, additional_headers);

			    // Perform query
			    res = curl_easy_perform(curl);
			    /* Check for errors */ 
			    double content_len;
			    if(res != CURLE_OK)
				    fprintf(stderr, "curl_easy_perform() failed: %s\n",
						    curl_easy_strerror(res));
			    else {
				    // extract validations for the query
				    validations = config_setting_get_member(query, "validations");
				    if (validations != NULL) {
					    printf("Performing validations\n");
					    validations_count = config_setting_length(validations);
					    // iterate over validation of this query
					    for(m=0;m<validations_count;m++){
						    validation = config_setting_get_elem(validations, m);
						    // wipe message from previous validation
						    memset(message,0,VALIDATION_MESSAGE_LENGTH);
						    perform_validation(curl,validation, &message);
						    printf("%s",message);
					    }
				    }
				    // end of validations in config file
				    
				    // compute headers and body hash 
				    hash_final(&body_specs);
				    hash_final(&headers_specs);

				    // reset message, to wipe validations messages
				    memset(message,0,VALIDATION_MESSAGE_LENGTH);
				    // validate headers for http queries
				    if (is_protocol(curl, "http://")) {
					    if (!validate_http_headers(headers_specs, body_specs, &message)) {
						    printf("FAILURE!\n");
						    printf("%s", message);
					    }
					    else {
						    printf("%s", message);
					    }
				    }


				    /* cleanup after each query */ 
				    clean_output(query, &headers_specs, &body_specs);
				    control_headers_free(additional_headers);
				    curl_slist_free_all(curl_headers);
				    curl_easy_cleanup(curl);

			    }
		    }
	    }
    }
 
  }
  else {
	  printf("no curl or no config\n");
  }
  return 0;
}
