#include <stdio.h>
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>
#include <libconfig.h>
#include "utils/mbd_utils.h"
#include "utils/mbd_version.h"
#include "utils/slist.h"
#include <uuid/uuid.h>


// libsodium for hash computation
#include <sodium.h>


// for c-ares
// requires libc-ares-dev
#include <ares.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
// end cares



// union type capable of holding each type of value found in validations
typedef union validation_value_t {
		int ival;
		long long llval;
		double fval;
		char *sval;
} validation_value_t;



void get_run_log_dir(config_setting_t *output_dir, char **run_path);
FILE *log_file;
char log_path[MAX_LOG_PATH_SIZE];

#define client_log(...) do { printf(__VA_ARGS__) ; fprintf(log_file, __VA_ARGS__); } while (0)
void setup_logging(config_setting_t *output_dir) {
	char *path;
	get_run_log_dir(output_dir, &path);
	mkpath(path);
	append_to_buffer(&path,"/");
	append_to_buffer(&path,"client.log");
	log_file=fopen(path, "w");
	strncpy(log_path, path, MAX_LOG_PATH_SIZE);
	free(path);
}

void close_logging() {
	fclose(log_file);
}

int read_input(char** response) {
    int c=EOF;
    int previous='\n';
    *response = (char *) malloc(256*sizeof(char));
    memset(*response, 0, 256);

    int current_size = 256;
    int i=0;
    while ( ! ( ( c = getchar() ) == previous && c == '\n') )
    {
	    previous=c;
	    (*response)[i++]=(char)c;

	    //if i reached maximize size then realloc size
	    if(i == current_size)
	    {
		    current_size = i+256;
		    *response = realloc(*response, current_size);
	    }
    }
}


int validate_info_value(queries_info_t *head, validations_mapping m, config_setting_t * entry,  char **message) {
	// message for one iteration in the repetition on the query
	char iteration_message[VALIDATION_MESSAGE_LENGTH];
	config_setting_t *value_entry = config_setting_get_member(entry, "value");
	if (value_entry == NULL) {
		client_log("value entry not found in validation\n");
		return -1;
	}
	int i=0;
	while (head!=NULL){
		switch(value_entry->type)
		{ 
			case CONFIG_TYPE_FLOAT:
				if (head->info[m.code].fval!=value_entry->value.fval) {
					snprintf(iteration_message, VALIDATION_MESSAGE_LENGTH,KRED "FAIL" KNON " (float), %s expected %f but is %f\n", m.name, value_entry->value.fval, head->info[m.code].fval);
					append_to_buffer(message, iteration_message);
					// do not return, but continue validating subsequent queries
					//return 0;
				}
				else {
					snprintf(iteration_message, VALIDATION_MESSAGE_LENGTH,KGRN "SUCCESS" KNON ", query num %d, %s is %f\n", i, m.name, value_entry->value.fval);
					append_to_buffer(message, iteration_message);
				}
				break;
			case CONFIG_TYPE_INT:
				if (head->info[m.code].ival!=value_entry->value.ival) {
					snprintf(iteration_message, VALIDATION_MESSAGE_LENGTH,KRED "FAIL" KNON " (int), %s expected %d but is %d\n", m.name, value_entry->value.ival, head->info[m.code].ival);
					append_to_buffer(message, iteration_message);
					return 0;
				}
				else {
					snprintf(iteration_message, VALIDATION_MESSAGE_LENGTH,KGRN "SUCCESS" KNON ", query num %d, %s is %d\n", i, m.name, value_entry->value.ival);
					append_to_buffer(message, iteration_message);
				}
				break;
			case CONFIG_TYPE_INT64:
				if (head->info[m.code].llval!=value_entry->value.llval) {
					snprintf(iteration_message, VALIDATION_MESSAGE_LENGTH,KRED "FAIL" KNON " (int64), %s expected %lld but is %lld\n", m.name, value_entry->value.llval, head->info[m.code].llval);
					append_to_buffer(message, iteration_message);
					return 0;
				}
				else {
					snprintf(iteration_message, VALIDATION_MESSAGE_LENGTH, KGRN "SUCCESS" KNON ", query num %d, %s is %lld\n", i, m.name, value_entry->value.llval);
					append_to_buffer(message, iteration_message);
				}
				break;
			case CONFIG_TYPE_STRING:
				if (!strcmp(head->info[m.code].sval, value_entry->value.sval)) {
					snprintf(iteration_message, VALIDATION_MESSAGE_LENGTH, KRED "FAIL" KNON " (string), %s expected %s but is %s\n", m.name, value_entry->value.sval, head->info[m.code].sval);
					append_to_buffer(message, iteration_message);
					return 0;
				}
				else {
					snprintf(iteration_message, VALIDATION_MESSAGE_LENGTH,KGRN "SUCCESS" KNON ", query num %d, %s is %s\n", i, m.name, value_entry->value.sval);
					append_to_buffer(message, iteration_message);
				}
		}
		head=head->next;
		i++;
	}
}


int validate_info_same_port(queries_info_t *head, validations_mapping m, config_setting_t * setting_entry, char** message) {
	char iteration_message[VALIDATION_MESSAGE_LENGTH];
	long long port=-1;
	while (head!=NULL) {
		// store port used by first query
		if (port < 0) {
			port = head->info[LOCAL_PORT].llval;
			snprintf(iteration_message, VALIDATION_MESSAGE_LENGTH, KGRN "SUCCESS" KNON " (same port), init to port %llu\n", port);
			append_to_buffer(message, iteration_message);
		}
		// for subsequent queries, check the same port is used
		else {
			if (head->info[LOCAL_PORT].llval != port){
					snprintf(iteration_message, VALIDATION_MESSAGE_LENGTH,KRED "FAIL" KNON " (same port): a different port was used!\n" KNON);
					append_to_buffer(message, iteration_message);
				return 0; 
			}
			snprintf(iteration_message, VALIDATION_MESSAGE_LENGTH, KGRN "SUCCESS" KNON " (same port)\n");
			append_to_buffer(message, iteration_message);
		}
		head=head->next;
	}
	return 1;

}


int validate_info_different_ports(queries_info_t *head, validations_mapping m, config_setting_t * setting_entry, char** message) {
	char iteration_message[VALIDATION_MESSAGE_LENGTH];
	long long port=-1;
	while (head!=NULL) {
		if (head->info[LOCAL_PORT].llval == port){
			snprintf(iteration_message, VALIDATION_MESSAGE_LENGTH,KRED "FAIL" KNON " (different ports): the same port was used for 2 subsequent queries!\n" KNON);
			append_to_buffer(message, iteration_message);
			return 0; 
		}
		snprintf(iteration_message, VALIDATION_MESSAGE_LENGTH, KGRN "SUCCESS" KNON " (different ports)\n");
		append_to_buffer(message, iteration_message);
		head=head->next;
	}
	return 1;

}

// validations_mapping type is defined in mbd-utils.h
// These mappings specify:
// - the name of the validation
// - its identification code
// - the function that will perform the validation
// The identification code gives the index of the value in query info that
// will be used for the comparison.

// The informations about each query are stored in an array 
// of type query_info_field, which is an enum type capable of containing 
// every type of value returned by curl.
// The index of the cell in the array in which an info is stored corresponds 
// to the identification code of the validations_mapping.
// For example, the "response_code" validation function will look in the 
// query_info array at index RESPONSE_CODE to get the actual response code
// result of the curl query.
//
// Here's what the code does:
// - look at validation name, and get the mapping m for which m.name corresponds
// - extract actual value of the query run at index m.code in the query_info array
// - look at what value type is present in the validation entry in the config file. 
//   This must be the same type as the actual value, and will determine which member 
//   of the union type is extracted
// - perform comparison of value from config file and the correct member of the union type
//
//
//***********************************************************************
// To add a validation:
//***********************************************************************
// - add an entry validations_mappings
// - If working on a new field:
//   - add an entry in validation_fields
//   - increment QUERY_INFO_FIELD_NUMBER
// - possible write function. For standard value equality validation, use the
// standard function validate_info_value. If values extracted from repeated queries need
// to be validated, look at validate_info_same_port.
 
validations_mapping validations_mappings[]={
	{"response_code", RESPONSE_CODE, validate_info_value}
	,{"size_download", SIZE_DOWNLOAD, validate_info_value}
	,{"num_connects", NUM_CONNECTS, validate_info_value}
	,{"local_port", LOCAL_PORT, validate_info_value}
	,{"same_port", NONE, validate_info_same_port}
	,{"different_ports", NONE, validate_info_different_ports}
};

int validations_mappings_len = sizeof(validations_mappings)/sizeof(validations_mappings[0]);


// This maps the curl options from their name to their actual value, eg "CURLOPT_URL" to CURLOPT_URL.
// It also specifies the type of data the option expects

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
	,{"CURLOPT_CUSTOMREQUEST", CURLOPT_CUSTOMREQUEST, "string"}
	,{"CURLOPT_TIMEOUT", CURLOPT_TIMEOUT, "long"}
	,{"ARES_SUCCESS", ARES_SUCCESS, "int"}
	,{"ARES_ENOTFOUND", ARES_ENOTFOUND, "int"}
	,{"ARES_FLAG_USEVC", ARES_FLAG_USEVC, "int"}
	
}; 

int mappings_len = sizeof(mappings)/sizeof(mappings[0]);


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



// check that the validation specified in entry passes.
// Returns 0 if it fails, 1 if it passes
// Also sets the message detailing what happened, both in case of success and failure
// // FIXME: add other comparisons than equality
int perform_validation(queries_info_t *queries_info,config_setting_t* entry, char **message) {
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
	validations_mapping m;
	int mapping_found = find_validation_mapping(name_str,&m);
	if (mapping_found) {
		client_log("ERROR, no validation mapping found for %s!\n", name_str);
		exit(1);
	}

	res = m.f(queries_info, m, entry, message);
	return res;
}



// find a mapping options as string -> option symbol
int find_validation_mapping(const char* validation, validations_mapping *m) {
	int i=0;
	validations_mapping found;
	while (i<validations_mappings_len && strcmp(validations_mappings[i].name, validation)) {
		i++;
	}
	if (i<validations_mappings_len) {
		*m = validations_mappings[i];
		return 0;
	}
	else {
		client_log("Validation %s not handled by this code\n", validation);
		return -1;
	}

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
		client_log("Options %s not handled by this code\n", option);
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

// build run id with a uuid
void get_run_id(char **id) {
	uuid_t uuid;

	// uuid as string
	static char *uuid_str;
	// indicates if uuid was already generated
	static int valid = 0;
	// loop index
	size_t i; 
	
	if (valid) {
		*id = uuid_str;
	}
	else {
		uuid_generate_random(uuid);
		uuid_str= malloc(sizeof(uuid)*2+1);
		uuid_str[0]='\0';
		char part[3];
		for (i = 0; i < sizeof uuid && i < RUN_ID_SIZE/2; i ++) {
			sprintf(part, "%02x", uuid[i]);
			strncat(uuid_str, part, 2);
		}
		*id=uuid_str;
		valid = 1;
	}
	


}

// structure used in download of tests definition from net
struct memory_download {
  char *content;
  size_t size;
};


// callback saving downloaded tests definition to memory
static size_t
tests_config_from_net_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct memory_download *mem = (struct memory_download *)userp;

  mem->content = realloc(mem->content, mem->size + realsize + 1);
  if(mem->content == NULL) {
    client_log("could not reallocate memory in tests config download)\n");
    return 0;
  }

  memcpy(&(mem->content[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->content[mem->size] = 0;

  return realsize;
}
// download tests definition file
void download_tests_definition(char **config) {
	CURL *curl;
	CURLcode res;
	curl = curl_easy_init();

	struct memory_download chunk;

	chunk.content = malloc(1);  /* will be grown as needed by the realloc above */
	chunk.size = 0;    /* no data at this point */



	if(curl) {

		// specify target
		curl_easy_setopt(curl,CURLOPT_URL, TESTS_FILE_URL);

		// specify which file to write to
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, tests_config_from_net_callback);

		// perform query
		res = curl_easy_perform(curl);
		if(res != CURLE_OK)
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
					curl_easy_strerror(res));

		// cleanup
		curl_easy_cleanup(curl);
	}
	*config = chunk.content;
}

//
// read the config file containing test specs
int parse_config_from_file( config_t *cfg, char *path) {
	/* Read the file. If there is an error, report it and exit. */
	if(! config_read_file(cfg, path))
	{
		fprintf(stderr, "%s:%d - %s\n", config_error_file(cfg),
				config_error_line(cfg), config_error_text(cfg));
		config_destroy(cfg);
		return(0);
	}
	return 1;
}

int parse_config_from_net(config_t *cfg) {
	// Download test file and put its content ingo tests_str
	// The server can possibly determine which file to send according to parameters sent by client
	char *tests_str;
	// download tests definition with mptcp disabled
	int ori_mptcp = disable_mptcp();
	download_tests_definition(&tests_str);
	set_mptcp(ori_mptcp);

	// try parse it
	if (!config_read_string(cfg,tests_str)) {
		printf("Erro in this config file:\n%s\n", tests_str);
		fprintf(stderr, "%d - %s\n", 
				config_error_line(cfg), config_error_text(cfg));
		config_destroy(cfg);
		// we do not need the config string anymore
		free(tests_str);
		// return failure
		return 0;
	}

	free(tests_str);

	// return success
	return 1;
}

int parse_config(int argc, char *argv[], config_t *cfg) {
	// flag indicating if config could be parsed
	int config_parsed=0;
	char *tests_str;
	config_init(cfg);
	if (argc<2){
		return parse_config_from_net(cfg);
	} else {
		// read config
		return  parse_config_from_file(cfg, argv[1]);
	}
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
		if (mapping_found) {
			client_log("ERROR, no mapping found!\n");
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
			client_log("NO option type MATCH\n____________________________________\n");
		}
	}
}


// get id of the test passed as argument
const char * get_test_id(config_setting_t *test){
	config_setting_t *test_id_setting = config_setting_get_member(test, "id");
	if (test_id_setting == NULL) {
		client_log("The test has no id, this is required!\n");
		exit(1);
	}
	return config_setting_get_string(test_id_setting);

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


// Extract the output dir from the config file, or sets it by default to /tmp
void get_base_dir(config_setting_t *output_dir, char **base_dir) {
	// if not output file, save in /tmp by default
	*base_dir=(char *) malloc(MAX_LOG_PATH_SIZE);
	if (output_dir==NULL){
		// "/tmp" + '\0'
		strcpy(*base_dir,DEFAULT_BASE_DIR);
	}
	else {
		strcpy(*base_dir,config_setting_get_string(output_dir));
	}
}

void get_run_log_dir(config_setting_t *output_dir, char **run_path){
		get_base_dir(output_dir, run_path);

		char *run_id;
		get_run_id(&run_id);

		// append run_id as directory
		strncat(*run_path, "/", 1);
		strncat(*run_path, run_id, strlen(run_id));

}

// concatenate 2 suffixes to use for log files
void build_suffix(char** full_suffix, const char *mptcp_flag_suffix, const char *log_suffix) {
	*full_suffix = (char *) malloc(strlen(mptcp_flag_suffix)+strlen(log_suffix)+1);
	memset(*full_suffix,0,sizeof(*full_suffix));
	strncat(*full_suffix,mptcp_flag_suffix,strlen(mptcp_flag_suffix));
	strncat(*full_suffix,log_suffix, strlen(log_suffix));
}

// log_dir is the log directory for this run
// test_id is the id of this test as found in the config file
// repeat is the repetition number of this query
// suffix is the suffix to add to the filename. Use to add "-H" and "-D"
build_log_file_path(const char *log_dir, const char *test_id, int repeat, const char *prefix, const char *suffix, char **path) {
	// allocate and clean memory (needed!)
	*path = (char *) malloc(MAX_LOG_PATH_SIZE);
	memset(*path, 0, MAX_LOG_PATH_SIZE);
	// copu log_dir value to destination string and append "/"
	append_to_buffer(path, log_dir);
	append_to_buffer(path, "/");
	if (prefix!=NULL) {
		append_to_buffer(path, prefix);
	}
	// append the test_id and repetition number
	append_to_buffer(path, test_id);
	char repeat_str[5];
	snprintf(repeat_str, 5, ".%03d", repeat);
	append_to_buffer(path, repeat_str);
	// append suffix
	append_to_buffer(path, suffix);
}

// builds the paths where the body and headers of the query will be saved
void build_file_paths(config_setting_t *output_dir, char** headers_path, char** body_path, const char *test_id, int repeat, const char *suffix){
		// the base_path is found in the config file. To that
		// we append -D for the body, and -H for the headers,
		// and we have the files paths where we write to

		char *base_path;
		get_run_log_dir(output_dir, &base_path);
		//this is the run log path 
		mkpath(base_path);

		// build log file for received headers and body
		char* full_suffix;
		build_suffix(&full_suffix, suffix, "-D");
		build_log_file_path(base_path, test_id, repeat, NULL, full_suffix, body_path);
		free(full_suffix);
		build_suffix(&full_suffix, suffix, "-H");
		build_log_file_path(base_path, test_id, repeat, NULL, full_suffix, headers_path);
		free(full_suffix);

		free(base_path);
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


void upload_log(const char *path) {
	CURL *curl;
	CURLcode res;
	// open file desc to pass to curl
	FILE *fd = fopen(path, "rb");
	// get run_id to upload in this dir on remote ftp
	char *run_id;
	get_run_id(&run_id);

	// extract filename
	const char *filename = strrchr(path, '/');
	// skip /
	filename++;

	// build destination URL
	// this includes the client directory, so that server and client logs can be rsynced
	// with no risk of overwriting files
	char dest_url[1024];
	sprintf(dest_url, CLIENT_LOG_UPLOAD_BASE_URL "/%s/client/%s", run_id, filename);

	struct stat file_stats;
	fstat(fileno(fd), &file_stats);

	// currently do not upload files bigger than 50KB
	if (file_stats.st_size < 50200) {
		curl = curl_easy_init();
		if(curl) {

			// enable uploading
			curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

			// specify target
			curl_easy_setopt(curl,CURLOPT_URL, dest_url);

			// specify which file to upload
			curl_easy_setopt(curl, CURLOPT_READDATA, fd);

			// create directories in upload path
			curl_easy_setopt(curl, CURLOPT_FTP_CREATE_MISSING_DIRS, CURLFTP_CREATE_DIR);

			// perform query
			res = curl_easy_perform(curl);
			if(res != CURLE_OK)
				client_log("curl_easy_perform() failed: %s\n",
						curl_easy_strerror(res));

			// cleanup
			curl_easy_cleanup(curl);
		}
	}
	fclose(fd);

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


void run_curl_test(config_setting_t *test, config_setting_t *output_dir, const char* suffix) {
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


////////////////////////////////////////////////////////////////////////////////
//                        C-ares test
////////////////////////////////////////////////////////////////////////////////



// structure holding information about one dns query.
// it has a link to the next query's information
typedef struct dns_queries_info_t {
	// c-ares status
	int status;
	// number of timeouts
	int timeouts;
	// domain name to resolve
	char domain[MAX_DOMAIN_SIZE];
	// list of ip addresses it resolves to
	struct slist * list;
	// file we write log to
	char log_path[MAX_LOG_PATH_SIZE];
	// file descriptor of log file
	FILE *fd;
	// link to next query_info
	struct dns_queries_info_t *next;
} dns_queries_info_t;

// mapping of dns queries validations
// - name of validation,
// - possible code, legacy from curl tests, but might become useful later. Use NONE to not use it.
// - validation function to call
typedef struct dns_validations_mapping{
	char *name;
	int  code;
	int (*f)(dns_queries_info_t *head, struct dns_validations_mapping m, config_setting_t * entry,  char **message);
} dns_validations_mapping;


// forward declarations
int dns_include(dns_queries_info_t *info, struct dns_validations_mapping m, config_setting_t * entry,  char **message);
int dns_result_code(dns_queries_info_t *info, struct dns_validations_mapping m, config_setting_t * entry,  char **message);


// dns validations mapping
dns_validations_mapping dns_validations_mappings[]={
	{"dns_include", NONE, dns_include}
	,{"dns_result_code", NONE, dns_result_code}
};

// check that the result code is what was expected
int dns_result_code(dns_queries_info_t *info, struct dns_validations_mapping m, config_setting_t * entry,  char **message){
	// message collector
	char iteration_message[VALIDATION_MESSAGE_LENGTH];

	// expected value
	config_setting_t *value_entry = config_setting_get_member(entry, "value");
	if (value_entry == NULL) {
		printf("value entry not found in validation\n");
		return -1;
	}
	const char *value_str = config_setting_get_string(value_entry);

	// map expected value string to its constant value
	mapping code_mapping;
	find_mapping(value_str, &code_mapping);
	// traverse all query_infos linked list to check each query resulted in the expected value
	while (info!=NULL){
		if (info->status == code_mapping.code) {
			sprintf(iteration_message, KGRN "Success expected return code %d\n" KNON, info->status);
			append_to_buffer(message, iteration_message);
		}
		else {
			sprintf(iteration_message, KRED "Failure, unexpected return code:\n" KNON);
			append_to_buffer(message, iteration_message);

			switch(info->status){
				case ARES_ENOTIMP:
					sprintf(iteration_message, KRED "ARES_ENOTIMP: type famlily not recognised\n" KNON);
					append_to_buffer(message, iteration_message);
					break;
				case ARES_EBADNAME:
					sprintf(iteration_message, KRED "ARES_EBADNAME: name is not valid internet address\n" KNON);
					append_to_buffer(message, iteration_message);
					break;
				case ARES_ENOTFOUND:
					sprintf(iteration_message, KRED "ARES_ENOTFOUND: name not found\n" KNON);
					append_to_buffer(message, iteration_message);
					break;
				case ARES_ENOMEM:
					sprintf(iteration_message, KRED "ARES_ENOMEM: memory exhausted\n" KNON);
					append_to_buffer(message, iteration_message);
					break;
				case ARES_ECANCELLED:
					sprintf(iteration_message, KRED "ARES_ECANCELLED: query was cancelled\n" KNON);
					append_to_buffer(message, iteration_message);
					break;
				case ARES_EDESTRUCTION:
					sprintf(iteration_message, KRED "ARES_EDESTRUCTION: ares channel destroyed, query cancelled\n" KNON);
					append_to_buffer(message, iteration_message);
					break;
				case ARES_EBADQUERY:
					sprintf(iteration_message, KRED "ARES_EBADQUERY\n" KNON);
					append_to_buffer(message, iteration_message);
					break;
				case ARES_ECONNREFUSED:
					sprintf(iteration_message, KRED "ARES_ECONNREFUSED\n" KNON);
					append_to_buffer(message, iteration_message);
					break;
				case ARES_EBADFAMILY:
					sprintf(iteration_message, KRED "ARES_EBADFAMILY\n" KNON);
					append_to_buffer(message, iteration_message);
					break;
				case ARES_EBADRESP:
					sprintf(iteration_message, KRED "ARES_EBADRESP\n" KNON);
					append_to_buffer(message, iteration_message);
					break;
				case ARES_ETIMEOUT:
					sprintf(iteration_message, KRED "ARES_ETIMEOUT\n" KNON);
					append_to_buffer(message, iteration_message);
					break;
				case ARES_EBADSTR:
					sprintf(iteration_message, KRED "ARES_EBADSTR\n" KNON);
					append_to_buffer(message, iteration_message);
					break;

			}

		}
		info = info->next;
	}
}

// Check that the domain resolution contains one or multiple ips,
// hence value in config file may be a string or a list of strings.
int dns_include(dns_queries_info_t *info, struct dns_validations_mapping m, config_setting_t * entry,  char **message){
	char iteration_message[VALIDATION_MESSAGE_LENGTH];
	// value to look for
	config_setting_t *value_entry = config_setting_get_member(entry, "value");
	if (value_entry == NULL) {
		printf("value entry not found in validation\n");
		return -1;
	}
	const char *value_str=NULL;
	int queries_count, i;

	// traverse whole query_info linked list
	while (info!=NULL){
		switch(value_entry->type)
		{ 
			// if string, use the value itself
			case CONFIG_TYPE_STRING:
				value_str = config_setting_get_string(value_entry);
				if (slist_any_str(info->list, value_str)) {
					sprintf(iteration_message, KGRN "Success, found ip %s\n" KNON, value_str);
					append_to_buffer(message, iteration_message);
					return 1;
				}
				else {
					sprintf(iteration_message, KRED "Failure, did not find ip %s\n" KNON, value_str);
					append_to_buffer(message, iteration_message);
					return 0;
				}
			// if list, check each list member
			case CONFIG_TYPE_LIST:
				queries_count = config_setting_length(value_entry);
				for (i=0; i<queries_count; i++){
					value_str = config_setting_get_string_elem(value_entry, i);
					if (!slist_any_str(info->list, value_str)) {
						sprintf(iteration_message, KRED "Failure, did not find ip %s\n" KNON, value_str);
						append_to_buffer(message, iteration_message);
						return 0;
					}
					else {
						sprintf(iteration_message, KGRN "Success, found ip %s\n" KNON, value_str);
						append_to_buffer(message, iteration_message);
					}
				}
				return 1;
		}
		// go to next query_info in linked list
		info = info->next;
	}
}

int dns_validations_mappings_len = sizeof(dns_validations_mappings)/sizeof(dns_validations_mappings[0]);

// find a mapping options as string -> option symbol
int find_dns_validation_mapping(const char* validation, dns_validations_mapping *m) {
	int i=0;
	while (i<dns_validations_mappings_len && strcmp(dns_validations_mappings[i].name, validation)) {
		i++;
	}
	if (i<dns_validations_mappings_len) {
		*m = dns_validations_mappings[i];
		return 0;
	}
	else {
		printf("Validation %s not handled by this code\n", validation);
		return -1;
	}

}


// perform all validations after queries have been done
int perform_dns_validation(dns_queries_info_t *queries_info,config_setting_t* entry, char **message) {
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
	dns_validations_mapping m;
	int mapping_found = find_dns_validation_mapping(name_str,&m);
	if (mapping_found) {
		printf("ERROR, no validation mapping found for %s!\n", name_str);
		exit(1);
	}

	// call the mapping's function
	res = m.f(queries_info, m, entry, message);
	return res;
}

// utility ares function, waiting for asynchronous code to terminate
static void
wait_ares(ares_channel channel)
{
	for(;;){
		struct timeval *tvp, tv;
		fd_set read_fds, write_fds;
		int nfds;

		FD_ZERO(&read_fds);
		FD_ZERO(&write_fds);
		nfds = ares_fds(channel, &read_fds, &write_fds);
		if(nfds == 0){
			break;
		}
		tvp = ares_timeout(channel, NULL, &tv);
		select(nfds, &read_fds, &write_fds, NULL, tvp);
		ares_process(channel, &read_fds, &write_fds);
	}
}

// C-ares callback.
// - arg is the user provided argument, we pass a dns_query_info_t structure
//   holding the hostname and file descriptor to log to
static void
callback(void *arg, int status, int timeouts, struct hostent *host)
{
	dns_queries_info_t *query_info = (dns_queries_info_t *) arg;

	// if host is NULL, resolution failed. We lookup name in query_info then
	fprintf( query_info->fd, "Resolution of %s\n", query_info->domain);
	if (host!=NULL) {
		fprintf( query_info->fd, "Effective host: %s\n", host->h_name);
	} 
	fprintf( query_info->fd, "Status: %d\n", status);
	fprintf( query_info->fd, "Timeouts: %d\n", timeouts);

	// save info for validations
	query_info->status = status;
	query_info->timeouts = timeouts;

	// stop here if resolution failed
	if(!host || status != ARES_SUCCESS){
		fprintf(query_info->fd, "Failed to lookup: %s\n", ares_strerror(status));
		return;
	}

	// if resolution successful, log addresses and collect them in query_info
	fprintf(query_info->fd, "Domain resolved:\n");

	char ip[INET6_ADDRSTRLEN];
	int i = 0;
	slist *ips = query_info->list;

	for (i = 0; host->h_addr_list[i]!=NULL; ++i) {
		inet_ntop(host->h_addrtype, host->h_addr_list[i], ip, sizeof(ip));
		fprintf(query_info->fd, "%s\n", ip);
		slist_append(ips, ip);
	}
	query_info->list = ips;

}

// builds the log path, and puts info in query_info
void set_dns_output(dns_queries_info_t *query_info, config_setting_t *output_dir, config_setting_t *test, int repeat, const char *suffix) {
	char *log_path;
	char *base_path;
	const char *test_id = get_test_id(test);

	// build the directory path
	get_run_log_dir(output_dir, &base_path);

	//this is the run specific log dir, create it if needed 
	mkpath(base_path);

	// All logs of dns tests go the the same file, even in case of repetitions
	char *full_suffix;
	build_suffix(&full_suffix, suffix, ".dns");
	build_log_file_path(base_path, test_id, 0, NULL, full_suffix, &log_path);
	free(full_suffix);

	// put info in query_info
	strncpy(query_info->log_path, log_path, MAX_LOG_PATH_SIZE);
	query_info->fd = fopen(log_path, "a");

}

void clean_dns_output(config_setting_t *test, dns_queries_info_t *query_info){
	fclose(query_info->fd);
}

// run a dns test as defined in the config file.
// Issues all queries and possible repetitions
void run_cares_test(config_setting_t *test, config_setting_t *output_dir, const char *suffix) {

	ares_channel channel;
	int status;
	struct ares_options options;
	int optmask = 0;

	// init c-ares
	status = ares_library_init(ARES_LIB_INIT_ALL);
	if (status != ARES_SUCCESS){
		printf("ares_library_init: %s\n", ares_strerror(status));
		return;
	}

	// get queries for this test
	config_setting_t *queries = config_setting_get_member(test, "queries");
	int queries_count = config_setting_length(queries);

	// index variable and message collector
	int k;
	char *message = malloc(VALIDATION_MESSAGE_LENGTH);
	
	// iterate on queries
	for(k=0;k<queries_count;k++){
		    // get query of this iteration
		    config_setting_t *query = config_setting_get_elem(queries, k);

		    // determine repetitions
		    config_setting_t *repeat_setting = config_setting_get_member(query, "repeat");
		    int repeat_query;
		    if (repeat_setting!=NULL) {
			    repeat_query = config_setting_get_int(repeat_setting);
		    }
		    else {
			    repeat_query = 1;
		    }

		    // get hostname to resolve
		    config_setting_t *host_setting = config_setting_get_member(query, "host");
		    const char *host = config_setting_get_string(host_setting);

		    // define the query_info linked list, initially empty
		    dns_queries_info_t *queries_info=NULL;
		    dns_queries_info_t *current_query_info=queries_info;

		    // set flags
		    config_setting_t *flags_setting = config_setting_get_member(query, "flags");
		    int flags_count;
		    int j;
		    const char *flag;
		    int mapping_found;
		    // reset options for this query
		    options.flags = 0;
		    if (flags_setting!=NULL) {
			    // flags is a list of strings we need to map to an c-ares flag
			    flags_count = config_setting_length(flags_setting);
			    for (j=0; j<flags_count; j++){
				    flag=config_setting_get_string_elem(flags_setting,j);
				    mapping m;
				    mapping_found = find_mapping(flag,&m);
				    if (!mapping_found) {
					    options.flags = options.flags||m.code;
				    }
			    }
		    }
		    // to have a callback when the socket changes state:
		    //	optmask |= ARES_OPT_SOCK_STATE_CB;
		    optmask |= ARES_OPT_FLAGS;

		    // set options
		    status = ares_init_options(&channel, &options, optmask);
		    if(status != ARES_SUCCESS) {
			    client_log(KRED "problem ares_init_options: %s\n" KNON, ares_strerror(status));
			    return;
		    }

		    // repetition index variable
		    int l;

		    
		    // issue repetitions
		    for(l=0; l<repeat_query; l++) {
			    if (queries_info==NULL) {
				    // first query, initialise
				    current_query_info = (dns_queries_info_t *)malloc(sizeof(dns_queries_info_t));
				    queries_info = current_query_info;
			    }
			    else {
				    // subsequent query, append
				    current_query_info->next= (dns_queries_info_t *)malloc(sizeof(dns_queries_info_t));
				    current_query_info=current_query_info->next;
			    }

			    // setup this query's query_info
			    slist *ips;
			    slist_init(&ips);
			    current_query_info->list = ips;
			    current_query_info->status = -1;
			    current_query_info->fd = NULL;
			    current_query_info->next = NULL;
			    strncpy(current_query_info->domain, host, MAX_DOMAIN_SIZE);

			    // setup logs
			    set_dns_output(current_query_info, output_dir, test, l, suffix);

			    // issue request
			    ares_gethostbyname(channel, host, AF_INET, callback, current_query_info);
			    // ipv6:
			    //ares_gethostbyname(channel, "google.com", AF_INET6, callback, NULL);

			    // wait for asynchronous code to terminate
			    wait_ares(channel);

			    // cleanup 
			    clean_dns_output(test, current_query_info);
		    }

		    // all logs of dns tests are placed in one file,
		    // we get its name from the last query info
		    // we disable mptcp for this
		    int ori_mptcp = disable_mptcp();
		    upload_log(current_query_info->log_path);
		    set_mptcp(ori_mptcp);

		    // perform validations
		    config_setting_t *validations = config_setting_get_member(query, "validations");
		    if (validations != NULL) {
			    //printf("Performing validations\n");
			    int validations_count = config_setting_length(validations);
			    // iterate over validation of this query
			    int m;
			    for(m=0;m<validations_count;m++){
				    config_setting_t *validation = config_setting_get_elem(validations, m);
				    // wipe message from previous validation
				    memset(message,0,sizeof(message));
				    perform_dns_validation(queries_info, validation, &message);
				    client_log("%s",message);

			    }
		    }
		    // FIXME: free this for each element in queries_info
		    //slist_free(query_info->list);
		    ares_destroy(channel);
	}
	ares_library_cleanup();
}


/////////////////////// end C-ares test ////////////////////////////////////////

int validate_test_entry(config_setting_t *test) {
	const char *name_str;
	config_setting_t *name_setting = config_setting_get_member(test, "name");
	config_setting_t *type_setting = config_setting_get_member(test, "type");
	if (name_setting!=NULL){
		name_str = config_setting_get_string(name_setting);
		client_log(KYEL "\n%s running...\n" KNON, name_str);
	}
	else
	{
		client_log(KRED "no name provided for test, aborting..." KNON);
		return 0;
	}



	if (type_setting==NULL){
		client_log(KRED "Not type specified for test \"%s\"\n" KNON, name_str);
		return 0;
	}
}

void run_test(config_setting_t *test, config_setting_t *output_dir, const char* suffix) {
	    config_setting_t *type_setting = config_setting_get_member(test, "type");
	    const char *type_str = config_setting_get_string(type_setting);
	    if (!strcmp(type_str,"curl")) {
		    run_curl_test(test, output_dir, suffix);
	    }
	    else if (!strcmp(type_str,"dns")) {
		    run_cares_test(test,output_dir, suffix);
	    }
	    else {
		    client_log(KRED "Unknown test type \"%s\"\n" KNON, type_str);
	    }

}



#define add_mapping(tab,code,type) tab[(code)] = (mapping) {#code, code, type} 
int main(int argc, char *argv[])
{
  // config root
  config_t cfg;
  // path to config file
  char *tests_file;
  // was config reas successfully?
  int config_read;
  // tests list entry
  config_setting_t *tests;
  // number of tests and index in loop
  int tests_count, i;
  //test entry and test name string
  config_setting_t *test, *name_setting, *type_setting, *output_dir;
  // string value of name_setting
  const char * name_str, *type_str;




 
  if( parse_config(argc, argv,&cfg)) {
    //extract tests
    output_dir = config_lookup(&cfg, "output_dir");
    // open file handle for client logs
    setup_logging(output_dir);
    tests = config_lookup(&cfg, "tests");
    char* run_id;
    get_run_id(&run_id);
    client_log("Run id is " KMAG "%s\n" KNON, run_id);
    if(tests != NULL) {
      tests_count = config_setting_length(tests);
       
      //printf("found %d tests\n", tests_count);
      client_log("found %d tests\n", tests_count);
    }
    puts("\n\n\n\n\nHelp us! You can optionally enter your email so we can contact you for debugging purposes:");
    char *email=(char*)malloc(120*sizeof(char));
    fgets(email, 120,stdin);
    puts("If you wish you can also shortly describe your environment (end with an empty line):");
    char *response;
    read_input(&response);
    fprintf(log_file, "Contact email: %s\n", email);
    fprintf(log_file, "Description: %s\n", response);
    free(email);
    free(response);

    // iterate on tests
    for (i=0; i<tests_count; i++){
	    test = config_setting_get_elem(tests, i);
	    if (validate_test_entry(test)) {
		    if (can_toggle_mptcp()) {
			int ori_mptcp = current_mptcp();
			int ori_csum  = current_csum();
			client_log(KGRN "Can toggle mptcp\n" KNON); 


			client_log(KYEL "Disabling mptcp\n" KNON); 
			disable_mptcp();
			disable_csum();
			run_test(test, output_dir, "_without_mptcp");
			
			client_log(KYEL "Enabling mptcp but no checksum\n" KNON); 
			enable_mptcp();
			run_test(test, output_dir, "_with_mptcp_no_csum");
			
			client_log(KYEL "Enabling checksum\n" KNON); 
			enable_csum();
			run_test(test, output_dir, "_with_mptcp_csum");

			set_mptcp(ori_mptcp);
			set_csum(ori_csum);
		    }
		    else {
			client_log(KRED "Cannot toggle mptcp, running with current setting, i.e. mptcp %s\n" KNON, (is_mptcp_active() ? "active" : "inactive")); 
			run_test(test, output_dir, (is_mptcp_active() ? "_active_mptcp" : "_inactive_mptcp") );
		    }
	    }
    }
    client_log("********************************************************************************\nRun id is " KMAG "%s" KNON "\n", run_id);
    client_log("Access your logs online at http://www.multipath-tcp.org/mbdetect_logs/%s/\n", run_id);
    client_log("********************************************************************************\n");
    close_logging();
    upload_log(log_path);
 
  }
  else {
	  printf("test config error\n");
  }
  return 0;
}
