#include <stdio.h>
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>
#include <libconfig.h>

// libsodium for hash computation
#include <sodium.h>


typedef struct {
	char *name;
	int code;
	char *type;
} mapping;
mapping mappings[] =  {
	{"CURLOPT_URL", CURLOPT_URL, "str"}
	,{"CURLOPT_HEADER", CURLOPT_HEADER, "long"}
	,{"CURLOPT_FOLLOWLOCATION", CURLOPT_FOLLOWLOCATION, "long"}
	,{"CURLOPT_POST", CURLOPT_POST, "long"}
	,{"CURLOPT_POSTFIELDSIZE", CURLOPT_POSTFIELDSIZE, "long"}
	,{"CURLOPT_POSTFIELDS",CURLOPT_POSTFIELDS,"str"}
	,{"CURLINFO_SIZE_DOWNLOAD",CURLINFO_SIZE_DOWNLOAD,"int"}
	,{"CURLINFO_RESPONSE_CODE",CURLINFO_RESPONSE_CODE ,"int"}
	
}; 

int mappings_len = sizeof(mappings)/sizeof(mappings[0]);


// stuff to write output to file
// *****************************
// structure keeping where we write
typedef struct write_dest {
	FILE *fd;
	size_t size;
	char *path;
	crypto_hash_sha256_state sha_state;
} payload_specs;

// callback discarding data
static size_t discard_data(void *ptr, size_t size, size_t nmemb, void *userp){
	payload_specs *specs;
	size_t realsize = size * nmemb;
	specs = (payload_specs *)userp;
	crypto_hash_sha256_update(&(specs->sha_state), ptr, realsize);
	return size*nmemb;
}

// callback writing data to file
static size_t
write_in_file(void *contents, size_t size, size_t nmemb, void *userp)
{
  payload_specs *specs;
  size_t realsize = size * nmemb, written;
  specs = (payload_specs *)userp;
  written = fwrite(contents, size, nmemb, specs->fd);
  crypto_hash_sha256_update(&(specs->sha_state), contents, size*nmemb);
  return written*size;
}
//------------------------------------



// FIXME: can we limit code duplication here?

// ----- double validations
int extract_double(config_setting_t* entry, const char* name, double* value) {
	config_setting_t *name_entry = config_setting_get_member(entry, "name");
	config_setting_t *value_entry = config_setting_get_member(entry, "value");
	if (name_entry == NULL || value_entry == NULL) {
		return -1;
	}
	name = config_setting_get_string(name_entry);
	*value = config_setting_get_float(value_entry);
	return 0;
}

int get_actual_double(CURL *curl, const char *name, double* actual) {
	int code;
	code = find_code(name);
	curl_easy_getinfo(curl, code, actual);
}
int double_equal_validation(CURL* curl,config_setting_t* validation) {
	double expected, actual;
	config_setting_t *name_setting;
	const char * name;

	name_setting = config_setting_get_member(validation, "name");
	name = config_setting_get_string(name_setting);
	extract_double(validation, name,&expected);
	get_actual_double(curl, name, &actual);
	if (actual==expected){
		printf("As expected, %f = %f\n",actual, expected);
	}
	else {
		printf("UNEXPECTED, got %f but expected %f\n", actual, expected);
	}

}


// ----- int validations
int extract_int(config_setting_t* entry, const char* name, int* value) {
	config_setting_t *name_entry = config_setting_get_member(entry, "name");
	config_setting_t *value_entry = config_setting_get_member(entry, "value");
	if (name_entry == NULL || value_entry == NULL) {
		return -1;
	}
	name = config_setting_get_string(name_entry);
	*value = config_setting_get_int(value_entry);
	return 0;
}

int get_actual_int(CURL *curl, const char *name, int* actual) {
	int code;
	code = find_code(name);
	curl_easy_getinfo(curl, code, actual);
}
int int_equal_validation(CURL* curl,config_setting_t* validation) {
	int expected, actual;
	config_setting_t *name_setting;
	const char * name;

	name_setting = config_setting_get_member(validation, "name");
	name = config_setting_get_string(name_setting);
	extract_int(validation, name,&expected);
	get_actual_int(curl, name, &actual);
	if (actual==expected){
		printf("As expected, %s %d = %d\n", name, actual, expected);
	}
	else {
		printf("UNEXPECTED, got %d but expected %d\n", actual, expected);
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
		error("Options %s not handled by this code\n", option);
		return 1;
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
		printf("Options %s not handled by this code\n", option);
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

// set curl options
void set_options(CURL* curl, config_setting_t *test){
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
			value_str = config_setting_get_string(value);
		//	printf("STR %s = %s\n", name_str, value_str);
			curl_easy_setopt(curl, find_code(name_str), value_str); 
		}
		else if (!strncmp(m.type,"long",4)){
			value_long = config_setting_get_int64(value);
		//	printf("LONG %s = %lu\n", name_str, value_long);
			curl_easy_setopt(curl, find_code(name_str), value_long); 
		}
		else {
			printf("NO MATCH\n____________________________________\n");
		}
	}
}

// set http headers
int set_headers(CURL* curl, config_setting_t *test, struct curl_slist* headers){
	// index, curl result, number of headers
	int j,res, headers_count;
	// the header string
	const char *header;
	config_setting_t *cfg_headers = config_setting_get_member(test, "headers");
	if (cfg_headers==NULL)
		return CURLE_OK;
	// iterate over the list of header strings and add each to the curl_slist *headers
	headers_count = config_setting_length(cfg_headers);
	for (j=0; j<headers_count; j++){
		header=config_setting_get_string_elem(cfg_headers,j);
		headers = curl_slist_append(headers, header); 
	}
	// add the headers list to curl
    	res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers); 
	return res;
}

// where to write the data received
void set_output(CURL* curl, config_setting_t *test, payload_specs *headers_specs, payload_specs *body_specs){
	
	// output_file setting
	config_setting_t *output_file = config_setting_get_member(test, "output_file");
	// length of the paths we will write to, ie with the -H and -D suffix appended
	int final_path_len;
	// path string retrieved from output_file setting
	const char *base_path;
	char *headers_path, *body_path;
	// file opened for writing body, and headers
	FILE * f, *fh;

	// and initialise the sha state
	crypto_hash_sha256_init(&(body_specs->sha_state));
	crypto_hash_sha256_init(&(headers_specs->sha_state));

	// discard data if no output_file present
	if (output_file==NULL){
		// discard both data and headers
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_data);
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, discard_data);

		// Do not write to file, but we'll still compute the hash
		// Body
		body_specs->fd=NULL;
		body_specs->path=NULL;
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, body_specs);
		// Headers
		headers_specs->fd=NULL;
		headers_specs->path=NULL;
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, headers_specs);
	}
	else {
		// specify callback to call when receiving data for body and headers
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_in_file);
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, write_in_file);

		// setup the config structure passed to successive call of the callback
		// the base_path is found in the config file. To that
		// we append -D for the body, and -H for the headers,
		// and we have the files paths where we write to
		base_path = config_setting_get_string(output_file);
		final_path_len = strlen(base_path)+2;
		// +1 for \0
		headers_path = malloc(final_path_len+1);
		body_path = malloc(final_path_len+1);

		// concatenate path and suffix
		strncpy(headers_path, base_path, final_path_len+1);
		strncat(headers_path, "-H", final_path_len+1);

		strncpy(body_path, base_path, final_path_len+1);
		strncat(body_path, "-D", final_path_len+1);

		// open file handle, setup struct and passit to curl
		// Body
		f = fopen(body_path,"w");
		body_specs->fd=f;
		body_specs->path=body_path;
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, body_specs);
		// Headers
		fh = fopen(headers_path,"w");
		headers_specs->fd=fh;
		headers_specs->path=headers_path;
		curl_easy_setopt(curl, CURLOPT_HEADERDATA, headers_specs);
	}
}

void clean_output(config_setting_t *test, payload_specs *headers_specs,payload_specs  *body_specs ){
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
		    payload_specs body_specs;
		    payload_specs headers_specs;
		    curl = curl_easy_init();
		    // get query of this iteration
		    config_setting_t *query = config_setting_get_elem(queries, k);

		    // set options and headers
		    set_options(curl, query);
		    set_output(curl, query, &headers_specs, &body_specs);
		    curl_headers=NULL;
		    set_headers(curl, query, curl_headers);

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
						    type_entry = config_setting_get_member(validation, "type");
						    // validation possible only if its type is specified
						    if (type_entry!=NULL){
							    type_str = config_setting_get_string(type_entry);
							    // curl option of type int
							    if (!strncmp(type_str, "int_equal", sizeof(type_str))){
								    int_equal_validation(curl, validation);
							    }
							    // curl option of type double
							    else if (!strncmp(type_str, "double_equal", sizeof(type_str))){
								    double_equal_validation(curl, validation);
							    }
							    // unknown test type
							    else {
								    printf("VALIDATION TYPE UNKNOWN : %s\n", type_str);
							    }
						    }
						    else {
							    continue;
						    }
					    }
				    }
			    }
			    // FIXME: move var declarations or put this in a function
			    unsigned char out[crypto_hash_sha256_BYTES];
			    crypto_hash_sha256_final(&(body_specs.sha_state), out);
			    char* sha=malloc(sizeof(out)*2+1);
			    sodium_bin2hex(sha, sizeof(out)*2+1, out, sizeof(out));
			    printf("body sha256 (file=%s):\n%s\n", body_specs.path,sha);

			    crypto_hash_sha256_final(&(headers_specs.sha_state), out);
			    sodium_bin2hex(sha, sizeof(out)*2+1, out, sizeof(out));
			    printf("headers sha256 (file=%s):\n%s\n", headers_specs.path,sha);
		    }
		    /* always cleanup */ 
		    clean_output(query, &headers_specs, &body_specs);
		    curl_slist_free_all(curl_headers);
		    curl_easy_cleanup(curl);
	    }
    }
 
  }
  else {
	  printf("no curl or no config\n");
  }
  return 0;
}
