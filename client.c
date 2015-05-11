// exit 1 = no mapping found
// exit 2 = test library not found
#include <stdio.h>
// curl needed for download of tests and upload of logs
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>
#include <libconfig.h>
#include "utils/mbd_utils.h"
#include "utils/mbd_version.h"
#include "utils/slist.h"
#include <uuid/uuid.h>
#include <dlfcn.h>

// ofr upload_log_file
#include <sys/stat.h>

// libsodium for hash computation
#include <sodium.h>


// declaration of mappings of option name to their constant's value
// declared as global for easier initialisation (avoids passing the pointer to pointer to append_mappings) 
// and avoids changing multiple functions. 
mapping *mappings;

void get_run_log_dir(config_setting_t *output_dir, char **run_path);
FILE *log_file;
char log_path[MAX_LOG_PATH_SIZE];

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

// find a mapping options as string -> option symbol
int find_mapping(const char* option, mapping* m) {
	int i=0;
	mapping *found, *current=mappings;

	while (current!=NULL && strcmp(current->name, option)) {
		current=current->next;
	}
	if (current!=NULL) {
		*m = *current;
		return 1;
	}
	else {
		client_log("Options %s not handled by this code\n", option);
		return -1;
	}

}
 
// return the value of the symbol whose name is passed as string
int find_code(const char* option) {
	int i=0;
	mapping *found, *current=mappings;
	while (current!=NULL && strcmp(current->name, option)) {
		current=current->next;
	}
	if (current!=NULL) {
		return current->code;
	}
	else {
		printf("Option %s not handled by this code, code not found\n", option);
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

 

// append option mappings, used by test libraries
int append_mappings(mapping *additions, int length) {
	printf("Adding %d mappings\n", length);
	// loop index
	int i;
	// next will be the mapping we need to initialise
	mapping *next=mappings;
	if (next==NULL) {
		mappings=(mapping*)malloc(sizeof(mapping));
		next=mappings;
	} else {
		while (next->next!=NULL) {
			next=next->next;
		}
		next=(mapping*)malloc(sizeof(mapping));
	}
	// from here next correctly point to the next mapping in the list to be initialised
	for (i=0; i<length; i++){
		// copy value to memory
		memcpy(next,additions+i, sizeof(mapping));
		// set pointer to last element
		next->next = (mapping*)malloc(sizeof(mapping));
		next = next->next;
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

// get the directory where this run's logs will be stored
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

// Check a test entry has all required attributes
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

// Linked list entry mapping test type named to its library functions
typedef struct test_mapping{
	const char* name;
	void (*init_options)();
	void (*run_test)(config_setting_t *test, config_setting_t *output_dir, const char *suffix);
	struct test_mapping *next;
} test_mapping;

test_mapping *test_mappings=NULL;

	
// Run the test, calling the functions from the related .so
void run_test(config_setting_t *test, config_setting_t *output_dir, const char* suffix) {
	    config_setting_t *type_setting = config_setting_get_member(test, "type");
	    const char *type_str = config_setting_get_string(type_setting);
	    void (*run_lib_test)(config_setting_t *test, config_setting_t *output_dir, const char *suffix);
	    void (*init_options)();
	    test_mapping *current=NULL;
	    if (test_mappings==NULL) {
		    test_mappings=(test_mapping*) malloc(sizeof(test_mapping));
	    }
	    else {
		    current=test_mappings;
		    while (strcmp(current->name, type_str) && current->next!=NULL) {
			    current=current->next;
		    }
	    }
	    //found, run it
	    if (current!=NULL && !strcmp(current->name,type_str)) {
		    run_lib_test = current->run_test;
		    init_options = current->init_options;
	    }
	    else {
		    //need to add it
		    //load it
		    // build library name to load : "./lib"+type_str+"_tests.so"
		    int size=(5+strlen(type_str)+9+1)*sizeof(char);
		    char *filename =(char *) malloc(size);
		    memset(filename,0,size);

		    strncat(filename,"./lib", 5);
		    strncat(filename, type_str, strlen(type_str));
		    strncat(filename, "_tests.so", 9);

		    void *handle = dlopen(filename, RTLD_LAZY);
		    if (!handle) {
			    printf("test shared library %s not found\n", filename);
			    exit(2);
		    }
		    free(filename);

		    run_lib_test=dlsym(handle,"run_lib_test");
		    init_options=dlsym(handle,"init_options");
		    // initialise it
		    init_options();

		    // now add it to the mappings
		    // this is the first test type in the mapping
		    // so the current entry (to be added) is at the address of test_mapping
		    if (current==NULL) {
			    //set test_mappings values
			    current=test_mappings;
		    }
		    else {
			    // create new one at end of list
			    current->next=(test_mapping*) malloc(sizeof(test_mapping));
			    current=current->next;
		    }
		    // in the other case, current was already set
		    current->name = type_str; //point to type_str value in config file
		    current->init_options = init_options;
		    current->run_test = run_lib_test;
		    current->next = NULL;

	    }

	    current->run_test(test, output_dir, suffix);

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
  // initialise mappings
  mappings=NULL;


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
