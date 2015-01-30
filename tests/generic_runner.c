#include <stdio.h>
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>
#include <libconfig.h>


typedef struct {
	char *name;
	int code;
	char *type;
} mapping;
mapping mappings[] =  {
	{"CURLOPT_URL", CURLOPT_URL, "str"},
	{"CURLOPT_HEADER", CURLOPT_HEADER, "long"},
	{"CURLOPT_FOLLOWLOCATION", CURLOPT_FOLLOWLOCATION, "long"},
	{"CURLOPT_POST", CURLOPT_POST, "long"},
	{"CURLOPT_POSTFIELDSIZE", CURLOPT_POSTFIELDSIZE, "long"},
	{"CURLOPT_POSTFIELDS",CURLOPT_POSTFIELDS,"str"}

}; 

int mappings_len = sizeof(mappings)/sizeof(mappings[0]);


 
// structure keeping where we write
typedef struct write_dest {
	FILE *fd;
	size_t size;
} file_write;

static size_t discard_data(void *ptr, size_t size, size_t nmemb, void *userp){
  return size*nmemb;
}

static size_t
write_in_file(void *contents, size_t size, size_t nmemb, void *userp)
{
  file_write *dest;
  size_t realsize = size * nmemb, written;
  dest = (file_write *)userp;
  written = fwrite(contents, size, nmemb, dest->fd);
  return written*size;
}





int find_mapping(const char* option, mapping* m) {
	int i=0;
	mapping found;
	while (i<mappings_len && strcmp(mappings[i].name, option)) {
		i++;
	}
	if (i<mappings_len) {
		//printf("mapping %s = option %s\n", mappings[i].name, option);
		*m = mappings[i];
		return 0;
	}
	else {
		error("Options %s not handled by this code\n", option);
		return 1;
	}

}
 
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

void set_options(CURL* curl, config_setting_t *test){
	int j;
	config_setting_t *options = config_setting_get_member(test, "options");
	int options_count = config_setting_length(options);
	for (j=0; j<options_count; j++){
		config_setting_t *option=config_setting_get_elem(options,j);
		config_setting_t *name = config_setting_get_member(option, "name");
		config_setting_t *value = config_setting_get_member(option, "value");
		const char *name_str = config_setting_get_string(name);
		mapping m;
		int r = find_mapping(name_str,&m);
		if (r) {
			printf("ERROR, no mapping found!\n");
			exit(1);
		}
		//printf("mapping : %s %s\n",m.name,m.type);
		if (!strncmp(m.type,"str",3)) {
			const char *value_str = config_setting_get_string(value);
		//	printf("STR %s = %s\n", name_str, value_str);
			curl_easy_setopt(curl, find_code(name_str), value_str); 
		}
		else if (!strncmp(m.type,"long",4)){
			long value_long = config_setting_get_int64(value);
		//	printf("LONG %s = %lu\n", name_str, value_long);
			curl_easy_setopt(curl, find_code(name_str), value_long); 
		}
		else {
			printf("NO MATCH\n____________________________________\n");
		}
	}
}

void set_headers(CURL* curl, config_setting_t *test, struct curl_slist* headers){
	int j,res;
	config_setting_t *cfg_headers = config_setting_get_member(test, "headers");
	if (cfg_headers==NULL)
		return ;
	int headers_count = config_setting_length(cfg_headers);
	for (j=0; j<headers_count; j++){
		const char* header=config_setting_get_string_elem(cfg_headers,j);
		headers = curl_slist_append(headers, header); 
	}
    	res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers); 
}

void set_output(CURL* curl, config_setting_t *test, void *userp){
	config_setting_t *output_file = config_setting_get_member(test, "output_file");
	if (output_file==NULL){
	    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_data);
	}
	else {
		file_write *dest = (file_write *) userp;
		const char *path = config_setting_get_string(output_file);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_in_file);
		FILE *f = fopen(path,"w");
		dest->fd=f;
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, userp);
	}
}

void clean_output(config_setting_t *test, void *userp){
	config_setting_t *output_file = config_setting_get_member(test, "output_file");
	if (output_file==NULL){
	    return;
	}
	else {
		file_write *dest = (file_write *) userp;
		fclose(dest->fd);	
		// FIXME: reset user structure to empty
		dest->fd=NULL;
		dest->size=0;
	}
}

#define add_mapping(tab,code,type) tab[(code)] = (mapping) {#code, code, type} 
int main(void)
{
  CURL *curl;
  CURLcode res;
  config_t cfg;
  int ret,i,j,count;
 
  ret = read_config("one_test.cfg", &cfg);
  if(curl && ret==0) {
    config_setting_t *tests = config_lookup(&cfg, "tests");
    if(tests != NULL) {
      count = config_setting_length(tests);
      int i;
       
      printf("found %d tests\n", count);
    }
    for (i=0; i<count; i++){
	    file_write dest;
	    curl = curl_easy_init();
	    config_setting_t *test = config_setting_get_elem(tests, i);
	    set_options(curl, test);
            set_output(curl, test, &dest);
	    struct curl_slist * curl_headers=NULL;
	    set_headers(curl, test, curl_headers);

	    /* Perform the request, res will get the return code */ 
	    res = curl_easy_perform(curl);
	    /* Check for errors */ 
	    double content_len;
	    if(res != CURLE_OK)
		    fprintf(stderr, "curl_easy_perform() failed: %s\n",
				    curl_easy_strerror(res));
	    else {
		    curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &content_len);
		    printf("Content length was : %f\n", content_len);
	    }
	    /* always cleanup */ 
	    clean_output(test, &dest);
	    curl_slist_free_all(curl_headers);
	    curl_easy_cleanup(curl);
    }
 
  }
  else {
	  printf("no curl or no config\n");
  }
  return 0;
}
