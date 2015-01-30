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
	{"CURLOPT_FOLLOWLOCATION", CURLOPT_FOLLOWLOCATION, "long"}
}; 

int mappings_len = sizeof(mappings)/sizeof(mappings[0]);

int find_mapping(const char* option, mapping* m) {
	int i=0;
	mapping found;
	while (i<mappings_len && strncmp(mappings[i].name,option, strlen(option))) {
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
 
int find_code(const char* option) {
	int i=0;
	while (i<mappings_len && strncmp(mappings[i].name,option, strlen(option))) {
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


#define add_mapping(tab,code,type) tab[(code)] = (mapping) {#code, code, type} 
int main(void)
{
  CURL *curl;
  CURLcode res;
  config_t cfg;
  int ret,i,j,count;
 
  curl = curl_easy_init();
  ret = read_config("curl_tests.cfg", &cfg);
  if(curl && ret==0) {
    config_setting_t *tests = config_lookup(&cfg, "tests");
    if(tests != NULL) {
      count = config_setting_length(tests);
      int i;
       
      printf("found %d tests\n", count);
    }
    for (i=0; i<count; i++){
	    config_setting_t *test = config_setting_get_elem(tests, i);
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
		    else {
			    printf("Found mapping %d\n", r);
		    }
		    printf("Will set option %s (option name %s) of type %s\n", name_str, m.name,m.type);
		    if (!strncmp(m.type,"str",3)) {
			    printf("MATCH str m.type=%s\n************************************\n", m.type);
		               const char *value_str = config_setting_get_string(value);
	                       printf("%s = %s\n", name_str, value_str);
                               curl_easy_setopt(curl, find_code(name_str), value_str); 
		    }
		    else if (!strncmp(m.type,"long",4)){
			    printf("MATCH long m.type=%s\n************************************\n", m.type);
		               long value_long = config_setting_get_int64(value);
	                       printf("%s = %lu\n", name_str, value_long);
                               curl_easy_setopt(curl, find_code(name_str), value_long); 
		    }
		    else {
			    printf("NO MATCH\n____________________________________\n");
		    }
	    }
    }

//    //curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:8080");
//    curl_easy_setopt(curl, find_code("CURLOPT_URL"), "http://localhost:8080");
//    /* example.com is redirected, so we tell libcurl to follow redirection */ 
//    //curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
//    curl_easy_setopt(curl,find_code("CURLOPT_FOLLOWLOCATION"), 1L);
//    /* also print headers */
//    //curl_easy_setopt(curl, CURLOPT_HEADER, 1L );
//    curl_easy_setopt(curl, find_code("CURLOPT_HEADER"), 1L );
 
    /* Perform the request, res will get the return code */ 
    res = curl_easy_perform(curl);
    /* Check for errors */ 
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
 
    /* always cleanup */ 
    curl_easy_cleanup(curl);
  }
  else {
	  printf("no curl or no config\n");
  }
  return 0;
}
