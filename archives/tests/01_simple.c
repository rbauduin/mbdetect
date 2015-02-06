#include <stdio.h>
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>


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
 
void set_option_long(CURL* curl, char* option, long value) {
	int i=0;
	while (i<mappings_len && strncmp(mappings[i].name,option, strlen(option))) {
		i++;
	}
	if (i<mappings_len) {
		curl_easy_setopt(curl, mappings[i].code, value); 
	}
	else {
		error("Options %s not handled by this code\n", option);
	}
}


void set_option_str(CURL* curl, char* option, char* value) {
	int i=0;
	while (i<mappings_len && strncmp(mappings[i].name,option, strlen(option)) ) {
		i++;
	}
	if (i<mappings_len) {
		printf("setting option");
		curl_easy_setopt(curl, mappings[i].code, value); 
	}
	else {
		printf("Options %s not handled by this code\n", option);
		exit(EXIT_FAILURE); 
	}
}

#define add_mapping(tab,code,type) tab[(code)] = (mapping) {#code, code, type} 
int main(void)
{
  CURL *curl;
  CURLcode res;
 
  curl = curl_easy_init();
  if(curl) {
    //curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:8080");
    set_option_str(curl, "CURLOPT_URL", "http://localhost:8080");
    /* example.com is redirected, so we tell libcurl to follow redirection */ 
    //curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    set_option_long(curl,"CURLOPT_FOLLOWLOCATION", 1L);
    /* also print headers */
    //curl_easy_setopt(curl, CURLOPT_HEADER, 1L );
    set_option_long(curl, "CURLOPT_HEADER", 1L );
 
    /* Perform the request, res will get the return code */ 
    res = curl_easy_perform(curl);
    /* Check for errors */ 
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
 
    /* always cleanup */ 
    curl_easy_cleanup(curl);
  }
  return 0;
}
