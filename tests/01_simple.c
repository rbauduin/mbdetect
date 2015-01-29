#include <stdio.h>
#include <curl/curl.h>


typedef struct {
	char *name;
	int code;
	char *type;
} mapping;
mapping arr[100000];
//=  {
//	{"CURLOPT_URL", CURLOPT_URL, "str"},
//	{"CURLOPT_HEADER", CURLOPT_HEADER, "long"}
//} 
 
#define add_mapping(tab,code,type) tab[(code)] = (mapping) {#code, code, type} 
int main(void)
{
  CURL *curl;
  CURLcode res;
add_mapping(arr,CURLOPT_URL,"str");
add_mapping(arr,CURLOPT_FOLLOWLOCATION,"long");
add_mapping(arr,CURLOPT_HEADER,"long");
 
  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:8080");
    /* example.com is redirected, so we tell libcurl to follow redirection */ 
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    /* also print headers */
    curl_easy_setopt(curl, CURLOPT_HEADER, 1L );
 
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
