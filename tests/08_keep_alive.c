#include <stdio.h>
#include <curl/curl.h>


int double_query(CURL* curl) {
	CURLcode res;
	/* Perform the request, res will get the return code */ 
	res = curl_easy_perform(curl);
	/* Check for errors */ 
	if(res != CURLE_OK)
	  fprintf(stderr, "curl_easy_perform() failed: %s\n",
	          curl_easy_strerror(res));
	
	/* Repeat query and see ports */
	res = curl_easy_perform(curl);
	if(res != CURLE_OK)
	  fprintf(stderr, "curl_easy_perform() failed: %s\n",
	          curl_easy_strerror(res));
}
 
int main(void)
{
  CURL *curl;
  CURLcode res;
 
  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:8080");
    /* example.com is redirected, so we tell libcurl to follow redirection */ 
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    /* also print headers */
    curl_easy_setopt(curl, CURLOPT_HEADER, 1L );


    // FIXME
    // Default is already keep-alive
    // Maybe test it with Connection: close
    // Set headers
    struct curl_slist *headers=NULL; 
    headers = curl_slist_append(headers, "Connection: Keep-Alive"); 
    res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers); 


 
    double_query(curl);


    printf("-------------------------\n");

    /* Now send 2 queries with Connection: Close header */
    curl_slist_free_all(headers);
    headers=NULL;
    headers = curl_slist_append(headers, "Connection: Close"); 
    res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers); 

    double_query(curl);
 
    /* always cleanup */ 
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
  }
  return 0;
}
