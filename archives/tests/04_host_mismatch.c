#include <stdio.h>
#include <curl/curl.h>
 
int main(void)
{
  CURL *curl;
  CURLcode res;
 
  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:8080");
    /* we tell libcurl to follow redirection */ 
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    /* also print headers */
    curl_easy_setopt(curl, CURLOPT_HEADER, 1L );

    // Set headers
    struct curl_slist *headers=NULL; 
    headers = curl_slist_append(headers, "AcCePt: text/html"); 
    headers = curl_slist_append(headers, "X-MiXeD-CaSe: 1");
    headers = curl_slist_append(headers, "Host: www.google.com");
    res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers); 
 
    /* Perform the request, res will get the return code */ 
    res = curl_easy_perform(curl);
    /* Check for errors */ 
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
 
    /* always cleanup */ 
    curl_slist_free_all(headers); 
    curl_easy_cleanup(curl);
  }
  return 0;
}
