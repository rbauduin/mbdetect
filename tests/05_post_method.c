#include <stdio.h>
#include <curl/curl.h>
 
int main(void)
{
  CURL *curl;
  CURLcode res;
  const char *data = "POST data to send...";
 
  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:8080");
    /* we tell libcurl to follow redirection */ 
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    /* also print headers */
    curl_easy_setopt(curl, CURLOPT_HEADER, 1L );
    // this is a POST
    curl_easy_setopt(curl, CURLOPT_POST, 1L);

    // Set headers
    struct curl_slist *headers=NULL; 
    headers = curl_slist_append(headers, "AcCePt: text/html"); 
    headers = curl_slist_append(headers, "X-MiXeD-CaSe: 1");
    headers = curl_slist_append(headers, "Host: www.google.com");
    res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers); 
 
    // set POST data
    /* size of the POST data, number of chars in string sent */   
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 20L);

    /* pass in a pointer to the data - libcurl will not copy */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data); 

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
