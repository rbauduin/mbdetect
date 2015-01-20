#include <stdio.h>
#include <curl/curl.h>
 
static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream){
  return size*nmemb;
}

int main(void)
{
  CURL *curl;
  CURLcode res;
  const char *data = "POST data to send...";
  double content_len;
 
  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:8080/cumulus.jpg");
    /* we tell libcurl to follow redirection */ 
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    /* send all data to this function, which just discards it  */ 
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);

    // Set headers
    struct curl_slist *headers=NULL; 
    headers = curl_slist_append(headers, "AcCePt: text/html"); 
    headers = curl_slist_append(headers, "X-MiXeD-CaSe: 1");
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
    else {
      curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &content_len);
      printf("Content length was : %f\n", content_len);
    }
 
    /* always cleanup */ 
    curl_slist_free_all(headers); 
    curl_easy_cleanup(curl);
  }
  return 0;
}
