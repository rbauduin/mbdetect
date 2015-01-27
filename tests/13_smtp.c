#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <time.h>


#define SERVER  "smtp://localhost:2525"
#define FROM    "<raphael.bauduin@uclouvain.be>"
#define TO      "<raphinou@yahoo.com>"
 



char *payload_text[200];


// Passed as user pointer to the READFUNCTION function (see READDATA below)
struct upload_status {
  int lines_read;
};
 
static size_t payload_source(void *ptr, size_t size, size_t nmemb, void *userp)
{
  struct upload_status *upload_ctx = (struct upload_status *)userp;
  const char *data;
 
  if((size == 0) || (nmemb == 0) || ((size*nmemb) < 1)) {
    return 0;
  }
 
  data = payload_text[upload_ctx->lines_read];
 
  if(data) {
    size_t len = strlen(data);
    memcpy(ptr, data, len);
    upload_ctx->lines_read++;
 
    return len;
  }
 
  return 0;
}

 
int main(void)
{
  CURL *curl;
  CURLcode res;
  struct curl_slist *recipients = NULL;
  static const char *from = "<raphael.bauduin@uclouvain.be>";
  static const char *to   = "<raphinou@yahoo.com>";
  struct upload_status upload_ctx;
  char message_id[150];
  time_t timer;
  struct tm* tm_info;
  char date[50];

  time(&timer);
  tm_info = localtime(&timer);
  //strftime(buffer, 25, "Date: %Y:%m:%d%H:%M:%S", tm_info);
  strftime(date, 50, "Date: %a, %d %b %Y %H:%M:%S %z", tm_info);

  printf("date : %s \n", date);

  srand(time(NULL));
  sprintf(message_id, "Message-ID: <%d@multipath-tcp.org>\r\n",rand());
  printf("id : %s \n", message_id);

  payload_text[0]=  date;
  payload_text[1]=  "To: " TO "\r\n";
  payload_text[2]=  "From: " FROM "(Sender)\r\n";
  payload_text[3]=  "Subject: SMTP test message\r\n";
  payload_text[4]=  message_id;
  payload_text[5]=  "\r\n"; /* empty line to divide headers from body, see RFC5322 */ 
  payload_text[6]=  "Thanks for sending this mail and testing multipath-tcp!.\r\n";
  payload_text[7]=  "\r\n";
  payload_text[8]=  NULL;
 
  upload_ctx.lines_read = 0;
 
  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, SERVER);
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, from);

    recipients = curl_slist_append(recipients, to);
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
    
    // Read data from stdin
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
    curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

 
    /* Perform the request, res will get the return code */ 

    //printf("Does nothing at this time because line %d is commented\n", __LINE__+1);
    res = curl_easy_perform(curl);

    /* Check for errors */ 
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
 
    /* always cleanup */ 
    curl_slist_free_all(recipients);
    curl_easy_cleanup(curl);
  }
  return 0;
}
