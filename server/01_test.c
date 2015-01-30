#include "mongoose.h"
#include "string.h"
#include <time.h>
#include <stdlib.h>

// See http://cesanta.com/docs/Embed.shtml


int event_handler(struct mg_connection *conn, enum mg_event ev) {
  int i,random;
  // QUESTION what about doing it with pointer?
  char new_uri[15];
  switch (ev) {
    case MG_AUTH: return MG_TRUE;
    case MG_REQUEST: 
	// needs to be in the switch statement, or segfaults
        // do not process requests for /cumulus.jpg, let the standard handler do it
        // hence serving file from filesystem
        if (!strcmp(conn->uri, "/cumulus.jpg")) {
        	return MG_FALSE;
        }
	// If path starts with /files, serve file on disk
        if (!strncmp(conn->uri, "/files", 6)) {
        	return MG_FALSE;
	}

	// requests to /random.jpg return a random image
        if (!strcmp(conn->uri, "/random.jpg")) {
		random=rand()%10;
		sprintf(new_uri,"/cumulus_%d.jpg", random);
		printf("%s\n",new_uri);
		conn->uri=new_uri;
		printf("will return %s for client on port %d\n", conn->uri, conn->remote_port);
        	return MG_FALSE;
        }

	mg_send_header(conn, "X-TeSt","WiTnEsS");
    	mg_printf_data(conn, "%s\n", "Welcome hehe!");
	mg_printf_data(conn, "%s\n", mg_get_header(conn, "Host"));
	printf("---Start of headers---\n");
        for (i = 0; i < conn->num_headers; i++){
            mg_printf_data(conn, "%s : %s\n", conn->http_headers[i].name, conn->http_headers[i].value);
            printf("%s : %s\n", conn->http_headers[i].name, conn->http_headers[i].value);
	}
	printf("---End of headers---\n");
        mg_printf_data(conn, "client ip : %s\n", conn->remote_ip);
        mg_printf_data(conn, "client port : %d\n", conn->remote_port);
        printf("POST length: %zd\n", conn->content_len);
        mg_printf_data(conn, "POST length: %zd\n", conn->content_len);
	printf("POST data : %s\n" , strndup(conn->content, conn->content_len));
	mg_printf_data(conn, "POST data : %s\n" , strndup(conn->content, conn->content_len));
    	mg_printf_data(conn, "%s\n", "Bye hehe!");
	return MG_TRUE;
    default: return MG_FALSE;
  }
}

int main(void) {
  struct mg_server *server = mg_create_server(NULL, event_handler);
  // seed prng
  srand(time(NULL));

  mg_set_option(server, "document_root", ".");      // Serve current directory
  mg_set_option(server, "listening_port", "8080");  // Open port 8080

  for (;;) {
    mg_poll_server(server, 1000);   // Infinite loop, Ctrl-C to stop
  }
  mg_destroy_server(&server);

  return 0;
}
