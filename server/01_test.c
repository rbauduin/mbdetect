#include "mongoose.h"

// See http://cesanta.com/docs/Embed.shtml



int event_handler(struct mg_connection *conn, enum mg_event ev) {
  int i;
  switch (ev) {
    case MG_AUTH: return MG_TRUE;
    case MG_REQUEST: 
	//mg_send_header(conn, "X-TeSt","VaLuE");
    	mg_printf_data(conn, "%s\n", "Welcome hehe!");
	mg_printf_data(conn, "%s\n", mg_get_header(conn, "Host"));
        for (i = 0; i < conn->num_headers; i++){
            mg_printf_data(conn, "%s : %s\n", conn->http_headers[i].name, conn->http_headers[i].value);
            printf("%s : %s\n", conn->http_headers[i].name, conn->http_headers[i].value);
	}
    	mg_printf_data(conn, "%s\n", "Bye hehe!");
	return MG_TRUE;
    default: return MG_FALSE;
  }
}

int main(void) {
  struct mg_server *server = mg_create_server(NULL, event_handler);
  mg_set_option(server, "document_root", ".");      // Serve current directory
  mg_set_option(server, "listening_port", "8080");  // Open port 8080

  for (;;) {
    mg_poll_server(server, 1000);   // Infinite loop, Ctrl-C to stop
  }
  mg_destroy_server(&server);

  return 0;
}
