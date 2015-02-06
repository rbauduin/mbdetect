#include "mongoose.h"
#include "string.h"
#include <time.h>
#include <stdlib.h>
#include <sodium.h>

// See http://cesanta.com/docs/Embed.shtml

void init_headers(crypto_hash_sha256_state *state) {
	char first_line[]="HTTP/1.1 200 OK\r\n";
	printf("%s", first_line);
	crypto_hash_sha256_init(state);
	crypto_hash_sha256_update(state, first_line, strlen(first_line));
}
void set_header(struct mg_connection *conn,crypto_hash_sha256_state *state, char *name, char *value) {
	char *header;
	int header_len;
	mg_send_header(conn, name,value);

	// +2 : ": "
	// +2 : \r\n
	header_len = strlen(name)+strlen(value)+2+2;
	// +1 : \0
	header=malloc(header_len+1);
	strcpy(header,name);
	strcat(header,": ");
	strcat(header,value);
	strcat(header,"\r\n");
	// -1 : do not put the null terminating char in the sha256 computation
	crypto_hash_sha256_update(state, header, header_len);
	printf("%s", header);
	free(header);
}

// had the chunked encoding header + the sha256 value as a last header
void close_headers(struct mg_connection * conn,crypto_hash_sha256_state *state) {
	// the sha256 result
	unsigned char out[crypto_hash_sha256_BYTES];
	// string representation of the sha256
	char *sha;
	char last_line[]="Transfer-Encoding: chunked\r\n\r\n";
	crypto_hash_sha256_update(state, last_line, strlen(last_line));


	crypto_hash_sha256_final(state, out);
	sha=malloc(sizeof(out)*2+1);
	sodium_bin2hex(sha, sizeof(out)*2+1, out, sizeof(out));
	printf("%s",last_line);
	printf("headers sha256 :\n%s\n", sha);

	mg_send_header(conn, "X-NH-H-SHA256",sha);
	free(sha);
}


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

	crypto_hash_sha256_state state;

	init_headers(&state);
	set_header(conn, &state, "X-TeSt","WiTnEsS");
	close_headers(conn,&state);
	//mg_send_header(conn, "X-NH-TEST","test control header");
	mg_send_header(conn,"X-NH-TEST","test control header");
	mg_send_header(conn, "X-NH-RETEST","test control header");

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
