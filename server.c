#include "utils/mongoose.h"
#include "string.h"
#include <stdarg.h>
#include <time.h>
#include <stdlib.h>
#include <sodium.h>
#include "utils/mbd_utils.h"
#include <sys/stat.h>
#include "utils/mongoose.h"



void set_header(struct mg_connection *conn,crypto_hash_sha256_state *state, char *name, char *value) {
	char *header;
	int header_len;
	mg_send_header(conn, name,value);

	// if this is not a control header, add it to the headers hash computation
	if (! is_headers_hash_control_header(name)) {
		// +2 : ": "
		// +2 : \r\n
		header_len = strlen(name)+strlen(value)+2+2;
		// +1 : \0
		header=malloc(header_len+1);
		strcpy(header,name);
		strcat(header,": ");
		strcat(header,value);
		strcat(header,"\r\n");
		printf("HASHING HEADER %s\n", header);
		crypto_hash_sha256_update(state, header, header_len);
		free(header);
	}
	else
		printf("NOT hashing HEADER %s\n", header);
}



void add_sha_headers_content(crypto_hash_sha256_state *state, char* content){
	printf("hasing in headers %s\n", (char *) content);
	crypto_hash_sha256_update(state, content, strlen(content));
}


void sha_from_state(crypto_hash_sha256_state *state, char(* sha)[crypto_hash_sha256_BYTES*2+1]) {
	// the sha256 result
	unsigned char out[crypto_hash_sha256_BYTES];
	crypto_hash_sha256_final(state, out);
	sodium_bin2hex(*sha, sizeof(out)*2+1, out, sizeof(out));
}


// had the chunked encoding header + the sha256 value as a last header
void end_hashed_headers(struct mg_connection *conn, crypto_hash_sha256_state *state) {
	// string representation of the sha256
	char sha[crypto_hash_sha256_BYTES*2+1];

	// finalise sha computation and send the header
	sha_from_state(state,&sha);

	// mg_send_headers blocked in mbd_file_endpoint, dunno why.
	printf("Sending hash header\n");
	mg_send_header(conn, HEADERS_HASH_HEADER ,sha);
}
// heavily inspired my from mongoose mg_printf_data

size_t add_content(char **acc, int buffer_size, crypto_hash_sha256_state *state, const char *fmt, ...) {
  va_list ap;
  int len;
  // FIXME use only addition
  char addition_a[1024], *addition=addition_a;

  va_start(ap, fmt);
  len = ns_avprintf(&addition, strlen(addition), fmt, ap);
  va_end(ap);
  //check if new string fits in buffer
  // +1 : \0
  int new_size = strlen(*acc) + strlen(addition) + 1;
  if ( new_size > buffer_size) {
	  // if we grow, grow 4 times what's needed
	  buffer_size=new_size*4;
	  *acc = (char *) realloc(*acc, buffer_size);
	  if (*acc==NULL) {
		  return -1;
	  }
  }
  // append content to the accumulator
  strlcat(*acc,addition);
  // update body hash
  crypto_hash_sha256_update(state, addition, strlen(addition));
  return buffer_size;
}

// compute the body hash and send it in a header
void end_content(struct mg_connection * conn,crypto_hash_sha256_state *body_state, crypto_hash_sha256_state *headers_state) {
	// the sha256 result
	unsigned char out[crypto_hash_sha256_BYTES];
	// string representation of the sha256
	char *sha;

	// finalise sha computation and send the header
	crypto_hash_sha256_final(body_state, out);
	sha=malloc(sizeof(out)*2+1);
	sodium_bin2hex(sha, sizeof(out)*2+1, out, sizeof(out));

	set_header(conn, headers_state, BODY_HASH_HEADER,sha);
	printf("body sha : %s\n", sha);
	free(sha);
}

// send content, and write it to a local file.
// Will be improved later to save data per experiment
void send_content(struct mg_connection * conn,char *body) {
    	mg_printf_data(conn, "%s", body);
	FILE* f=fopen("/tmp/body","w");
	printf("size of body : %d\n",(int)strlen(body));
	fwrite(body,strlen(body),1,f);
	fclose(f);
}

void file_hash(char* path, char (*sha)[crypto_hash_sha256_BYTES*2+1]) {
	FILE *f;
	char buffer[1024];
	size_t read;

	f = fopen(path,"r");
	crypto_hash_sha256_state sha_state;
	crypto_hash_sha256_init(&sha_state);

	while((read = fread(buffer, 1, sizeof(buffer), f)) > 0 ){
		crypto_hash_sha256_update(&sha_state, buffer, read);
	}
	fclose(f);

	unsigned char out[crypto_hash_sha256_BYTES];
	crypto_hash_sha256_final(&sha_state, out);
	sodium_bin2hex(*sha, sizeof(out)*2+1, out, sizeof(out));

}

int event_handler(struct mg_connection *conn, enum mg_event ev) {
  int i,random;
  // QUESTION what about doing it with pointer?
  char new_uri[95];
  switch (ev) {
    case MG_AUTH: return MG_TRUE;
    case MG_REQUEST: 
		  
		  
	printf("start %s\n", conn->uri);
	// sha state for headers and body
	crypto_hash_sha256_state state, body_state;

	// we immediately initialise the body state
	crypto_hash_sha256_init(&body_state);
	crypto_hash_sha256_init(&state);
		  
		  
		  
	// needs to be in the switch statement, or segfaults
        // do not process requests for /cumulus.jpg, let the standard handler do it
        // hence serving file from filesystem
        if (!strcmp(conn->uri, "/files/cumulus.jpg")) {
		// +20 : header name + ": " + some reserve, in case we change the name
		mbd_deliver_file(conn, conn->uri, &state );
        	return MG_MORE;
        }
	//// If path starts with /files, serve file on disk
        //if (!strncmp(conn->uri, "/files", 6)) {
        //	return MG_FALSE;
	//}

	// requests to /random.jpg return a random image
        if (!strcmp(conn->uri, "/random.jpg")) {
		random=rand()%10;
		//snprintf(new_uri,sizeof(new_uri),"/files/cumulus_%d.jpg", random);
		
		conn->uri=new_uri;
		//printf("will return %s for client on port %d\n", conn->uri, conn->remote_port);
		mbd_deliver_file(conn, new_uri, &state );
        	return MG_MORE;
        }

	// initialises a body of length 4096
	//  will be expanded if needed in add_content
	char *body;
	body = (char *) malloc(4096);
	memset(body,0,4096);
	int buffer_size = 4096;

	// line added by mongoose. We might as wel look at a way to set it outself
	add_sha_headers_content(&state,"HTTP/1.1 200 OK\r\n");
	set_header(conn, &state, "X-TeSt","WiTnEsS");

	set_header(conn, &state, "X-NH-TEST","test control header");
	set_header(conn, &state, "X-NH-RETEST","test control header");

	buffer_size = add_content(&body, buffer_size, &body_state, "%s\n", "Welcome hehe!");
	buffer_size = add_content(&body, buffer_size, &body_state, "%s\n", mg_get_header(conn, "Host"));
	//printf("---Start of headers---\n");
        for (i = 0; i < conn->num_headers; i++){
	    buffer_size = add_content(&body, buffer_size, &body_state,  "%s : %s\n", conn->http_headers[i].name, conn->http_headers[i].value);
	}
	//printf("---End of headers---\n");
	buffer_size = add_content(&body, buffer_size, &body_state, "%s\n",  conn->remote_ip);
	buffer_size = add_content(&body, buffer_size, &body_state, "%d\n", conn->remote_port);
	buffer_size = add_content(&body, buffer_size, &body_state, "%zd\n", conn->content_len);
	buffer_size = add_content(&body, buffer_size, &body_state, "POST data : %s\n", strndup(conn->content, conn->content_len));
	buffer_size = add_content(&body, buffer_size, &body_state, "%s\n", "Bye hehe!");

	end_content(conn, &body_state, &state);
	// add the chunked encoding header set by mongoose
	add_sha_headers_content(&state, "Transfer-Encoding: chunked\r\n");
	end_hashed_headers(conn,&state);
	
	send_content(conn, body);
	free(body);







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
