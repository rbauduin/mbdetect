#include "utils/mongoose.h"
#include "string.h"
#include <stdarg.h>
#include <time.h>
#include <stdlib.h>
#include <sodium.h>
#include "utils/mbd_utils.h"
#include <sys/stat.h>
#include "utils/mongoose.h"


// set a header line, only for content we generate ourself, not for use when serving files!
int set_header_line(char **acc, int buffer_size, crypto_hash_sha256_state *state, char *addition) {
	int new_buffer_size = append_to_buffer(acc, buffer_size, addition);
	int header_len=strlen(addition);

	// if this is not a control header, add it to the headers hash computation
	if (! is_headers_hash_control_header(addition)) {
		crypto_hash_sha256_update(state, addition, header_len);
	}
	return new_buffer_size;
}

// set a header, only for content we generate ourself, not for use when serving files!
int set_header(char **acc, int buffer_size, crypto_hash_sha256_state *state, char *name, char *value) {
	char *header;
	int header_len, new_buffer_size;
	//mg_send_header(conn, name,value);
	char addition[MAX_HEADER_SIZE];
	snprintf(addition, MAX_HEADER_SIZE, "%s: %s\r\n", name, value);
	return set_header_line(acc, buffer_size, state, addition);
}

// add the chunked encoding header to the sha computation 
// and send the sha256 value as a last header
// for use only when we generate the content ourself
int end_hashed_headers(char **acc, int buffer_size, crypto_hash_sha256_state *state) {
	// string representation of the sha256
	char sha[crypto_hash_sha256_BYTES*2+1];
	// finalise sha computation and send the header
	sha_from_state(state,&sha);
	return set_header(acc, buffer_size, state, HEADER_HEADERS_HASH ,sha);
}


// append a string to an accumulator, growing the allocated memory if needed
int  append_to_buffer(char **acc, int buffer_size, char* addition){
  int new_size = strlen(*acc) + strlen(addition) + 1;
  //check if new string fits in buffer
  // +1 : \0
  if ( new_size > buffer_size) {
	  // if we grow, grow 2 times what's needed
	  buffer_size=new_size*2;
	  *acc = (char *) realloc(*acc, buffer_size);
	  if (*acc==NULL) {
		  return -1;
	  }
  }
  // append content to the accumulator
  strlcat(*acc,addition);
  return buffer_size;
}

// heavily inspired by mongoose mg_printf_data
size_t add_content(char **acc, int buffer_size, crypto_hash_sha256_state *state, const char *fmt, ...) {
  va_list ap;
  int len;
  // FIXME use only addition
  char addition_a[1024], *addition=addition_a;

  va_start(ap, fmt);
  len = ns_avprintf(&addition, strlen(addition), fmt, ap);
  va_end(ap);
  buffer_size = append_to_buffer(acc, buffer_size,  addition);
  // update body hash
  crypto_hash_sha256_update(state, addition, strlen(addition));
  return buffer_size;
}

// compute the body hash and send it in a header
void end_content(char **headers,int headers_buffer_size, crypto_hash_sha256_state *body_state, crypto_hash_sha256_state *headers_state) {
	// the sha256 result
	unsigned char out[crypto_hash_sha256_BYTES];
	// string representation of the sha256
	char *sha;

	// finalise sha computation and send the header
	crypto_hash_sha256_final(body_state, out);
	sha=malloc(sizeof(out)*2+1);
	sodium_bin2hex(sha, sizeof(out)*2+1, out, sizeof(out));

	set_header(headers, headers_buffer_size, headers_state, HEADER_BODY_HASH,sha);
	free(sha);
}

int setup_buffer(char **b) {
	// initialises a body of length 4096
	//  will be expanded if needed in add_content
	//  memory is freed after is it sent out to the client
	*b = (char *) malloc(4096);
	memset(*b,0,4096);
	return 4096;
}

void generate_content(struct mg_connection *conn, char** headers, char** body) {
	// loop index
	int i;
	// sha state for headers and body
	crypto_hash_sha256_state headers_state, body_state;

	// we immediately initialise the body state
	crypto_hash_sha256_init(&body_state);
	crypto_hash_sha256_init(&headers_state);

	// initialise buffers
	int buffer_size = setup_buffer(body);
	int headers_buffer_size = setup_buffer(headers);

	// set headers
	headers_buffer_size = set_header_line(headers, headers_buffer_size, &headers_state, "HTTP/1.1 200 OK\r\n");
	headers_buffer_size = set_header(headers, headers_buffer_size, &headers_state, "X-TeSt","WiTnEsS");
	headers_buffer_size = set_header(headers, headers_buffer_size, &headers_state, "X-H-TEST","test control header");
	headers_buffer_size = set_header(headers, headers_buffer_size, &headers_state, "X-H-RETEST","test control header");
	headers_buffer_size = set_header_line(headers, headers_buffer_size, &headers_state, "Transfer-Encoding: chunked\r\n");

	// Check received headers
	char received_headers_sha[crypto_hash_sha256_BYTES*2+1];
	control_header *received_headers=NULL;
	// collect headers and compute the sha
	handle_received_headers(conn, &received_headers,&received_headers_sha); 

	// Check headers hash and add the header indicating if we received the client's headers unmodified 
	char ok[2];
	snprintf((char *)&ok,2,"%d", validate_headers_sha(received_headers_sha, received_headers));
	headers_buffer_size = set_header(headers, headers_buffer_size, &headers_state, HEADER_SERVER_RCVD_HEADERS, ok  );


	// add content to body
	buffer_size = add_content(body, buffer_size, &body_state, "%s\n", "Welcome hehe!");
	buffer_size = add_content(body, buffer_size, &body_state, "%s\n", mg_get_header(conn, "Host"));
	buffer_size = add_content(body, buffer_size, &body_state, "%s\n",  conn->remote_ip);
	buffer_size = add_content(body, buffer_size, &body_state, "%d\n", conn->remote_port);
	buffer_size = add_content(body, buffer_size, &body_state, "%zd\n", conn->content_len);
	buffer_size = add_content(body, buffer_size, &body_state, "POST data : %s\n", strndup(conn->content, conn->content_len));
	buffer_size = add_content(body, buffer_size, &body_state, "%s\n", "Bye hehe!");

	// add the body hash to the headers
	end_content(headers, headers_buffer_size, &body_state, &headers_state);
	// add the headers containing the sha of the other headers
	end_hashed_headers(headers, headers_buffer_size,&headers_state);

	// cleanup
	control_headers_free(received_headers);

}


int event_handler(struct mg_connection *conn, enum mg_event ev) {
  int i,random;
  // QUESTION what about doing it with pointer?
  char new_uri[95];
  switch (ev) {
    case MG_AUTH: return MG_TRUE;
    case MG_REQUEST: 
		  
		  
	// needs to be in the switch statement, or segfaults
        // do not process requests for /cumulus.jpg, let the standard handler do it
        // hence serving file from filesystem
        if (!strcmp(conn->uri, "/files/cumulus.jpg")) {
		// +20 : header name + ": " + some reserve, in case we change the name
		mbd_deliver_file(conn );
        	return MG_MORE;
        }

	// requests to /random.jpg return a random image
        if (!strcmp(conn->uri, "/random.jpg")) {
		random=rand()%10;
		snprintf(new_uri,sizeof(new_uri),"/files/cumulus_%d.jpg", random);
		
		conn->uri=new_uri;
		//printf("will return %s for client on port %d\n", conn->uri, conn->remote_port);
		mbd_deliver_file(conn );
        	return MG_MORE;
        }
	
	// If we get here, wee need to generate content ourself
        if (!strcmp(conn->uri, "/")) {
		char *body, *headers;
		generate_content(conn, &headers, &body);
		send_response(conn, headers, body);
		return MG_TRUE;
	}

	send_error_with_hash(conn, 404);
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
