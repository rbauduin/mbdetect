#include "mbd_utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sodium.h>

int is_control_header(const char* contents) {
	return (strstr(contents,"X-NH-")!=NULL);
}

// is contents the request line with our fantasy protocol?
int is_400_request_line(const char *contents){
	return !strncmp(contents, HANDLED_400_METHOD, strlen(HANDLED_400_METHOD));
}

// FIXME: use strncmp with length of header we are looking for
int is_headers_hash_control_header(const char* contents) {
	return (strstr(contents,HEADER_HEADERS_HASH)!=NULL);
}

// is the header to be included in the header's hash value?
int is_header_in_hash(const char *contents){
	return (!is_headers_hash_control_header(contents) &&
		!is_400_request_line(contents) &&
		strncmp(contents, IGNORE_PREFIX_HEADER_HASH, strlen(IGNORE_PREFIX_HEADER_HASH)));
}


int is_empty_line(const char *contents) {
	//return (strstr(contents,": ")==NULL);
	//return (strlen(contents)==0);
	return (strcmp(contents,"\r\n")==0);
}

int is_empty_header(const char *contents) {
	return (strstr(contents,": ")==NULL);
	//return (strlen(contents)==0);
	//return (strcmp(contents,"\r\n")==0);
}

int is_http_status_header(const char *contents) {
	return (strspn(contents,"HTTP/1.1")==8);
}

void sha_from_state(crypto_hash_sha256_state *state, char(* sha)[crypto_hash_sha256_BYTES*2+1]) {
	// the sha256 result
	unsigned char out[crypto_hash_sha256_BYTES];
	crypto_hash_sha256_final(state, out);
	sodium_bin2hex(*sha, sizeof(out)*2+1, out, sizeof(out));
}
void string_sha(char* string, char(* sha)[crypto_hash_sha256_BYTES*2+1]) {
  crypto_hash_sha256_state state; 
  crypto_hash_sha256_init(&state);
  crypto_hash_sha256_update(&state, string, strlen(string));
  sha_from_state(&state,sha);
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


// add a part to the computed sha headers
// used to add headers automatically set by mongoose
// and in the client to compute hash of headers set by curl
// for use only when we generate the content ourself
void add_sha_headers_content(crypto_hash_sha256_state *state, char* content){
	crypto_hash_sha256_update(state, content, strlen(content));
}

void build_header_line(char (*header_line)[MAX_HEADER_SIZE], const char *name, const char *value){
	memset(*header_line,0,sizeof(header_line));
	snprintf(*header_line, MAX_HEADER_SIZE,"%s: %s", name, value);  
}

void add_sha_headers_components(crypto_hash_sha256_state *received_headers_state, const char* name, const char *value){
	char header_line[MAX_HEADER_SIZE];
	build_header_line(&header_line, name, value);  
	add_sha_headers_content(received_headers_state,header_line);
}

// add a control header entry in the linked list
// added as new head of the list
control_header* control_headers_prepend(control_header* list, control_header* new) {
	// if list does not exist, this is the first entry
	if (list==NULL) {
		return new;
	}
	// prepend
	else{
		new->next = list;
		return new;
	}

}
void collect_control_header_components(control_header **headers, const char *n, const char *v){

	// we allocate memory for the fields and copy the values we receive
	// this way we know we always have to free fields when freeing the headers list
	char *name=(char *) malloc(strlen(n)+1);
	char *value=(char *) malloc(strlen(v)+1);
	strcpy(name, n);
	strcpy(value, v);

	control_header *header = (control_header *) malloc(sizeof(control_header));
	header->next = NULL;
	// FIXME : ok to get rid of const qualifier?
	header->name=name;
	header->value=value;
	*headers = control_headers_prepend(*headers, header);

}

int free_control_header(control_header *header) {
		if (header->name!=NULL)
			free(header->name);
		if (header->value!=NULL)
			free(header->value);
		return 0;
}

// free all memory allocated when we built the control_headers linked list
// free fields indicate if the name and value field have been allocated by us or not
// (yes in the client, no in the server)
int control_headers_free(control_header* list) {
	int i=0;
	control_header* previous_head;
	while (list!=NULL) {
		free_control_header(list);
		previous_head = list;
		list = list->next;
		free(previous_head);
		i++;
	};
	return i;
}


// extract header value from the headers list
void get_header_value(control_header* list, char* needle, char** result) {
	while (list!=NULL){
		if(!strcmp(list->name,needle)){
			*result=list->value;
			return;
		}
		list=list->next;
	}
	*result=NULL;
}

// append a string to an accumulator, growing the allocated memory if needed
int  append_to_buffer(char **acc, const char* addition){
  int buffer_size = sizeof(acc);
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
  strlcat(*acc,addition,new_size);
  return buffer_size;
}

// get id of the test passed as argument
const char * get_test_id(config_setting_t *test){
	config_setting_t *test_id_setting = config_setting_get_member(test, "id");
	if (test_id_setting == NULL) {
		fprintf(stderr, "The test has no id, this is required!\n");
		exit(1);
	}
	return config_setting_get_string(test_id_setting);

}


