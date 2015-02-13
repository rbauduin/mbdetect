#include "mbd_utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sodium.h>
int is_control_header(char* contents) {
	return (strstr(contents,"X-NH-")!=NULL);
}

// FIXME: use strncmp with length of header we are looking for
int is_headers_hash_control_header(char* contents) {
	return (strstr(contents,HEADER_HEADERS_HASH)!=NULL);
}

int is_empty_line(char *contents) {
	//return (strstr(contents,": ")==NULL);
	//return (strlen(contents)==0);
	return (strcmp(contents,"\r\n")==0);
}

int is_empty_header(char *contents) {
	return (strstr(contents,": ")==NULL);
	//return (strlen(contents)==0);
	//return (strcmp(contents,"\r\n")==0);
}

int is_http_status_header(char *contents) {
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

void add_sha_headers_components(crypto_hash_sha256_state *received_headers_state, const char* name, const char *value){
	char header_line[1024];
	memset(header_line,0,sizeof(header_line));
	snprintf(header_line, 1024,"%s: %s", name, value);  
	add_sha_headers_content(received_headers_state,header_line);
	printf("added to hash: %s\n",header_line);
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
void collect_control_header_components(control_header **headers, const char *name, const char *value){
	control_header *header = (control_header *) malloc(sizeof(control_header));
	header->next = NULL;
	// FIXME : ok to get rid of const qualifier?
	header->name=(char *)name;
	header->value=(char *)value;
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
int control_headers_free(control_header* list, int free_fields) {
	int i=0;
	control_header* previous_head;
	while (list!=NULL) {
		if (free_fields) {
			free_control_header(list);
		}
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
	result=NULL;
}

