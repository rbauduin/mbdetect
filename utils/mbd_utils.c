#include "mbd_utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sodium.h>
int is_control_header(char* contents) {
	return (strstr(contents,"X-NH-")!=NULL);
}


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
