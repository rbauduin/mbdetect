#include <sodium.h>
#define HEADERS_HASH_HEADER "X-NH-H-SHA256"
#define BODY_HASH_HEADER "X-NH-D-SHA256"
#define VALIDATION_MESSAGE_LENGTH 2048

// useful to append to mystring with snprintf(eos(mystring), size-strlen(mystring), fmt, ...)
#define eos(s) ((s)+strlen(s))
int is_control_header(char* contents);
void sha_from_state(crypto_hash_sha256_state *state, char(* sha)[crypto_hash_sha256_BYTES*2+1]);
void string_sha(char* string, char(* sha)[crypto_hash_sha256_BYTES*2+1]); 
void file_hash(char* path, char (*sha)[crypto_hash_sha256_BYTES*2+1]);
