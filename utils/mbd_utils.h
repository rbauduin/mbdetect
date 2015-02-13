#include <sodium.h>
#define HEADER_HEADERS_HASH "X-NH-H-SHA256"
#define HEADER_BODY_HASH "X-NH-D-SHA256"
#define VALIDATION_MESSAGE_LENGTH 2048
#define HEADER_SERVER_RCVD_HEADERS "X-H-HDRRCVOK"

// useful to append to mystring with snprintf(eos(mystring), size-strlen(mystring), fmt, ...)
#define eos(s) ((s)+strlen(s))
#define min(a,b) a<b ? a : b



// store  headers sent by server in a chained list
// their name start with X-NH- (NH for not included in hash)
typedef struct control_header {
	char *name;
	char* value;
	struct control_header* next;
} control_header;



int is_control_header(char* contents);
void sha_from_state(crypto_hash_sha256_state *state, char(* sha)[crypto_hash_sha256_BYTES*2+1]);
void string_sha(char* string, char(* sha)[crypto_hash_sha256_BYTES*2+1]); 
void file_hash(char* path, char (*sha)[crypto_hash_sha256_BYTES*2+1]);
control_header* control_headers_prepend(control_header* list, control_header* new);
int free_control_header(control_header *header);
int control_headers_free(control_header* list, int free_fields) ;
void get_header_value(control_header* list, char* needle, char** result); 
void add_sha_headers_components(crypto_hash_sha256_state *received_headers_state, const char* name, const char *value);
void collect_control_header_components(control_header **headers, const char *name, const char *value);
