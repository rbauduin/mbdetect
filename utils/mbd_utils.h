#include <sodium.h>
#include <libconfig.h>
#define HEADER_HEADERS_HASH "X-NH-H-SHA256"
#define HEADER_BODY_HASH "X-NH-D-SHA256"
#define VALIDATION_MESSAGE_LENGTH 2048
#define HEADER_SERVER_RCVD_HEADERS "X-H-HDRRCVOK"
#define MAX_HEADER_NAME_SIZE 512
#define MAX_HEADER_VALUE_SIZE 512
#define MAX_HEADER_SIZE 1024
#define NOT_FOUND_BODY "File not found. This is a test server only, with not content available." 
#define NO_MATCH 0
#define MATCH 1
#define HEADER_NOT_FOUND -1
#define NULL_OPERANDS	-2
#define HANDLED_400_METHOD "x20bliptupbam"
#define QUERY_INFO_FIELD_NUMBER 4
// headers starting with this string are ignored the headers hash computation
// currently only used for the fantasy HTTP method GIVE
#define IGNORE_PREFIX_HEADER_HASH "GIVE"
// useful to append to mystring with snprintf(eos(mystring), size-strlen(mystring), fmt, ...)
#define eos(s) ((s)+strlen(s))
#define min(a,b) a<b ? a : b
#define max(a,b) a>b ? a : b


// Colors in terminal
#define KNON  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

// store  headers of the request in a chained list
typedef struct control_header {
	char *name;
	char* value;
	struct control_header* next;
} control_header;



// structure keeping where we write
typedef struct write_dest {
	// file descriptor curl writes the payload to
	FILE *fd;
	// used by curl to keep trace of what was already written
	size_t size;
	// path to save payload to
	char *path;
	// payload type, D for body, H for headers 
	char type; 
	crypto_hash_sha256_state sha_state;
	char sha[2*crypto_hash_sha256_BYTES+1];
	// FIXME: this is only for headers, and will never happen for body. Should we have 2 distinct struct? 
	// // however, this has an impact on the rest of the code, with the type of arguments changed....
	// hash of body sent by server
	control_header* control_headers;
} payload_specs;

typedef union query_info_field {
	int ival;
	long long llval;
	float fval;
	char *sval;
	double dval;
} query_info_field;

typedef struct queries_info_t {
	payload_specs *headers_specs;
	payload_specs *body_specs;
	query_info_field info[QUERY_INFO_FIELD_NUMBER];
	struct queries_info_t *next;
} queries_info_t;


// !!!!!!!!!!!!!!!!!!!
// When adding a field,
// remember to increase QUERY_INFO_FIELD_NUMBER above in mbd-utils.h 
typedef enum validation_fields {
	RESPONSE_CODE,
	SIZE_DOWNLOAD,
	NUM_CONNECTS,
	LOCAL_PORT,
	NONE
} validation_fields;

typedef struct validations_mapping{
	char *name;
	int  code;
	int (*f)(queries_info_t *head, struct validations_mapping m, config_setting_t * entry,  char **message);
} validations_mapping;

int is_control_header(const char* contents);
void sha_from_state(crypto_hash_sha256_state *state, char(* sha)[crypto_hash_sha256_BYTES*2+1]);
void string_sha(char* string, char(* sha)[crypto_hash_sha256_BYTES*2+1]); 
void file_hash(char* path, char (*sha)[crypto_hash_sha256_BYTES*2+1]);
control_header* control_headers_prepend(control_header* list, control_header* new);
int free_control_header(control_header *header);
int control_headers_free(control_header* list) ;
void get_header_value(control_header* list, char* needle, char** result); 
void add_sha_headers_components(crypto_hash_sha256_state *received_headers_state, const char* name, const char *value);
void collect_control_header_components(control_header **headers, const char *name, const char *value);
int is_header_in_hash(const char* contents);
int  append_to_buffer(char **acc, char* addition);
