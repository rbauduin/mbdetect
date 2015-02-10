#include "mbd_utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int is_control_header(char* contents) {
	return (strstr(contents,"X-NH-")!=NULL);
}


int is_headers_hash_control_header(char* contents) {
	return (strstr(contents,HEADERS_HASH_HEADER)!=NULL);
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
