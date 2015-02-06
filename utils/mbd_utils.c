#include "mbd_utils.h"
#include <stdlib.h>
#include <string.h>
int is_control_header(char* contents) {
	return (strstr(contents,"X-NH-")!=NULL);
}


