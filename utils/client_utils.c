#include "mbd_utils.h"
#include "client_utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
// get the directory where this run's logs will be stored
void get_run_log_dir(config_setting_t *output_dir, char **run_path){
		get_base_dir(output_dir, run_path);

		char *run_id;
		get_run_id(&run_id);

		// append run_id as directory
		strncat(*run_path, "/", 1);
		strncat(*run_path, run_id, strlen(run_id));

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
FILE *log_file;

void setup_logging(config_setting_t *output_dir) {
	char *path;
	get_run_log_dir(output_dir, &path);
	mkpath(path);
	append_to_buffer(&path,"/");
	append_to_buffer(&path,"client.log");
	log_file=fopen(path, "w");
	strncpy(log_path, path, MAX_LOG_PATH_SIZE);
	free(path);
}

void close_logging() {
	fclose(log_file);
}


