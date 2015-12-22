//gcc -c  -lcares -fpic dns_tests.c
//gcc -shared -fpic -o libdns_tests.so dns_tests.o -lcares
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libconfig.h>
#include "utils/mbd_utils.h"
#include "utils/client_utils.h"
#include "utils/mbd_version.h"
#include "utils/slist.h"
// for c-ares
// requires libc-ares-dev
#include <ares.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
// end cares
////////////////////////////////////////////////////////////////////////////////
//                        C-ares test
////////////////////////////////////////////////////////////////////////////////



// structure holding information about one dns query.
// it has a link to the next query's information
typedef struct dns_queries_info_t {
	// c-ares status
	int status;
	// number of timeouts
	int timeouts;
	// domain name to resolve
	char domain[MAX_DOMAIN_SIZE];
	// list of ip addresses it resolves to
	struct slist * list;
	// file we write log to
	char log_path[MAX_LOG_PATH_SIZE];
	// file descriptor of log file
	FILE *fd;
	// link to next query_info
	struct dns_queries_info_t *next;
} dns_queries_info_t;

// mapping of dns queries validations
// - name of validation,
// - possible code, legacy from curl tests, but might become useful later. Use NONE to not use it.
// - validation function to call
typedef struct dns_validations_mapping{
	char *name;
	int  code;
	int (*f)(dns_queries_info_t *head, struct dns_validations_mapping m, config_setting_t * entry,  char **message);
} dns_validations_mapping;


// forward declarations
int dns_include(dns_queries_info_t *info, struct dns_validations_mapping m, config_setting_t * entry,  char **message);
int dns_result_code(dns_queries_info_t *info, struct dns_validations_mapping m, config_setting_t * entry,  char **message);


// dns validations mapping
dns_validations_mapping dns_validations_mappings[]={
	{"dns_include", NONE, dns_include}
	,{"dns_result_code", NONE, dns_result_code}
};

// check that the result code is what was expected
int dns_result_code(dns_queries_info_t *info, struct dns_validations_mapping m, config_setting_t * entry,  char **message){
	// message collector
	char iteration_message[VALIDATION_MESSAGE_LENGTH];

	// expected value
	config_setting_t *value_entry = config_setting_get_member(entry, "value");
	if (value_entry == NULL) {
		printf("value entry not found in validation\n");
		return -1;
	}
	const char *value_str = config_setting_get_string(value_entry);

	// map expected value string to its constant value
	mapping code_mapping;
	find_mapping(value_str, &code_mapping);
	// traverse all query_infos linked list to check each query resulted in the expected value
	while (info!=NULL){
		if (info->status == code_mapping.code) {
			sprintf(iteration_message, KGRN "Success expected return code %d\n" KNON, info->status);
			append_to_buffer(message, iteration_message);
		}
		else {
			sprintf(iteration_message, KRED "Failure, unexpected return code:\n" KNON);
			append_to_buffer(message, iteration_message);

			switch(info->status){
				case ARES_ENOTIMP:
					sprintf(iteration_message, KRED "ARES_ENOTIMP: type famlily not recognised\n" KNON);
					append_to_buffer(message, iteration_message);
					break;
				case ARES_EBADNAME:
					sprintf(iteration_message, KRED "ARES_EBADNAME: name is not valid internet address\n" KNON);
					append_to_buffer(message, iteration_message);
					break;
				case ARES_ENOTFOUND:
					sprintf(iteration_message, KRED "ARES_ENOTFOUND: name not found\n" KNON);
					append_to_buffer(message, iteration_message);
					break;
				case ARES_ENOMEM:
					sprintf(iteration_message, KRED "ARES_ENOMEM: memory exhausted\n" KNON);
					append_to_buffer(message, iteration_message);
					break;
				case ARES_ECANCELLED:
					sprintf(iteration_message, KRED "ARES_ECANCELLED: query was cancelled\n" KNON);
					append_to_buffer(message, iteration_message);
					break;
				case ARES_EDESTRUCTION:
					sprintf(iteration_message, KRED "ARES_EDESTRUCTION: ares channel destroyed, query cancelled\n" KNON);
					append_to_buffer(message, iteration_message);
					break;
				case ARES_EBADQUERY:
					sprintf(iteration_message, KRED "ARES_EBADQUERY\n" KNON);
					append_to_buffer(message, iteration_message);
					break;
				case ARES_ECONNREFUSED:
					sprintf(iteration_message, KRED "ARES_ECONNREFUSED\n" KNON);
					append_to_buffer(message, iteration_message);
					break;
				case ARES_EBADFAMILY:
					sprintf(iteration_message, KRED "ARES_EBADFAMILY\n" KNON);
					append_to_buffer(message, iteration_message);
					break;
				case ARES_EBADRESP:
					sprintf(iteration_message, KRED "ARES_EBADRESP\n" KNON);
					append_to_buffer(message, iteration_message);
					break;
				case ARES_ETIMEOUT:
					sprintf(iteration_message, KRED "ARES_ETIMEOUT\n" KNON);
					append_to_buffer(message, iteration_message);
					break;
				case ARES_EBADSTR:
					sprintf(iteration_message, KRED "ARES_EBADSTR\n" KNON);
					append_to_buffer(message, iteration_message);
					break;

			}

		}
		info = info->next;
	}
}

// Check that the domain resolution contains one or multiple ips,
// hence value in config file may be a string or a list of strings.
int dns_include(dns_queries_info_t *info, struct dns_validations_mapping m, config_setting_t * entry,  char **message){
	char iteration_message[VALIDATION_MESSAGE_LENGTH];
	// value to look for
	config_setting_t *value_entry = config_setting_get_member(entry, "value");
	if (value_entry == NULL) {
		printf("value entry not found in validation\n");
		return -1;
	}
	const char *value_str=NULL;
	int queries_count, i;

	// traverse whole query_info linked list
	while (info!=NULL){
		switch(value_entry->type)
		{ 
			// if string, use the value itself
			case CONFIG_TYPE_STRING:
				value_str = config_setting_get_string(value_entry);
				if (slist_any_str(info->list, value_str)) {
					sprintf(iteration_message, KGRN "Success, found ip %s\n" KNON, value_str);
					append_to_buffer(message, iteration_message);
					return 1;
				}
				else {
					sprintf(iteration_message, KRED "Failure, did not find ip %s\n" KNON, value_str);
					append_to_buffer(message, iteration_message);
					return 0;
				}
			// if list, check each list member
			case CONFIG_TYPE_LIST:
				queries_count = config_setting_length(value_entry);
				for (i=0; i<queries_count; i++){
					value_str = config_setting_get_string_elem(value_entry, i);
					if (!slist_any_str(info->list, value_str)) {
						sprintf(iteration_message, KRED "Failure, did not find ip %s\n" KNON, value_str);
						append_to_buffer(message, iteration_message);
						return 0;
					}
					else {
						sprintf(iteration_message, KGRN "Success, found ip %s\n" KNON, value_str);
						append_to_buffer(message, iteration_message);
					}
				}
				return 1;
		}
		// go to next query_info in linked list
		info = info->next;
	}
}

int dns_validations_mappings_len = sizeof(dns_validations_mappings)/sizeof(dns_validations_mappings[0]);

// find a mapping options as string -> option symbol
int find_dns_validation_mapping(const char* validation, dns_validations_mapping *m) {
	int i=0;
	while (i<dns_validations_mappings_len && strcmp(dns_validations_mappings[i].name, validation)) {
		i++;
	}
	if (i<dns_validations_mappings_len) {
		*m = dns_validations_mappings[i];
		return 0;
	}
	else {
		printf("Validation %s not handled by this code\n", validation);
		return -1;
	}

}


// perform all validations after queries have been done
int perform_dns_validation(dns_queries_info_t *queries_info,config_setting_t* entry, char **message) {
	// value to return
	int res;
	
	// actual value we got in this run
	validation_value_t actual;

	// value entry from the config file. 
	// value_entry->value contains the union typed value we need to compare to expected value
	config_setting_t *value_entry = config_setting_get_member(entry, "value");

	// name entry from the config file, and its string value.
	// Its value is the name of the option passed to curl_easy_getinfo, which we get from the mappings
	config_setting_t *name_entry = config_setting_get_member(entry, "name");
	const char * name_str=config_setting_get_string(name_entry);
	// mapping of the option name to its value
	dns_validations_mapping m;
	int mapping_found = find_dns_validation_mapping(name_str,&m);
	if (mapping_found) {
		printf("ERROR, no validation mapping found for %s!\n", name_str);
		exit(1);
	}

	// call the mapping's function
	res = m.f(queries_info, m, entry, message);
	return res;
}

// utility ares function, waiting for asynchronous code to terminate
static void
wait_ares(ares_channel channel)
{
	for(;;){
		struct timeval *tvp, tv;
		fd_set read_fds, write_fds;
		int nfds;

		FD_ZERO(&read_fds);
		FD_ZERO(&write_fds);
		nfds = ares_fds(channel, &read_fds, &write_fds);
		if(nfds == 0){
			break;
		}
		tvp = ares_timeout(channel, NULL, &tv);
		select(nfds, &read_fds, &write_fds, NULL, tvp);
		ares_process(channel, &read_fds, &write_fds);
	}
}

// C-ares callback.
// - arg is the user provided argument, we pass a dns_query_info_t structure
//   holding the hostname and file descriptor to log to
static void
callback(void *arg, int status, int timeouts, struct hostent *host)
{
	dns_queries_info_t *query_info = (dns_queries_info_t *) arg;

	// if host is NULL, resolution failed. We lookup name in query_info then
	fprintf( query_info->fd, "Resolution of %s\n", query_info->domain);
	if (host!=NULL) {
		fprintf( query_info->fd, "Effective host: %s\n", host->h_name);
	} 
	fprintf( query_info->fd, "Status: %d\n", status);
	fprintf( query_info->fd, "Timeouts: %d\n", timeouts);

	// save info for validations
	query_info->status = status;
	query_info->timeouts = timeouts;

	// stop here if resolution failed
	if(!host || status != ARES_SUCCESS){
		fprintf(query_info->fd, "Failed to lookup: %s\n", ares_strerror(status));
		return;
	}

	// if resolution successful, log addresses and collect them in query_info
	fprintf(query_info->fd, "Domain resolved:\n");

	char ip[INET6_ADDRSTRLEN];
	int i = 0;
	slist *ips = query_info->list;

	for (i = 0; host->h_addr_list[i]!=NULL; ++i) {
		inet_ntop(host->h_addrtype, host->h_addr_list[i], ip, sizeof(ip));
		fprintf(query_info->fd, "%s\n", ip);
		slist_append(ips, ip);
	}
	query_info->list = ips;

}

// builds the log path, and puts info in query_info
void set_dns_output(dns_queries_info_t *query_info, config_setting_t *output_dir, config_setting_t *test, int repeat, const char *suffix) {
	char *log_path;
	char *base_path;
	const char *test_id = get_test_id(test);

	// build the directory path
	get_run_log_dir(output_dir, &base_path);

	//this is the run specific log dir, create it if needed 
	mkpath(base_path);

	// All logs of dns tests go the the same file, even in case of repetitions
	char *full_suffix;
	build_suffix(&full_suffix, suffix, ".dns");
	build_log_file_path(base_path, test_id, 0, NULL, full_suffix, &log_path);
	free(full_suffix);

	// put info in query_info
	strncpy(query_info->log_path, log_path, MAX_LOG_PATH_SIZE);
	query_info->fd = fopen(log_path, "a");

}

void clean_dns_output(config_setting_t *test, dns_queries_info_t *query_info){
	fclose(query_info->fd);
}

// run a dns test as defined in the config file.
// Issues all queries and possible repetitions
void run_lib_test(config_setting_t *test, config_setting_t *output_dir, const char *suffix) {

	ares_channel channel;
	int status;
	struct ares_options options;
	int optmask = 0;

	// init c-ares
	status = ares_library_init(ARES_LIB_INIT_ALL);
	if (status != ARES_SUCCESS){
		printf("ares_library_init: %s\n", ares_strerror(status));
		return;
	}

	// get queries for this test
	config_setting_t *queries = config_setting_get_member(test, "queries");
	int queries_count = config_setting_length(queries);

	// index variable and message collector
	int k;
	char *message = malloc(VALIDATION_MESSAGE_LENGTH);
	
	// iterate on queries
	for(k=0;k<queries_count;k++){
		    // get query of this iteration
		    config_setting_t *query = config_setting_get_elem(queries, k);

		    // determine repetitions
		    config_setting_t *repeat_setting = config_setting_get_member(query, "repeat");
		    int repeat_query;
		    if (repeat_setting!=NULL) {
			    repeat_query = config_setting_get_int(repeat_setting);
		    }
		    else {
			    repeat_query = 1;
		    }

		    // get hostname to resolve
		    config_setting_t *host_setting = config_setting_get_member(query, "host");
		    const char *host = config_setting_get_string(host_setting);

		    // define the query_info linked list, initially empty
		    dns_queries_info_t *queries_info=NULL;
		    dns_queries_info_t *current_query_info=queries_info;

		    // set flags
		    config_setting_t *flags_setting = config_setting_get_member(query, "flags");
		    int flags_count;
		    int j;
		    const char *flag;
		    int mapping_found;
		    // reset options for this query
		    options.flags = 0;
		    if (flags_setting!=NULL) {
			    // flags is a list of strings we need to map to an c-ares flag
			    flags_count = config_setting_length(flags_setting);
			    for (j=0; j<flags_count; j++){
				    flag=config_setting_get_string_elem(flags_setting,j);
				    mapping m;
				    mapping_found = find_mapping(flag,&m);
				    if (!mapping_found) {
					    options.flags = options.flags||m.code;
				    }
			    }
		    }
		    // to have a callback when the socket changes state:
		    //	optmask |= ARES_OPT_SOCK_STATE_CB;
		    optmask |= ARES_OPT_FLAGS;

		    // set options
		    status = ares_init_options(&channel, &options, optmask);
		    if(status != ARES_SUCCESS) {
			    client_log(KRED "problem ares_init_options: %s\n" KNON, ares_strerror(status));
			    return;
		    }

		    // repetition index variable
		    int l;

		    
		    // issue repetitions
		    for(l=0; l<repeat_query; l++) {
			    if (queries_info==NULL) {
				    // first query, initialise
				    current_query_info = (dns_queries_info_t *)malloc(sizeof(dns_queries_info_t));
				    queries_info = current_query_info;
			    }
			    else {
				    // subsequent query, append
				    current_query_info->next= (dns_queries_info_t *)malloc(sizeof(dns_queries_info_t));
				    current_query_info=current_query_info->next;
			    }

			    // setup this query's query_info
			    slist *ips;
			    slist_init(&ips);
			    current_query_info->list = ips;
			    current_query_info->status = -1;
			    current_query_info->fd = NULL;
			    current_query_info->next = NULL;
			    strncpy(current_query_info->domain, host, MAX_DOMAIN_SIZE);

			    // setup logs
			    set_dns_output(current_query_info, output_dir, test, l, suffix);

			    // issue request
			    ares_gethostbyname(channel, host, AF_INET, callback, current_query_info);
			    // ipv6:
			    //ares_gethostbyname(channel, "google.com", AF_INET6, callback, NULL);

			    // wait for asynchronous code to terminate
			    wait_ares(channel);

			    // cleanup 
			    clean_dns_output(test, current_query_info);
		    }

		    // all logs of dns tests are placed in one file,
		    // we get its name from the last query info
		    // we disable mptcp for this
		    int ori_mptcp = disable_mptcp();
		    upload_log(current_query_info->log_path);
		    set_mptcp(ori_mptcp);

		    // perform validations
		    config_setting_t *validations = config_setting_get_member(query, "validations");
		    if (validations != NULL) {
			    //printf("Performing validations\n");
			    int validations_count = config_setting_length(validations);
			    // iterate over validation of this query
			    int m;
			    for(m=0;m<validations_count;m++){
				    config_setting_t *validation = config_setting_get_elem(validations, m);
				    // wipe message from previous validation
				    memset(message,0,sizeof(message));
				    perform_dns_validation(queries_info, validation, &message);
				    client_log("%s",message);

			    }
		    }
		    // FIXME: free this for each element in queries_info
		    //slist_free(query_info->list);
		    ares_destroy(channel);
	}
	ares_library_cleanup();
}


void init_options() {
	mapping additions[]= {{"ARES_SUCCESS", ARES_SUCCESS, "int", NULL},
		{"ARES_ENOTFOUND", ARES_ENOTFOUND, "int", NULL},
		{"ARES_FLAG_USEVC", ARES_FLAG_USEVC, "int", NULL}
	};
	append_mappings(additions, sizeof(additions)/sizeof(additions[0])); 
}

/////////////////////// end C-ares test ////////////////////////////////////////

