#include<stdio.h>
#include <sys/types.h>
#include<sys/socket.h>
#include <netdb.h>    // for addrinfo
#include<arpa/inet.h> // for inet_addr
#include <string.h>   // for memset
#include <stdlib.h>   // for exit()


char *build_get_query(char* path, char* protocol,char* host){
	// template used to build the query 
	char *tpl= "GET %s %s\r\nHost: %s\r\n\r\n";
	// length of the query string
	int query_len;
	// the query string itself
	char* query;
	// -6 to account for %s in template
	query_len= strlen(tpl)-6+strlen(host)+strlen(path)+strlen(protocol);
	// allocate memory and clean it
	query = (char *)malloc(query_len);
	memset(query, 0, query_len);

	// build query from template and return it
	sprintf(query, tpl, path, protocol, host);
	return query;
}

int send_query(int sockfd, char* query, char* response) {
	int sent=0, write_res, size=strlen(query), res;

	while (sent<strlen(query)){
		res = write(sockfd, query+sent, size-sent, 0);
		if (res == -1) {
			printf("Can't write\n");
			return -1;
		}
		sent+=res;
	}
	return sent;
}

int print_response(int sockfd){
	int bufsize=1024, read, total_read=0;
	char buf[bufsize];
	memset(buf, 0, bufsize);

	while ( read =recv(sockfd, buf, bufsize, 0)> 0){
		printf("%s",buf);
		memset(buf, 0, read);
		total_read+=read;
	}
}

int main(void){
	// rv: getaddrinfo result code
	int sockfd, portno, rv;
	struct sockaddr_in server;
	struct hostent *host;

	// hints: indicate which type of resolution we want
	// servinfo: info received from getaddrinfo call
	// p : used in loop
	struct addrinfo hints, *servinfo, *p;

	// GET query and response
	char* query, *response;
	int res;

	// clean memory
	memset(&hints, 0, sizeof hints);

	// fill in hints
	hints.ai_family = AF_UNSPEC; // AF_INET6 forces IPv6
	hints.ai_socktype = SOCK_STREAM;



	// host resolution
	if ((rv = getaddrinfo("localhost", "8080", &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		exit(1);
	}

	for(p = servinfo; p != NULL; p = p->ai_next) {
		// create socket
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
						p->ai_protocol)) == -1) {
			perror("socket");
			continue;
		}

		// connect
		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("connect");
			continue;
		}

		break; // if we get here, we must have connected successfully
	}

	freeaddrinfo(servinfo); 

	if (p == NULL) {
		// looped off the end of the list with no connection
		fprintf(stderr, "failed to connect\n");
		exit(2);
	}


	puts("Connected");
	query = build_get_query("/","SICS/1.0","localhost");
	printf("\nreceived query: \n%s\n", query);
	res = send_query(sockfd, query, response);
	if ( res == strlen(query) ) {
		// query sent in full, read response
		printf("Sent %d bytes\n", res);
		print_response(sockfd);
	}

	free(query);


	return 0;

}
