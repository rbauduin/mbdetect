#include<stdio.h>
#include <sys/types.h>
#include<sys/socket.h>
#include <netdb.h>    // for addrinfo
#include<arpa/inet.h> // for inet_addr
#include <string.h>   // for memset
#include <stdlib.h>   // for exit()


int main(void){
	// rv: getaddrinfo result code
	int sockfd, portno, rv;
	struct sockaddr_in server;
	struct hostent *host;

	// hints: indicate which type of resolution we want
	// servinfo: info received from getaddrinfo call
	// p : used in loop
	struct addrinfo hints, *servinfo, *p;

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
	return 0;

}
