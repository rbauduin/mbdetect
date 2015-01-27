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
	
	// char array to hold testual representation of ip address
	char ipstr[INET6_ADDRSTRLEN];

	// clean memory
	memset(&hints, 0, sizeof hints);

	// fill in hints
	hints.ai_family = AF_UNSPEC; // AF_INET6 forces IPv6
	hints.ai_socktype = SOCK_STREAM;



	// host resolution
	if ((rv = getaddrinfo("www.google.com", NULL, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		exit(1);
	}

	for(p = servinfo; p != NULL; p = p->ai_next) {
		void *addr;
		char *ipver;
		
		// get the pointer to the address itself,
		// different fields in IPv4 and IPv6:
		if (p->ai_family == AF_INET) { // IPv4
		    struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
		    addr = &(ipv4->sin_addr);
		    ipver = "IPv4";
		} else { // IPv6
		    struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
		    addr = &(ipv6->sin6_addr);
		    ipver = "IPv6";
		}
		
		// convert the IP to a string and print it:
		inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
		printf("  %s: %s\n", ipver, ipstr);
	}

	freeaddrinfo(servinfo); 
	return 0;

}
