/*
 * This code will query a ntp server for the local time and display
 * it.  it is intended to show how to use a NTP server as a time
 * source for a simple network connected device.
 * This is the C version.  The orignal was in Perl
 *
 * For better clock management see the offical NTP info at:
 * http://www.eecis.udel.edu/~ntp/
 *
 * written by Tim Hogard (thogard@abnormal.com)
 * Thu Sep 26 13:35:41 EAST 2002
 * Converted to C Fri Feb 21 21:42:49 EAST 2003
 * this code is in the public domain.
 * it can be found here http://www.abnormal.com/~thogard/ntp/
 *
 */

// modified by Raphaël Bauduin
// Another good example (under GPL)  is http://ftp.ics.uci.edu/pub/centos0/ics-custom-build/BUILD/nagios-plugins-1.4.13/plugins/check_ntp.c

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

main() {
	ntpdate();
}

ntpdate() {
char	*hostname="81.83.19.45";
int	portno=123;		//NTP is port 123
int	maxlen=1024;		//check our buffers
int	i;			// misc var i
unsigned char msg[48]={010,0,0,0,0,0,0,0,0};	// the packet we send
unsigned long long  buf[maxlen];	// the buffer we get back
//struct in_addr ipaddr;		//	
struct protoent *proto;		//
struct sockaddr_in server_addr;
int	s;	// socket
int	tmit;	// the time -- This is a time_t sort of

//use Socket;
//
//#we use the system call to open a UDP socket
//socket(SOCKET, PF_INET, SOCK_DGRAM, getprotobyname("udp")) or die "socket: $!";
proto=getprotobyname("udp");
s=socket(PF_INET, SOCK_DGRAM, proto->p_proto);
if(s) {
	//perror("asd");
	//printf("socket=%d\n",s);
}
//
//#convert hostname to ipaddress if needed
//$ipaddr   = inet_aton($HOSTNAME);
memset( &server_addr, 0, sizeof( server_addr ));
server_addr.sin_family=AF_INET;
server_addr.sin_addr.s_addr = inet_addr(hostname);
//argv[1] );
//i   = inet_aton(hostname,&server_addr.sin_addr);
server_addr.sin_port=htons(portno);
//printf("ipaddr (in hex): %x\n",server_addr.sin_addr);

/*
 * build a message.  Our message is all zeros except for a one in the
 * protocol version field
 * msg[] in binary is 00 001 000 00000000 
 * it should be a total of 48 bytes long
*/

// send the data
i=sendto(s,msg,sizeof(msg),0,(struct sockaddr *)&server_addr,sizeof(server_addr));

// get the data back
i=recv(s,buf,sizeof(buf),0);
//printf("recvfr: %d\n",i);
//perror("recvfr:");

//We get 12 long words back in Network order
uint32_t high_part;
uint32_t low_part ;
char buffer[30];
// i=2 -> referebce
//   3 -> origin
//   4 -> Receive
//   5 -> transmit
i=4;
//for(i=0;i<12;i++){
	// hex value print
	high_part = htonl((uint32_t)(buf[i] >> 32));
	low_part = htonl((uint32_t)(buf[i] & 0xFFFFFFFFLL));
	// printed as displayed in wireshark:
	printf("%d:\n", i);
	printf("\t%08x",low_part);
	printf("%08x\n",high_part);

	// high part = fractional part
	high_part = (uint32_t)(buf[i] >> 32);
	// low part = integer part (need conversion with ntohl first)
	low_part = (uint32_t)(buf[i] & 0xFFFFFFFFLL);


	// compute fractional part from high_part:
	double frac = (.00000001*(0.5+(double)(ntohl(high_part)/42.94967296)));
	printf("frac: %f\n", frac);


	// take ntohl of buffer, and substract (year 1970- year 1900) in seconds
	// to convert from ntp to unix
	time_t seconds=ntohl(low_part)-0x83aa7e80;
        strftime(buffer,30,"%Y%m%dT%T",gmtime(&seconds));
        printf("Server recieved request at: %s.%d\n",buffer,(int)(frac*1000000));
        printf("epoch:%d\n\n",(int)seconds);

//}

}
