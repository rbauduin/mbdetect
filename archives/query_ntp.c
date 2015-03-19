/* Copyright (GPL), 2004 Mike Chirico mchirico@comcast.net or mchirico@users.sourceforge.net
   http://prdownloads.sourceforge.net/souptonuts/working_with_time.tar.gz?download

   This program queries a timeserver on UDP port 123 and allows us to peek at 
   at the NTP timestamp format.


   Run this program as follows:

      $ ./queryTimeServer <timeserver>
  
   or

      $ ./queryTimeServer timeserver1.upenn.edu
 

   Compile:

      $ gcc -o queryTimeServer -Wall -W -O2 -s -pipe queryTimeServer.c


  


Need a list of Public NTP Secondary (stratum 2) Time Servers?
http://www.eecis.udel.edu/~mills/ntp/clock2b.html


A good reference of the standard:
http://www.eecis.udel.edu/~mills/database/rfc/rfc2030.txt





   Below is a description of the NTP/SNTP Version 4 message format,
   which follows the IP and UDP headers. This format is identical to
   that described in RFC-1305, with the exception of the contents of the
   reference identifier field. The header fields are defined as follows:

                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |LI | VN  |Mode |    Stratum    |     Poll      |   Precision   |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                          Root Delay                           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                       Root Dispersion                         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                     Reference Identifier                      |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      |                   Reference Timestamp (64)                    |
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      |                   Originate Timestamp (64)                    |
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      |                    Receive Timestamp (64)                     |
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      |                    Transmit Timestamp (64)                    |
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                 Key Identifier (optional) (32)                |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      |                                                               |
      |                 Message Digest (optional) (128)               |
      |                                                               |
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+



   Reference Timestamp: This is the time at which the local clock was
   last set or corrected, in 64-bit timestamp format.

   Originate Timestamp: This is the time at which the request departed
   the client for the server, in 64-bit timestamp format.

   Receive Timestamp: This is the time at which the request arrived at
   the server, in 64-bit timestamp format.

   Transmit Timestamp: This is the time at which the reply departed the
   server for the client, in 64-bit timestamp format.










*/


#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>
#include <unistd.h>
#include <stdint.h>



/*
 * Time of day conversion constant.  Ntp's time scale starts in 1900,
 * Unix in 1970.
 */
#define JAN_1970        0x83aa7e80      /* 2208988800 1970 - 1900 in seconds */


#define NTP_TO_UNIX(n,u) do {  u = n - JAN_1970; } while (0)


#define HTONL_FP(h, n)  do { (n)->l_ui = htonl((h)->l_ui); \
                             (n)->l_uf = htonl((h)->l_uf); } while (0)

#define NTOHL_FP(n, h)  do { (h)->l_ui = ntohl((n)->l_ui); \
                             (h)->l_uf = ntohl((n)->l_uf); } while (0)






#define SA      struct sockaddr
#define MAXLINE 16384
#define READMAX 16384		//must be less than MAXLINE or equal
#define NUM_BLK 20
#define MAXSUB  512
#define URL_LEN 256
#define MAXHSTNAM 512
#define MAXPAGE 1024
#define MAXPOST 1638

#define LISTENQ         1024

extern int h_errno;





/*
 * NTP uses two fixed point formats.  The first (l_fp) is the "long"
 * format and is 64 bits long with the decimal between bits 31 and 32.
 * This is used for time stamps in the NTP packet header (in network
 * byte order) and for internal computations of offsets (in local host
 * byte order). We use the same structure for both signed and unsigned
 * values, which is a big hack but saves rewriting all the operators
 * twice. Just to confuse this, we also sometimes just carry the
 * fractional part in calculations, in both signed and unsigned forms.
 * Anyway, an l_fp looks like:
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Integral Part                         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Fractional Part                       |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * REF http://www.eecis.udel.edu/~mills/database/rfc/rfc2030.txt
 */


typedef struct {
  union {
    uint32_t Xl_ui;
    int32_t Xl_i;
  } Ul_i;
  union {
    uint32_t Xl_uf;
    int32_t Xl_f;
  } Ul_f;
} l_fp;


#define l_ui    Ul_i.Xl_ui              /* unsigned integral part */
#define l_i     Ul_i.Xl_i               /* signed integral part */
#define l_uf    Ul_f.Xl_uf              /* unsigned fractional part */
#define l_f     Ul_f.Xl_f               /* signed fractional part */






#define HTONL_F(f, nts) do { (nts)->l_uf = htonl(f); \
                                if ((f) & 0x80000000) \
                                        (nts)->l_i = -1; \
                                else \
                                        (nts)->l_i = 0; \
                        } while (0)





struct pkt {
  uint8_t  li_vn_mode;     /* leap indicator, version and mode */
  uint8_t  stratum;        /* peer stratum */
  uint8_t  ppoll;          /* peer poll interval */
  int8_t  precision;      /* peer clock precision */
  uint32_t    rootdelay;      /* distance to primary clock */
  uint32_t    rootdispersion; /* clock dispersion */
  uint32_t refid;          /* reference clock ID */
  l_fp    ref;        /* time peer clock was last updated */
  l_fp    org;            /* originate time stamp */
  l_fp    rec;            /* receive time stamp */
  l_fp    xmt;            /* transmit time stamp */

#define LEN_PKT_NOMAC   12 * sizeof(uint32_t) /* min header length */
#define LEN_PKT_MAC     LEN_PKT_NOMAC +  sizeof(uint32_t)
#define MIN_MAC_LEN     3 * sizeof(uint32_t)     /* DES */
#define MAX_MAC_LEN     5 * sizeof(uint32_t)     /* MD5 */

  /*
   * The length of the packet less MAC must be a multiple of 64
   * with an RSA modulus and Diffie-Hellman prime of 64 octets
   * and maximum host name of 128 octets, the maximum autokey
   * command is 152 octets and maximum autokey response is 460
   * octets. A packet can contain no more than one command and one
   * response, so the maximum total extension field length is 672
   * octets. But, to handle humungus certificates, the bank must
   * be broke.
   */
#ifdef OPENSSL
  uint32_t exten[NTP_MAXEXTEN / 4]; /* max extension field */
#else /* OPENSSL */
  uint32_t exten[1];       /* misused */
#endif /* OPENSSL */
  uint8_t  mac[MAX_MAC_LEN]; /* mac */
};







void dg_snd( int sockfd, struct sockaddr * pcliaddr, socklen_t servlen)
{
  int n;
  int len;
  char buffer[30];

  time_t seconds;


  struct pkt *msg;
  struct pkt *prt;



  msg= (struct pkt *) malloc(sizeof(struct pkt)*1);
  prt= (struct pkt *) malloc(sizeof(struct pkt)*1);

  msg->li_vn_mode=227;
  msg->stratum=0;
  msg->ppoll=4;
  msg->precision=0;
  msg->rootdelay=0;
  msg->rootdispersion=0;
  msg->ref.Ul_i.Xl_i=0;
  msg->ref.Ul_f.Xl_f=0;
  msg->org.Ul_i.Xl_i=0;
  msg->org.Ul_f.Xl_f=0;
  msg->rec.Ul_i.Xl_i=0;
  msg->rec.Ul_f.Xl_f=0;
  msg->xmt.Ul_i.Xl_i=0;
  msg->xmt.Ul_f.Xl_f=0;




        fprintf(stderr,"*************  INITIAL VALUES BEFORE SEND  *******************\n");

        fprintf(stderr,"li_vn_mode %Xh  size %lu\n",msg->li_vn_mode,sizeof(msg->li_vn_mode) );
        fprintf(stderr,"stratum %d size %d\n",msg->stratum,(int) sizeof(msg->stratum));
        fprintf(stderr,"ppoll %d size %d\n",msg->ppoll,(int) sizeof(msg->ppoll));
        fprintf(stderr,"precision %d  size %d\n",msg->precision,(int) sizeof(msg->precision));
        fprintf(stderr,"rootdelay %d size %d\n",msg->rootdelay,(int) sizeof(msg->rootdelay));
        fprintf(stderr,"rootdispersion %d %d\n",msg->rootdispersion,(int) sizeof(msg->rootdispersion));
        fprintf(stderr,"refid %d size %d\n",msg->refid,(int) sizeof(msg->refid));

        fprintf(stderr,"ref %u  %d\n",msg->ref.Ul_i.Xl_ui,(int) sizeof(msg->ref.Ul_i));
        fprintf(stderr,"ref %u  %d\n",msg->ref.Ul_f.Xl_f,(int) sizeof(msg->ref.Ul_f));

        fprintf(stderr,"org %u  %d\n",msg->ref.Ul_i.Xl_ui,(int) sizeof(msg->ref.Ul_i));
        fprintf(stderr,"org %u  %d\n",msg->ref.Ul_f.Xl_f,(int) sizeof(msg->ref.Ul_f));


        fprintf(stderr,"org %u  %d\n",msg->org.Ul_i.Xl_ui,(int) sizeof(msg->org.Ul_i));
        fprintf(stderr,"org %u  %d\n",msg->org.Ul_f.Xl_f,(int) sizeof(msg->org.Ul_f));

        fprintf(stderr,"rec %u  %d\n",msg->rec.Ul_i.Xl_ui,(int)sizeof(msg->rec.Ul_i));
        fprintf(stderr,"rec %u  %d\n",msg->rec.Ul_f.Xl_f,(int)sizeof(msg->rec.Ul_f));

        fprintf(stderr,"xmt %u  %d\n",msg->xmt.Ul_i.Xl_ui,(int)sizeof(msg->xmt.Ul_i));
        fprintf(stderr,"xmt %u  %d\n",msg->xmt.Ul_f.Xl_f,(int)sizeof(msg->xmt.Ul_f));

        fprintf(stderr,"*************  END INITIAL VALUES BEFORE SEND  ***************\n");









  len=48;

      sendto(sockfd, (char *) msg, len, 0, pcliaddr, servlen);
      n = recvfrom(sockfd, msg, len, 0, NULL, NULL);


        fprintf(stderr,"\n\n*************   2nd START  *******************\n");
        fprintf(stderr,"li_vn_mode %Xh  size %d\n",msg->li_vn_mode,(int)sizeof(msg->li_vn_mode) );
        fprintf(stderr,"stratum %d size %d\n",msg->stratum,(int)sizeof(msg->stratum));
        fprintf(stderr,"ppoll %d size %d\n",msg->ppoll,(int)sizeof(msg->ppoll));
        fprintf(stderr,"precision %d  size %d\n",msg->precision,(int)sizeof(msg->precision));
        fprintf(stderr,"rootdelay %Xh size %d\n",ntohl(msg->rootdelay),(int)sizeof(msg->rootdelay));
        fprintf(stderr,"rootdispersion %d %d\n",ntohl(msg->rootdispersion),(int)sizeof(msg->rootdispersion));
        fprintf(stderr,"refid %d size %d\n",msg->refid,(int)sizeof(msg->refid));


       	NTOHL_FP(&msg->ref, &prt->ref);
       	NTOHL_FP(&msg->org, &prt->org);
       	NTOHL_FP(&msg->rec, &prt->rec);
       	NTOHL_FP(&msg->xmt, &prt->xmt);

        fprintf(stderr,"ref %u  %d\n",prt->ref.Ul_i.Xl_ui,(int)sizeof(msg->ref.Ul_i));
        fprintf(stderr,"ref %u  %d\n",prt->ref.Ul_f.Xl_f,(int)sizeof(msg->ref.Ul_f));

          

        fprintf(stderr,"org %u  %d\n",prt->org.Ul_i.Xl_ui,(int)sizeof(prt->org.Ul_i));
        fprintf(stderr,"org %u  %d\n",prt->org.Ul_f.Xl_f,(int)sizeof(prt->org.Ul_f));

        fprintf(stderr,"rec %u  %d\n",prt->rec.Ul_i.Xl_ui,(int)sizeof(prt->rec.Ul_i));
        fprintf(stderr,"rec %u  %d\n",prt->rec.Ul_f.Xl_f,(int)sizeof(prt->rec.Ul_f));

        fprintf(stderr,"xmt %u  %d\n",prt->xmt.Ul_i.Xl_ui,(int)sizeof(prt->xmt.Ul_i));
        fprintf(stderr,"xmt %u  %d\n",prt->xmt.Ul_f.Xl_f,(int)sizeof(prt->xmt.Ul_f));

	NTP_TO_UNIX(prt->ref.Ul_i.Xl_ui, seconds);
        strftime(buffer,30,"%m-%d-%Y  %T",localtime(&seconds));
        fprintf(stderr,"\nref: %s.%u\n",buffer,prt->ref.Ul_f.Xl_f);


	NTP_TO_UNIX(prt->org.Ul_i.Xl_ui, seconds);
        strftime(buffer,30,"%m-%d-%Y  %T",localtime(&seconds));
        fprintf(stderr,"org: %s.%u\n",buffer,prt->org.Ul_f.Xl_f);


	NTP_TO_UNIX(prt->rec.Ul_i.Xl_ui, seconds);
        strftime(buffer,30,"%m-%d-%Y  %T",localtime(&seconds));
        fprintf(stderr,"rec: %s.%u\n",buffer,prt->rec.Ul_f.Xl_f);



	NTP_TO_UNIX(prt->xmt.Ul_i.Xl_ui, seconds);
        strftime(buffer,30,"%m-%d-%Y  %T",localtime(&seconds));
        fprintf(stderr,"xmt: %s.%u\n",buffer,prt->xmt.Ul_f.Xl_f); // = l_f

        fprintf(stderr,"*************   2nd STOP  *******************\n");



  msg->li_vn_mode=227;
  msg->stratum=0;
  msg->ppoll=4;
  msg->precision=-6;
  msg->rootdelay=256;
  msg->rootdispersion=256;

  msg->ref.Ul_i.Xl_i= msg->xmt.Ul_i.Xl_i;
  msg->ref.Ul_f.Xl_f= msg->xmt.Ul_f.Xl_f;

  msg->org.Ul_i.Xl_i= msg->xmt.Ul_i.Xl_i;
  msg->org.Ul_f.Xl_f= msg->xmt.Ul_f.Xl_f;







         sendto(sockfd, (char *) msg, len, 0, pcliaddr, servlen);
	  n = recvfrom(sockfd, msg, len, 0, NULL, NULL);
int     maxlen=1024;
unsigned long long  buf[maxlen];	// the buffer we get back
memcpy(buf, msg, sizeof(buf));
uint32_t high_part;
uint32_t low_part ;
int i=2;
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

	printf("ntohl high part: %u\n", ntohl(high_part));

	seconds=ntohl(low_part)-0x83aa7e80;
        strftime(buffer,30,"%m-%d-%Y  %T",localtime(&seconds));
        printf("ref low: %s\n\n",buffer);

	// NOTE this is wrong, the fractional part has to be 
	// converted to a float as:
	// (.00000001*(0.5+(double)(ntohl(high_part)/42.94967296)))
	//
        printf("fractional (high): %u\n\n",ntohl(high_part));
        printf("fractional (high): %u\n\n",ntohl(high_part));

	seconds=ntohl(buf[i])-0x83aa7e80;
        strftime(buffer,30,"%m-%d-%Y  %T",localtime(&seconds));
        printf("ref complete: %s\n\n",buffer);





        fprintf(stderr,"\n\n*************   3nd START  *******************\n");
        fprintf(stderr,"li_vn_mode %Xh  size %d\n",msg->li_vn_mode,(int)sizeof(msg->li_vn_mode) );
        fprintf(stderr,"stratum %d size %d\n",msg->stratum,(int)sizeof(msg->stratum));
        fprintf(stderr,"ppoll %d size %d\n",msg->ppoll,(int)sizeof(msg->ppoll));
        fprintf(stderr,"precision %d  size %d\n",msg->precision,(int)sizeof(msg->precision));

        fprintf(stderr,"rootdelay %Xh size %d\n",ntohl(msg->rootdelay),(int)sizeof(msg->rootdelay));
        fprintf(stderr,"rootdispersion %d %d\n",ntohl(msg->rootdispersion),(int)sizeof(msg->rootdispersion));


        fprintf(stderr,"refid %d size %d\n",msg->refid,(int)sizeof(msg->refid));



       	NTOHL_FP(&msg->ref, &prt->ref);
       	NTOHL_FP(&msg->org, &prt->org);
       	NTOHL_FP(&msg->rec, &prt->rec);
       	NTOHL_FP(&msg->xmt, &prt->xmt);

        fprintf(stderr,"ref %u  %d\n",prt->ref.Ul_i.Xl_ui,(int)sizeof(msg->ref.Ul_i));
        fprintf(stderr,"ref %u  %d\n",prt->ref.Ul_f.Xl_f,(int)sizeof(msg->ref.Ul_f));


        fprintf(stderr,"org %u  %d\n",prt->org.Ul_i.Xl_ui,(int)sizeof(prt->org.Ul_i));
        fprintf(stderr,"org %u  %d\n",prt->org.Ul_f.Xl_f,(int)sizeof(prt->org.Ul_f));

        fprintf(stderr,"rec %u  %d\n",prt->rec.Ul_i.Xl_ui,(int)sizeof(prt->rec.Ul_i));
        fprintf(stderr,"rec %u  %d\n",prt->rec.Ul_f.Xl_f,(int)sizeof(prt->rec.Ul_f));

        fprintf(stderr,"xmt %u  %d\n",prt->xmt.Ul_i.Xl_ui,(int)sizeof(prt->xmt.Ul_i));
        fprintf(stderr,"xmt %u  %d\n",prt->xmt.Ul_f.Xl_f,(int)sizeof(prt->xmt.Ul_f));

	NTP_TO_UNIX(prt->ref.Ul_i.Xl_ui, seconds);
        strftime(buffer,30,"%m-%d-%Y  %T",localtime(&seconds));
        fprintf(stderr,"\nref: %s.%u\n",buffer,prt->ref.Ul_f.Xl_f);


	NTP_TO_UNIX(prt->org.Ul_i.Xl_ui, seconds);
        strftime(buffer,30,"%m-%d-%Y  %T",localtime(&seconds));
        fprintf(stderr,"org: %s.%u\n",buffer,prt->org.Ul_f.Xl_f);


	NTP_TO_UNIX(prt->rec.Ul_i.Xl_ui, seconds);
        strftime(buffer,30,"%m-%d-%Y  %T",localtime(&seconds));
        fprintf(stderr,"rec: %s.%u\n",buffer,prt->rec.Ul_f.Xl_f);



	NTP_TO_UNIX(prt->xmt.Ul_i.Xl_ui, seconds);
        strftime(buffer,30,"%m-%d-%Y  %T",localtime(&seconds));
        fprintf(stderr,"xmt: %s.%u\n",buffer,prt->xmt.Ul_f.Xl_f);

        fprintf(stderr,"*************   3nd STOP  *******************\n");


	free(msg);
        free(prt);

}





int main(int argc, char **argv)
{


	if (argc < 2) {
		fprintf(stderr,
			"./queryTimeServer timeserver1.upenn.edu\n"
                        "or\n"      
			"./queryTimeServer timex.usg.edu\n"
			"./queryTimeServer ntp.linux.org.ve\n"
			"./queryTimeServer ntp.pop-pr.rnp.br\n\n"  

			);
		exit(1);
	}


	int sockfd;
	struct sockaddr_in servaddr;
	char **pptr;




	char str[50];
	struct hostent *hptr;
	if ((hptr = gethostbyname(argv[1])) == NULL) {
		fprintf(stderr, " gethostbyname error for host: %s: %s",
			argv[1], hstrerror(h_errno));
		exit(1);
	}

	if (hptr->h_addrtype == AF_INET
	    && (pptr = hptr->h_addr_list) != NULL) {

		inet_ntop(hptr->h_addrtype, *pptr, str, sizeof(str));
	} else {
		fprintf(stderr, "Error call inet_ntop \n");
	}

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd == -1)
	  fprintf(stderr,"Error in socket \n");
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(123);
	inet_pton(AF_INET, str, &servaddr.sin_addr);

	if (connect(sockfd, (SA *) & servaddr, sizeof(servaddr)) == -1 )
	  fprintf(stderr,"Error in connect \n");
        dg_snd(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr));
        close(sockfd);
    
  exit(0);
}
