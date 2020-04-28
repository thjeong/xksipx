#include <stdio.h> 
#include <stdlib.h>
#include <unistd.h> 
#include <math.h>
#include <inttypes.h>
#include <string.h>
#include <sys/socket.h> 
#include <sys/types.h> 
#include <sys/poll.h>
#include <arpa/inet.h> 
#include <netinet/in_systm.h>
#include <netinet/in.h> 
#include <netinet/ip.h> /* used for ip structure */
#include <netinet/udp.h> /* used for udp structure */
#include <netdb.h> /* used for gethostbyname */
#include "digcalc.h"

#define MYPORT 5060/* the port users will be connecting to */
#define BUFSIZE 4096
//#define DEBUG 

/*
 *  * broken-out digest attributes (with quotes removed)
 *  *  probably not NUL terminated.
 *  */

static int sip_parse(const char *str, int len, sip_attrs_t *attr_out);
static int digest_parse(const char *str, int len, digest_attrs_t *attr_out);
void * calcresponse(char *resp, digest_attrs_t *sipauth, sip_attrs_t *sip);

int main(int argc, char **argv){
    
    int port = MYPORT;
    int sockfd; /* for recv_message */
    int sock; /* for UAC */
    struct sockaddr_in my_addr; /* my address information */
    struct sockaddr_in their_addr; /* connector's address information */
    struct sockaddr_in host; /* for sending message */
    struct hostent *he; /* for getting my addr */
    int addr_len, numbytes;

    static char dgram[BUFSIZE]; /* Datagram buf */
    struct ip *iph = (struct ip*)dgram; 
    struct udphdr *udp = (struct udphdr*)dgram + sizeof(struct ip); 
    char *buf = (char*)udp + sizeof(struct udphdr);
    int buf_size;
    char que[BUFSIZE];
    int que_size;

    sip_attrs_t *sip2send;
    digest_attrs_t *auth2send;
    sip_attrs_t *rcvdsip;

    char srcip[32];
    char hostname[]="203.254.210.11";
    char *s_encode;
    unsigned char message[BUFSIZE];
    char command[3][256];
    char contextbuf[256];
//	struct timeval tv_timeo = { 3, 500000 };  /* 3.5 second */
	int poll_rtn;
	struct pollfd pfd;

    int i;
    
    char *end, *scan;
    FILE *fp;
    /* end of init */

    /* get my srcip */
    gethostname(srcip,32);
    
    if((he = gethostbyname(srcip)) == NULL) 
    { 
        perror("Gethostbyname error!n"); 
        exit(1); 
    } 
    sprintf(srcip, "%s",inet_ntoa(*((struct in_addr *)he->h_addr)));
    free(he);
    /* my ip is srcip */

    /* memory allocation */
    rcvdsip = (sip_attrs_t*)malloc(sizeof(sip_attrs_t));
    sip2send = (sip_attrs_t*)malloc(sizeof(sip_attrs_t));
    auth2send = (digest_attrs_t*)malloc(sizeof(digest_attrs_t));
    memset(dgram, 0, BUFSIZE);
    memset(sip2send, 0, sizeof(sip_attrs_t));
    memset(rcvdsip, 0, sizeof(sip_attrs_t));
    memset(auth2send, 0, sizeof(digest_attrs_t));
    sip2send->cseq = 10000;

    /* start of recv init */
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }
/*
	if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv_timeo, sizeof(tv_timeo)) == -1) {
		perror("setsockopt");
		exit(1);
	}

	if(setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv_timeo, sizeof(tv_timeo)) == -1) {
		perror("setsockopt");
		exit(1);
	}
*/
	fcntl(sockfd, F_SETFL, O_NONBLOCK);

    my_addr.sin_family = AF_INET; /* host byte order */
    my_addr.sin_port = htons(MYPORT); /* short, network byte order */
    my_addr.sin_addr.s_addr = INADDR_ANY; /* auto-fill with my IP */
    bzero(&(my_addr.sin_zero), 8);/* zero the rest of the struct */

    if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) \
               == -1) {
        perror("bind");
        exit(1);
    }

    addr_len = sizeof(struct sockaddr);
    /* end of recv init */

    /* start of send init */
    sprintf(command[0], "REGISTER,samsung070.com,07070156894,07070156894,23-00000000,XKSTYLE-SMS-ROBOT,,,,");
    sprintf(command[1], "REGISTER,samsung070.com,07070156894,07070156894,23-00000000,XKSTYLE-SMS-ROBOT,,,,");
    sprintf(command[2], "MESSAGE,samsung070.com,07070156894,%s,23-00000000,XKSTYLE-SMS-ROBOT,,%s,", argv[1], argv[2]);

    if((he = gethostbyname(hostname)) == NULL) 
    { 
        perror("Gethostbyname error!n"); 
        exit(1); 
    } 
     
    if((sock = socket(AF_INET,SOCK_RAW,IPPROTO_UDP)) == -1) 
    { 
        perror("Socket"); 
        exit(1); 
    } 
     
    { 
        /* UDP structure-------8 bytes in all */
        udp->uh_sport = htons(port); /* source port */
        udp->uh_dport = htons(port);
        udp->uh_ulen = htons(4 + sizeof(udp) + buf_size);
        udp->uh_sum = 0;
    } 
     
    /* Sockaddr_in structure */
    host.sin_family = AF_INET; 
    host.sin_port = htons(port); 
    host.sin_addr.s_addr = inet_addr(hostname);
    bzero(&(host.sin_zero), 8);/* zero the rest of the struct */

    /* end of send init */

    /* start of send process */
    for(i = 0; i < 3; i++) {

            scan = command[i];
            end = command[i] + strlen(command[i]);
            sip2send->method = scan;
            while(end > scan && *scan != ',') ++scan;
            sip2send->methodlen = scan - sip2send->method;
            ++scan;
            sip2send->uri = scan;
            while(end > scan && *scan != ',') ++scan;
            sip2send->urilen = scan - sip2send->uri;
            ++scan;
            sip2send->caller = scan;
            while(end > scan && *scan != ',') ++scan;
            sip2send->callerlen = scan - sip2send->caller;
            ++scan;
            sip2send->callee = scan;
            while(end > scan && *scan != ',') ++scan;
            sip2send->calleelen = scan - sip2send->callee;
            ++scan;
            sip2send->callid = scan;
            while(end > scan && *scan != ',') ++scan;
            sip2send->callidlen = scan - sip2send->callid;
            ++scan;
            sip2send->useragt = scan;
            while(end > scan && *scan != ',') ++scan;
            sip2send->useragtlen = scan - sip2send->useragt;
            ++scan;
            sip2send->auth = scan;
            while(end > scan && *scan != ',') ++scan;
            sip2send->authlen = scan - sip2send->auth;
            ++scan;
            sip2send->context = scan;
            while(end > scan && *scan != ',') ++scan;
            sip2send->contextlen = scan - sip2send->context;

            if(rcvdsip->authlen > 0 && *(sip2send->method) == 'R') {
                digest_parse(rcvdsip->auth, rcvdsip->authlen, auth2send);
                calcresponse(auth2send->resp, auth2send, sip2send);
                auth2send->resplen = strlen(auth2send->resp);
                rcvdsip->authlen = 0;
            }

            if(sip2send->contextlen > 0 && *(sip2send->method) == 'M') {
                s_encode = mzapi_encode_base64(sip2send->context, sip2send->contextlen);
                if(s_encode == ((char *)0))return(1); /* error */
                build_context(contextbuf, sip2send, s_encode);
                free((void *)s_encode);
                sip2send->context = contextbuf;
                sip2send->contextlen = strlen(contextbuf);
            }
            build_message(buf, srcip, port, sip2send, auth2send);
            buf_size = strlen(buf);

    /* Send the datagram over to the intended host */
    udp->uh_ulen = htons(4 + sizeof(udp) + buf_size);

    if((sendto(sock, udp, 4 + sizeof(udp) + buf_size, 0, (struct sockaddr *)&host, sizeof(host))) == -1)
    { 
        perror("Sendto error"); 
        exit(1); 
    } else {

#ifdef DEBUG
        printf("send packet to %s\n",hostname);
        printf("========================================\n");
        printf("%s",buf);
        printf("========================================\n");
#endif

        /* increase cseq */
        sip2send->cseq++;
    }

    /* end of send process */

    /* start of recv process */
    rcvdsip->authlen = 0;

	pfd.fd = sockfd;
	pfd.events = POLLIN | POLLHUP;

	for(;;) {
		poll_rtn = poll(&pfd, 1, 10 * 1000);
		if(poll_rtn > 0) {
			if ((numbytes=recvfrom(sockfd, message, BUFSIZE, 0, \
				(struct sockaddr *)&their_addr, &addr_len)) == -1) {
   				perror("recvfrom");
		   		exit(1);
   			} else break;
		} else if(poll_rtn == 0) {
			perror("No response");
			exit(1);
		} else {
			perror("poll");
			exit(1);
		}
	}

#ifdef DEBUG
    printf("got packet from %s\n",inet_ntoa(their_addr.sin_addr));
    printf("packet is %d bytes long\n",numbytes);
    message[numbytes] = '\0';
    printf("========================================\n");
    printf("%s",message);
    printf("========================================\n");
#endif

    sip_parse(message, strlen(message), rcvdsip);

    if(i == 2) printf("%.*s\n", rcvdsip->resultlen, rcvdsip->result);

    /* end of recv process */

    }   // end of for(i=0;i < 3; i++)
    return 0;
}

#define FIELDMAX    64

void* calcresponse(char *resp, digest_attrs_t *sipauth, sip_attrs_t *sip)
{
 char pszNonce[FIELDMAX];
 char pszCNonce[FIELDMAX];
 char pszRealm[FIELDMAX];
 char pszQop[FIELDMAX];
 char pszUser[FIELDMAX];
 char pszURI[FIELDMAX];
 char pszPass[FIELDMAX];
 char * pszAlg = "MD5";
 char szNonceCount[9] = "00000001";
 char pszMethod[FIELDMAX];
HASHHEX HA1;
HASHHEX HA2 = "";
const HASHHEX Response;

if(sipauth->nlen > 0 && sipauth->nlen < FIELDMAX) sprintf(pszNonce, "%.*s", sipauth->nlen, sipauth->nonce);
else return;

if(sip->methodlen > 0 && sip->methodlen < FIELDMAX) sprintf(pszMethod, "%.*s", sip->methodlen, sip->method);
else return;

if(sipauth->clen > 0 && sipauth->clen < FIELDMAX) sprintf(pszCNonce, "%.*s", sipauth->clen, sipauth->cnonce);
else {
    sprintf(pszCNonce, "");
    sipauth->cnonce = pszCNonce;
    sipauth->clen = strlen(pszCNonce);
}

if(sipauth->ulen > 0 && sipauth->ulen < FIELDMAX) sprintf(pszUser, "%.*s", sipauth->ulen, sipauth->user);
else {
    sprintf(pszUser, "%.*s", sip->callerlen, sip->caller);
    sipauth->user = sip->caller;
    sipauth->ulen = sip->callerlen;
}

// if(sipauth->urilen > 0 && sipauth->urilen < FIELDMAX) sprintf(pszURI, "sip:%.*s", sipauth->urilen, sipauth->uri);
if(sipauth->urilen > 0 && sipauth->urilen < FIELDMAX) sprintf(pszURI, "%.*s", sipauth->urilen, sipauth->uri);
else {
    sprintf(pszURI, "%.*s", sip->urilen, sip->uri);
    sipauth->uri = sip->uri;
    sipauth->urilen = sip->urilen;
}

if(sipauth->rlen > 0 && sipauth->rlen < FIELDMAX) sprintf(pszRealm, "%.*s", sipauth->rlen, sipauth->realm);
else {
    sprintf(pszRealm, "203.254.210.100");
    sipauth->realm = pszRealm;
    sipauth->rlen = strlen(pszRealm);
}

if(sipauth->qlen > 0 && sipauth->qlen < FIELDMAX) sprintf(pszQop, "%.*s", sipauth->qlen, sipauth->qop);
else {
    sprintf(pszQop, "auth");
    sipauth->qop = pszQop;
    sipauth->qlen = strlen(pszQop);
}

if(sipauth->pwdlen > 0 && sipauth->pwdlen < FIELDMAX) sprintf(pszPass, "%.*s", sipauth->pwdlen, sipauth->passwd);
else {
    sprintf(pszPass, "112880");
    sipauth->passwd = pszPass;
    sipauth->pwdlen = strlen(pszPass);
}

DigestCalcHA1(pszAlg, pszUser, pszRealm, pszPass, pszNonce, pszCNonce, HA1);
DigestCalcResponse(HA1, pszNonce, szNonceCount, pszCNonce, pszQop, pszMethod, pszURI, HA2, Response);

sipauth->resp = Response;
sipauth->resplen = strlen(Response);
}
