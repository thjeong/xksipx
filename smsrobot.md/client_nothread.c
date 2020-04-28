#include <stdio.h> 
#include <stdlib.h>
#include <unistd.h> 
#include <math.h>

#include <sys/socket.h> 
#include <sys/types.h> 
#include <arpa/inet.h> 
#include <netinet/in_systm.h>
#include <netinet/in.h> 
#include <netinet/ip.h> /* used for ip structure */
#include <netinet/udp.h> /* used for udp structure */

#include <netdb.h> /* used for gethostbyname */
#include <inttypes.h>
#include <string.h>

#include "digcalc.h"

#define MYPORT 5080/* the port users will be connecting to */
#define BUFSIZE 8192 

/*
 *  * broken-out digest attributes (with quotes removed)
 *  *  probably not NUL terminated.
 *  */
typedef struct {
const char *realm, *nonce, *cnonce, *qop, *user, *resp, *dom;
const char *max, *stale, *ncount, *uri, *charset, *passwd;
int rlen, nlen, clen, qlen, ulen, resplen, dlen;
int mlen, slen, nclen, urilen, charsetlen, pwdlen;
char ncbuf[9];
} digest_attrs_t;

typedef struct {
const char *method, *uri, *caller, *callee, *callid, *useragt, *auth, *context;
int methodlen, urilen, useridlen, callerlen, calleelen, callidlen, useragtlen, authlen, contextlen;
int cseq, expires, maxfwd;
} sip_attrs_t;

static int sip_parse(const char *str, int len, sip_attrs_t *attr_out);
static int digest_parse(const char *str, int len, digest_attrs_t *attr_out);

static int build_message(char *msg, const char *srcip, int srcport, const sip_attrs_t *sip, const digest_attrs_t *auth);
static int build_context(char *msg, const sip_attrs_t *sip, const char* smsmsg);

void * calcresponse(char *resp, digest_attrs_t *sipauth, sip_attrs_t *sip);

unsigned char message[BUFSIZE];

int main(int argc, char **argv){
    /* for recv_message */
    int sockfd;
    struct sockaddr_in my_addr;/* my address information */
    struct sockaddr_in their_addr; /* connector's address information */
    int addr_len, numbytes;

    /* for UAC */
    int port = MYPORT;
    int sock;
    int bytes; 
    static char dgram[BUFSIZE]; /* Datagram buf */
    FILE *fp;

    struct hostent *he; 
    struct sockaddr_in host; 
    struct ip *iph = (struct ip*)dgram; 
    struct udphdr *udp = (struct udphdr*)dgram + sizeof(struct ip); 
    char *buf = (char*)udp + sizeof(struct udphdr);

    sip_attrs_t *sip2send;
    digest_attrs_t *auth2send;

    sip_attrs_t *rcvdsip;

    char command[3][512];
    char contextbuf[512];
    char *s_encode;
    char srcip[16];
    char filename[]="xksmsrobot.conf";
    char hostname[]="203.254.210.1";

    int i;
    int buf_size;
    char que[BUFSIZE];
    int que_size;
    
    char *end, *scan, *srcport, *fromuri;
    /* end of init */

    sip2send = (sip_attrs_t*)malloc(sizeof(sip_attrs_t));
    auth2send = (digest_attrs_t*)malloc(sizeof(digest_attrs_t));
    sip2send->cseq = 10000;

    /* get my srcip */
    gethostname(srcip,16);
    
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

    /* start of recv init */
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }

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
    sprintf(command[0], "REGISTER,samsung070.com,07070156894,07070156894,23-00000000,XKSTYLE-SMS-ROBOT,,,");
    sprintf(command[1], "REGISTER,samsung070.com,07070156894,07070156894,23-00000000,XKSTYLE-SMS-ROBOT,,,");
    sprintf(command[2], "MESSAGE,samsung070.com,07070156894,%s,23-00000000,XKSTYLE-SMS-ROBOT,,%s", argv[1], argv[2]);

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
     
    memset(dgram, 0, BUFSIZE);

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
        printf("send packet to %s\n",hostname);
        printf("========================================\n");
        printf("%s",buf);
        printf("========================================\n");
        /* increase cseq */
        sip2send->cseq++;
    }

    /* end of send process */

    /* start of recv process */
    rcvdsip->authlen = 0;

    if ((numbytes=recvfrom(sockfd, message, BUFSIZE, 0, \
                       (struct sockaddr *)&their_addr, &addr_len)) == -1) {
        perror("recvfrom");
        exit(1);
    }

    printf("got packet from %s\n",inet_ntoa(their_addr.sin_addr));
    printf("packet is %d bytes long\n",numbytes);
    message[numbytes] = '\0';
    printf("========================================\n");
    printf("%s",message);
    printf("========================================\n");

    sip_parse(message, strlen(message), rcvdsip);
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

if(sipauth->ulen > 0 && sipauth->ulen < FIELDMAX) sprintf(pszUser, "%.*s", sipauth->ulen, sipauth->user);
else {
    sprintf(pszUser, "07070156894");
    sipauth->user = pszUser;
    sipauth->ulen = strlen(pszUser);
}

if(sipauth->urilen > 0 && sipauth->urilen < FIELDMAX) sprintf(pszURI, "sip:%.*s", sipauth->urilen, sipauth->uri);
else {
    sprintf(pszURI, "sip:samsung070.com");
    sipauth->uri = pszURI;
    sipauth->urilen = strlen(pszURI);
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

#define	lstreqcase(conststr, val, len) ((len) == sizeof (conststr) - 1 && \
		strncasecmp((conststr), (val), sizeof (conststr) - 1) == 0)

/* build a message REGISTER */
static int
build_message(char *msg, const char *srcip, int srcport, const sip_attrs_t *sip, const digest_attrs_t *auth)
{
    sprintf(msg, "%.*s sip:%.*s SIP/2.0\r\n", sip->methodlen, sip->method, sip->urilen, sip->uri);
    sprintf(msg + strlen(msg), "From: <sip:%.*s@%.*s>;tag=%.*s\r\n", sip->callerlen, sip->caller, sip->urilen, sip->uri, sip->callidlen, sip->callid);
    sprintf(msg + strlen(msg), "To: <sip:%.*s@%.*s>\r\n", sip->calleelen, sip->callee, sip->urilen, sip->uri);
    sprintf(msg + strlen(msg), "Contact: <sip:%.*s@%s:%d>\r\n", sip->callerlen, sip->caller, srcip, srcport);
    sprintf(msg + strlen(msg), "Via: SIP/2.0/UDP %s:%d;branch=z9hG4bK-1\r\n", srcip, srcport);
    sprintf(msg + strlen(msg), "Call-ID: %.*s@%s\r\n", sip->callidlen, sip->callid, srcip);
    sprintf(msg + strlen(msg), "CSeq: %d %.*s\r\n", sip->cseq, sip->methodlen, sip->method);
    sprintf(msg + strlen(msg), "User-Agent: %.*s\r\n",sip->useragtlen, sip->useragt);
    sprintf(msg + strlen(msg), "Max-Forwards: 70\r\n");
    if(*(sip->method) == 'M') sprintf(msg + strlen(msg), "Content-Type: application/x-npim\r\n");
    if(*(sip->method) == 'R') {
        sprintf(msg + strlen(msg), "Expires: 3600\r\n");

        if(auth->resplen > 0 && auth->rlen > 0 && auth->nlen > 0 && auth->urilen > 0) {
            sprintf(msg + strlen(msg), "Authorization: Digest username=\"%.*s\",realm=\"%.*s\",nonce=\"%.*s\",", auth->ulen, auth->user, auth->rlen, auth->realm, auth->nlen, auth->nonce);
            sprintf(msg + strlen(msg), "uri=\"%.*s\",response=\"%.*s\",algorithm=\"MD5\",nc=00000001,qop=\"auth\"\r\n", auth->urilen, auth->uri, auth->resplen, auth->resp);
        }
    }

    sprintf(msg + strlen(msg), "Content-Length: %d\r\n", sip->contextlen);
    if(sip->contextlen > 0) {
        sprintf(msg + strlen(msg), "\r\n%.*s\r\n", sip->contextlen, sip->context);
    } else sprintf(msg + strlen(msg), "\r\n");
    return(0);
}

/* build a message context */
static int
build_context(char *msg, const sip_attrs_t *sip, const char* smsmsg)
{
    sprintf(msg, "r:%.*s\r\n", sip->callerlen, sip->caller);
    sprintf(msg + strlen(msg), "e:%.*s@%.*s\r\n", sip->calleelen, sip->callee, sip->urilen, sip->uri);
    sprintf(msg + strlen(msg), "s:xkstyle-sms\r\n");
    sprintf(msg + strlen(msg), "i:4\r\n\r\n");
    sprintf(msg + strlen(msg), "%s", smsmsg);

    return(0);
}

/* parse a SIP message string */
static int
sip_parse(const char *str, int len, sip_attrs_t *attr_out)
{
	static const char fstr[] = "From";
	static const char tstr[] = "To";
	static const char cstr[] = "Contact";
	static const char vstr[] = "Via";
	static const char istr[] = "Call-ID";
	static const char sstr[] = "CSeq";
	static const char ustr[] = "User-Agent";
	static const char mstr[] = "Max-Forwards";
	static const char estr[] = "Expires";
	static const char astr[] = "WWW-Authenticate";
	static const char lstr[] = "Content-Length";

	const char *scan, *attr, *val, *end;
        const char *probe, *probeend;
        char temp[16];
	int alen, vlen;

	if (len == 0) len = strlen(str);
	scan = str;
	end = str + len;
	for (;;) {
	    /* parse attribute */
	    attr = scan;
	    while (scan < end && (*scan != ':' && *scan != ' ')) ++scan;
	    alen = scan - attr;
	    if (!alen || scan == end || scan + 1 == end) {
	        return (-5);
	    }

	    /* parse value */
            ++scan;
	    /* skip over space */
            while(scan < end && isspace(*scan)) ++scan;
	    val = scan;
	    while (scan < end && *scan != '\r') ++scan;
	    vlen = scan - val;
	    if (!vlen)
	        return (-5);

	    /* lookup the attribute */

		switch (*attr) {
		    case 'w':
		    case 'W':
                        if (memcmp(astr,attr,alen) == 0) {
				attr_out->auth = val;
				attr_out->authlen = vlen;
			}
			break;
		    case 'c':
		    case 'C':
                        if (memcmp(istr,attr,alen) == 0) {
                            /* small parsing */
                            probe = val;
                            probeend = val + vlen;
                            attr_out->callid = probe;
	                    while (probe < probeend && *probe != '@') ++probe;
                            attr_out->callidlen = probe - attr_out->callid;
			}
                        if (memcmp(sstr,attr,alen) == 0) {
                            memcpy(temp, val, vlen);
                            temp[vlen] = 0;
		    	    attr_out->cseq = atoi(temp);
			}
                        if (memcmp(lstr,attr,alen) == 0) {
                            memcpy(temp, val, vlen);
                            temp[vlen] = 0;
		    	    attr_out->contextlen = atoi(temp);
			}
			break;
		    case 'e':
		    case 'E':
                        if (memcmp(estr,attr,alen) == 0) {
                            memcpy(temp, val, vlen);
                            temp[vlen] = 0;
			    attr_out->expires = atoi(temp);
			}
			break;
		    case 'f':
		    case 'F':
                        if (memcmp(fstr,attr,alen) == 0) {
                            /* small parsing */
                            probe = val;
                            probeend = val + vlen;
	                    while (probe < probeend && *probe != ':') ++probe;
                            ++probe;
                            attr_out->caller = probe;
                            while (probe < probeend && *probe != '@') ++probe;
                            attr_out->callerlen = probe - attr_out->caller;
                            ++probe;
                            attr_out->uri = probe;
                            while (probe < probeend && *probe != '>') ++probe;
                            attr_out->urilen = probe - attr_out->uri;
			}
			break;
		    case 'm':
		    case 'M':
                        if (memcmp(mstr,attr,alen) == 0) {
                            memcpy(temp, val, vlen);
                            temp[vlen] = 0;
			    attr_out->maxfwd = atoi(temp);
			}
			break;
		    case 't':
		    case 'T':
                        if (memcmp(tstr,attr,alen) == 0) {
                            /* small parsing */
                            probe = val;
                            probeend = val + vlen;
	                    while (probe < probeend && *probe != ':') ++probe;
                            ++probe;
                            attr_out->callee = probe;
                            while (probe < probeend && *probe != '@') ++probe;
                            attr_out->calleelen = probe - attr_out->callee;
			}
			break;
		    case 'u':
		    case 'U':
                        if (memcmp(ustr,attr,alen) == 0) {
				attr_out->useragt = val;
				attr_out->useragtlen = vlen;
			}
			break;
		    case 'v':
		    case 'V':
			break;
		}

		/* we should be at the end of the string or a comma */
		// if (scan == end) break;
                /* skip if nearly end of msg. fix it later!!! */
		if (scan > end - 5) break;
		if (*scan != '\r')
			return (-5);
	    /* skip over cr */
                while(scan < end && isspace(*scan)) ++scan;
	}

	return (0);
}

/* parse a digest auth string */
static int
digest_parse(const char *str, int len, digest_attrs_t *attr_out)
{
	static const char rstr[] = "realm";
	static const char nstr[] = "nonce";
	static const char cnstr[] = "cnonce";
	static const char qstr[] = "qop";
	static const char userstr[] = "username";
	static const char respstr[] = "response";
	static const char dstr[] = "domain";
	static const char maxstr[] = "maxbuf";
	static const char ststr[] = "stale";
	static const char ncstr[] = "nc";
	static const char uristr[] = "digest-uri";
	static const char charsetstr[] = "charset";
       
	const char *scan, *attr, *val, *end;
	int alen, vlen;

	if (len == 0) len = strlen(str);
	scan = str;
	end = str + len;

        /* skip over Digest */
        while(scan < end && !isspace(*scan)) ++scan;
	for (;;) {
		/* skip over commas */
		while (scan < end && (*scan == ',' || isspace(*scan))) ++scan;
		/* parse attribute */
		attr = scan;
		while (scan < end && *scan != '=') ++scan;
		alen = scan - attr;
		if (!alen || scan == end || scan + 1 == end) {
			return (-5);
		}

		/* parse value */
		if (scan[1] == '"') {
			scan += 2;
			val = scan;
			while (scan < end && *scan != '"') {
				/* skip over "\" quoting, but don't remove it */
				if (*scan == '\\') {
					if (scan + 1 == end)
						return (-5);
					scan += 2;
				} else {
					++scan;
				}
			}
			vlen = scan - val;
			if (*scan != '"')
				return (-5);
			++scan;
		} else {
			++scan;
			val = scan;
			while (scan < end && *scan != ',') ++scan;
			vlen = scan - val;
		}
		if (!vlen)
			return (-5);

		/* lookup the attribute */
		switch (*attr) {
		    case 'c':
		    case 'C':
			if (lstreqcase(cnstr, attr, alen)) {
				attr_out->cnonce = val;
				attr_out->clen = vlen;
			}
			if (lstreqcase(charsetstr, attr, alen)) {
				attr_out->charset = val;
				attr_out->charsetlen = vlen;
			}
			break;
		    case 'd':
		    case 'D':
			if (lstreqcase(dstr, attr, alen)) {
				attr_out->dom = val;
				attr_out->dlen = vlen;
			}
			if (lstreqcase(uristr, attr, alen)) {
				attr_out->uri = val;
				attr_out->urilen = vlen;
			}
			break;
		    case 'm':
		    case 'M':
			if (lstreqcase(maxstr, attr, alen)) {
				attr_out->max = val;
				attr_out->mlen = vlen;
			}
			break;
		    case 'n':
		    case 'N':
			if (lstreqcase(nstr, attr, alen)) {
				attr_out->nonce = val;
				attr_out->nlen = vlen;
			}
			if (lstreqcase(ncstr, attr, alen)) {
				attr_out->ncount = val;
				attr_out->nclen = vlen;
			}
			break;
		    case 'q':
		    case 'Q':
			if (lstreqcase(qstr, attr, alen)) {
				attr_out->qop = val;
				attr_out->qlen = vlen;
			}
			break;
		    case 'r':
		    case 'R':
			if (lstreqcase(rstr, attr, alen)) {
				attr_out->realm = val;
				attr_out->rlen = vlen;
			}
			if (lstreqcase(respstr, attr, alen)) {
				attr_out->resp = val;
				attr_out->resplen = vlen;
			}
			break;
		    case 's':
		    case 'S':
			if (lstreqcase(ststr, attr, alen)) {
				attr_out->stale = val;
				attr_out->slen = vlen;
			}
			break;
		    case 'u':
		    case 'U':
			if (lstreqcase(userstr, attr, alen)) {
				attr_out->user = val;
				attr_out->ulen = vlen;
			}
			break;
		}

		/* we should be at the end of the string or a comma */
		if (scan == end) break;
		if (*scan != ',')
			return (-5);
	}

	return (0);
}
