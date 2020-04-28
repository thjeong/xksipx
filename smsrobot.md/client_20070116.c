#include <stdio.h> 
#include <stdlib.h>
#include <unistd.h> 
#include <math.h>

#include <sys/socket.h> 
#include <sys/types.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <netinet/ip.h> /* used for ip structure */
#include <netinet/udp.h> /* used for udp structure */

#include <netdb.h> /* used for gethostbyname */
#include <inttypes.h>
#include <string.h>

#include <pthread.h>

#define MYPORT 5080/* the port users will be connecting to */
#define BUFSIZE 4096

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

/*
 *  * broken-out digest attributes (with quotes removed)
 *  *  probably not NUL terminated.
 *  */
typedef struct {
const char *realm, *nonce, *cnonce, *qop, *user, *resp, *dom;
const char *max, *stale, *ncount, *uri, *charset;
int rlen, nlen, clen, qlen, ulen, resplen, dlen;
int mlen, slen, nclen, urilen, charsetlen;
char ncbuf[9];
} digest_attrs_t;

typedef struct {
const char *method, *from, *to, *contact, *via, *callid, *cseq, *useragt, *auth;
const char *fromid, *toid, *fromuri, *touri; 
// const char *maxfwd, *expires, *conlength;
int mlen, flen, tlen, clen, vlen, ilen, slen, ulen, alen;
int maxfwd, expires, contextlen;
int fromlen, tolen, fromurilen, tourilen;
char ncbuf[9];
} sip_attrs_t;

unsigned char message[BUFSIZE];

static int sip_parse(const char *str, int len, sip_attrs_t *attr_out);
static int digest_parse(const char *str, int len, digest_attrs_t *attr_out);

static int build_register(char *msg, const char *srcip, int srcport, const sip_attrs_t *sip, const digest_attrs_t *auth);

unsigned short in_cksum(unsigned short *addr, int len);
void * send_message(void *arg);
void * recv_message(void *arg);

sip_attrs_t *rcvdsip;
digest_attrs_t *rcvdsipauth;

int main(int argc, char **argv){

    int sock;
    pthread_t snd_thread, rcv_thread;
    void * thread_result;

    /* memory allocation */
    rcvdsip = (sip_attrs_t*)malloc(sizeof(sip_attrs_t));
    rcvdsipauth = (digest_attrs_t*)malloc(sizeof(digest_attrs_t));

    pthread_create(&snd_thread, NULL, send_message, (void*)sock);
    pthread_create(&rcv_thread, NULL, recv_message, (void*)sock);
    pthread_join(snd_thread, &thread_result);
    pthread_join(rcv_thread, &thread_result);
    close(sock);
    return 0;
}

void * recv_message(void *arg)
{
    int sockfd = (int)arg;
    struct sockaddr_in my_addr;/* my address information */
    struct sockaddr_in their_addr; /* connector's address information */
    int addr_len, numbytes;
    int i;

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

    while(1) {
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
    printf("========================================\n>");

    if(-5 == sip_parse(message, strlen(message), rcvdsip)) printf("abnormal parsing error.\n");
    digest_parse(rcvdsip->auth, rcvdsip->alen, rcvdsipauth);
    /*
    printf("\n");
    for(i = 0; i < rcvdsip->fromlen; i++) printf("%c", rcvdsip->fromid[i]);
    printf("\n");
    for(i = 0; i < rcvdsip->fromurilen; i++) printf("%c", rcvdsip->fromuri[i]);
    printf("\n");
    for(i = 0; i < rcvdsip->tolen; i++) printf("%c", rcvdsip->toid[i]);
    printf("\n");
    for(i = 0; i < rcvdsip->tourilen; i++) printf("%c", rcvdsip->touri[i]);
    printf("\n");
    fflush(stdout);
    */
    }

    close(sockfd);
}

void * send_message(void *arg)
{ 
    /* for UAC */
    int port = MYPORT;
    int sock = (int)arg; 
    int bytes; 
    char dgram[BUFSIZE]; /* Datagram buf */
    FILE *fp;

    struct hostent *he; 
    struct sockaddr_in host; 
    struct ip *iph = (struct ip*)dgram; 
    struct udphdr *udp = (struct udphdr*)dgram + sizeof(struct ip); 
    char *buf = (char*)udp + sizeof(struct udphdr);

    char command[128];
    char filename[]="msg1.txt";
    char hostname[]="203.254.210.1";

    int i;
    int buf_size;
    char que[BUFSIZE];
    int que_size;
    
    char *end, *scan, *srcip, *srcport, *fromuri;
    /* end of init */

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

    /* start of while */
    while(1) {

    printf(">");
    fgets(command, BUFSIZE, stdin);

    switch(*command){
        case 'q':
        case 'Q':
            exit(0);
            break;
        case 't':
        case 'T':
            filename[3] = '5';

            fp = fopen(filename, "r");
            que_size = fread(que, 1, 2048, fp);
            que[que_size] = 0;

            buf_size = 0;
            for(i = 0; i < que_size; i++) {
                if(que[i] == '\n') {
                    if(que[i - 1] != '\r') {
                        buf[buf_size++] = '\r';
                    } else {
                        /* do nothing */
                    }
                }
            buf[buf_size++] = que[i];
            }
            fclose(fp);
            break;
        case 'r':
        case 'R':
            build_register(buf, hostname, port, rcvdsip, rcvdsipauth);
            break;
    }
    /* Send the datagram over to the intended host */
    if((sendto(sock, udp, 4 + sizeof(udp) + buf_size, 0, (struct sockaddr *)&host, sizeof(host))) == -1)
    { 
        perror("Sendto error"); 
        exit(1); 
    } else {
        printf("send packet to %s\n",hostname);
        printf("========================================\n");
        printf("%s",buf);
        printf("========================================\n");
    }

    }   /* end of while */  
} 

unsigned short in_cksum(unsigned short *addr,int len)
{
    register int sum = 0; 
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;  

    /*
     *  * Our algorithm is simple, using a 32 bit accumulator (sum), we add 
     *   * sequential 16 bit words to it, and at the end, fold back all the
     *    * carry bits from the top 16 bits into the lower 16 bits. 
     *     */ 
    while (nleft > 1)  {  
         sum += *w++;  
          nleft -= 2;
    } 

    /* mop up an odd byte, if necessary */ 
    if (nleft == 1) {
         *(u_char *)(&answer) = *(u_char *)w ;  
          sum += answer;
    } 

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);/* add hi 16 to low 16 */  
    sum += (sum >> 16); /* add carry */  
    answer = ~sum; /* truncate to 16 bits */  
    return(answer);  
}

#define	lstreqcase(conststr, val, len) ((len) == sizeof (conststr) - 1 && \
		strncasecmp((conststr), (val), sizeof (conststr) - 1) == 0)

/* build a message REGISTER */
static int
build_register(char *msg, const char *srcip, int srcport, const sip_attrs_t *sip, const digest_attrs_t *auth)
{
    if(srcport != 5080 && srcport != 5060) return (-5);
    sprintf(msg, "REGISTER sip:%s SIP/2.0\r\n", sip->fromuri);
    sprintf(msg + strlen(msg) - 1, "From: <sip:%s@%s>;tag=23-00000000\r\n", sip->fromid, sip->fromuri);
    sprintf(msg + strlen(msg) - 1, "To: <sip:%s@%s>\r\n", sip->toid, sip->touri);
    sprintf(msg + strlen(msg) - 1, "Contact: <sip:%s@%s:%d>\r\n", sip->fromid, srcip, srcport);
    sprintf(msg + strlen(msg) - 1, "Via: SIP/2.0/UDP %s:%d;branch=z9hG4bK-1\r\n", srcip, srcport);
    sprintf(msg + strlen(msg) - 1, "Call-ID: 23-00000000@%d\r\n", srcip);
    sprintf(msg + strlen(msg) - 1, "CSeq: 1 REGISTER\r\n");
    sprintf(msg + strlen(msg) - 1, "User-Agent: XKSTYLE-SMS-ROBOT\r\n");
    sprintf(msg + strlen(msg) - 1, "Max-Forwards: 70\r\n");
    sprintf(msg + strlen(msg) - 1, "Expires: 3600\r\n");
    if(auth != NULL)
    sprintf(msg + strlen(msg) - 1, "Authorization: Digest username=\"%s\",realm=\"%s\",nonce=\"%s\",uri=\"%s\",response=\"%s\",algorithm=MD5,cnonce=\"%d\",nc=00000001,qop=auth\r\n", sip->fromid, auth->realm, auth->nonce, auth->uri, auth->resp, auth->cnonce);
    sprintf(msg + strlen(msg) - 1, "Content-Length: 0\r\n\r\n");
    return(0);
}

/* parse a SIP message string */
static int
sip_parse(const char *str, int len, sip_attrs_t *attr_out)
{
/*	static const char fstr[] = "From";
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
        */
	const char *scan, *attr, *val, *end;
        const char *probe, *probeend;
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
				attr_out->alen = vlen;
			}
			break;
		    case 'c':
		    case 'C':
                        if (memcmp(cstr,attr,alen) == 0) {
				attr_out->contact = val;
				attr_out->clen = vlen;
			}
                        if (memcmp(istr,attr,alen) == 0) {
				attr_out->callid = val;
				attr_out->ilen = vlen;
			}
                        if (memcmp(sstr,attr,alen) == 0) {
				attr_out->cseq = val;
				attr_out->slen = vlen;
			}
                        if (memcmp(lstr,attr,alen) == 0) {
				attr_out->contextlen = atoi(val);
		//		attr_out->slen = vlen;
			}
			break;
		    case 'e':
		    case 'E':
                        if (memcmp(estr,attr,alen) == 0) {
				attr_out->expires = atoi(val);
		//		attr_out->flen = vlen;
			}
			break;
		    case 'f':
		    case 'F':
                        if (memcmp(fstr,attr,alen) == 0) {
			    attr_out->from = val;
			    attr_out->flen = vlen;
                            /* small parsing */
                            probe = val;
                            probeend = val + vlen;
	                    while (probe < probeend && *probe != ':') ++probe;
                            ++probe;
                            attr_out->fromid = probe;
                            while (probe < probeend && *probe != '@') ++probe;
                            attr_out->fromlen = probe - attr_out->fromid;
                            ++probe;
                            attr_out->fromuri = probe;
                            while (probe < probeend && *probe != '>') ++probe;
                            attr_out->fromurilen = probe - attr_out->fromuri;
			}
			break;
		    case 'm':
		    case 'M':
                        if (memcmp(mstr,attr,alen) == 0) {
				attr_out->maxfwd = atoi(val);
		//		attr_out->mlen = vlen;
			}
			break;
		    case 't':
		    case 'T':
                        if (memcmp(tstr,attr,alen) == 0) {
			    attr_out->to = val;
			    attr_out->tlen = vlen;
                            /* small parsing */
                            probe = val;
                            probeend = val + vlen;
	                    while (probe < probeend && *probe != ':') ++probe;
                            ++probe;
                            attr_out->toid = probe;
                            while (probe < probeend && *probe != '@') ++probe;
                            attr_out->tolen = probe - attr_out->toid;
                            ++probe;
                            attr_out->touri = probe;
                            while (probe < probeend && *probe != '>') ++probe;
                            attr_out->tourilen = probe - attr_out->touri;
			}
			break;
		    case 'u':
		    case 'U':
                        if (memcmp(ustr,attr,alen) == 0) {
				attr_out->useragt = val;
				attr_out->ulen = vlen;
			}
			break;
		    case 'v':
		    case 'V':
                        if (memcmp(vstr,attr,alen) == 0) {
				attr_out->via = val;
				attr_out->vlen = vlen;
			}
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
/*	static const char rstr[] = "realm";
	static const char nstr[] = "nonce";
	static const char cstr[] = "cnonce";
	static const char qstr[] = "qop";
	static const char ustr[] = "username";
	static const char respstr[] = "response";
	static const char dstr[] = "domain";
	static const char mstr[] = "maxbuf";
	static const char sstr[] = "stale";
	static const char ncstr[] = "nc";
	static const char uristr[] = "digest-uri";
	static const char charsetstr[] = "charset";
        */
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
