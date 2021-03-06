#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include "sip_attrs.h"

#define MYPORT 5060    /* the port users will be connecting to */
#define MAXBUFLEN 4096 
#define ENTRY_SIZE 1 /* message count which could be handled by this SIP engine */

void *responder(void *data);
void write_parsed_context(sip_attrs_t *rcvdsip);
void trying2invite(struct sockaddr_in their_addr, sip_attrs_t *rcvdsip);

typedef struct {
	unsigned char active;
	char userid[48];
	char passwd[48];
	struct sockaddr_in addr;
} user_entry;

user_entry entry[ENTRY_SIZE];
sip_attrs_t *rcvdsip[ENTRY_SIZE];
char hostname[] = "203.254.210.244";

int main()
{
	int i, status;
        int sockfd;
        struct sockaddr_in my_addr;    /* my address information */
        struct sockaddr_in their_addr; /* connector's address information */
        int addr_len, numbytes;
        char buf[MAXBUFLEN];
        char buf2send[MAXBUFLEN];
	pthread_t pth[ENTRY_SIZE];
	int cur = 0;
	int ent_no[ENTRY_SIZE];
	FILE *fp;

	printf("Memory allocation (%d kbytes)...", (sizeof(sip_attrs_t) + sizeof(uri_attrs_t) * 5 + sizeof(via_attrs_t) + sizeof(digest_attrs_t) + sizeof(sdp_attrs_t)) * ENTRY_SIZE / 1024);

	fp = fopen("./USER.DB", "r");

    for(i = 0; i < ENTRY_SIZE; i++) {
        /* memory allocation */
        rcvdsip[i] = (sip_attrs_t*)malloc(sizeof(sip_attrs_t));
        rcvdsip[i]->uri = (uri_attrs_t*)malloc(sizeof(uri_attrs_t));
        rcvdsip[i]->from = (uri_attrs_t*)malloc(sizeof(uri_attrs_t));
        rcvdsip[i]->to = (uri_attrs_t*)malloc(sizeof(uri_attrs_t));
        rcvdsip[i]->contact = (uri_attrs_t*)malloc(sizeof(uri_attrs_t));
        rcvdsip[i]->route = (uri_attrs_t*)malloc(sizeof(uri_attrs_t));
        rcvdsip[i]->via[0] = (via_attrs_t*)malloc(sizeof(via_attrs_t));
        rcvdsip[i]->via[1] = (via_attrs_t*)malloc(sizeof(via_attrs_t));
        rcvdsip[i]->via[2] = (via_attrs_t*)malloc(sizeof(via_attrs_t));
        rcvdsip[i]->via[3] = (via_attrs_t*)malloc(sizeof(via_attrs_t));
        rcvdsip[i]->credential = (digest_attrs_t*)malloc(sizeof(digest_attrs_t));
        rcvdsip[i]->sdp = (sdp_attrs_t*)malloc(sizeof(sdp_attrs_t));

	entry[i].active = 0;
	numbytes = fread(entry[i].userid, sizeof(entry[i].userid), 1, fp);
	numbytes = fread(entry[i].passwd, sizeof(entry[i].passwd), 1, fp);
    }
	fclose(fp);
	printf("OK\n");

	printf("ALL USER ENTRIES\n");
	printf("--------------------------------\n");
	printf("NO\tUSER_ID    \tPASSWD\n");
	printf("--------------------------------\n");
	for(i = 0; i < ENTRY_SIZE; i++) {
		if(strlen(entry[i].userid) == 0) break;
		printf("%d\t%s\t%s\n", i, entry[i].userid, entry[i].passwd);
	}
	printf("\n");

        if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
            perror("socket");
            exit(1);
        }

        my_addr.sin_family = AF_INET;         /* host byte order */
        my_addr.sin_port = htons(MYPORT);     /* short, network byte order */
        my_addr.sin_addr.s_addr = INADDR_ANY; /* auto-fill with my IP */
        bzero(&(my_addr.sin_zero), 8);        /* zero the rest of the struct */

	printf("Listening port(%d) binding...", MYPORT);
        if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) \
                                                                       == -1) {
            perror("bind");
            exit(1);
        }
	printf("OK\n");

        addr_len = sizeof(struct sockaddr);

	numbytes = buildreg(buf, rcvdsip[0], 0);
	printf("SENDING MSG TO %s...\n=========================================\n%s\n", hostname, buf);
	sendto_raw(5060, hostname, buf, numbytes);

	while(1) {
	if ((numbytes=recvfrom(sockfd, buf, MAXBUFLEN, 0, \
		(struct sockaddr *)&their_addr, &addr_len)) == -1) {
		perror("recvfrom");
		//exit(1);
		break;
	}

	// if(their_addr.sin_addr == NULL) printf("IS NULL\n");
	// sprintf(buf2send, "%s", inet_ntoa(my_addr.sin_addr));
	// printf("%s\n", buf2send);
	
	// printf("\nRcvd packet from %s(%d)",inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port));
	printf("\tlength: %d bytes long.\n", numbytes);
	buf[numbytes] = '\0';
	printf("<%d>==============================================\n%s\n",cur,buf);
	fflush(stdout);

	i = 0;
	// select number of rcvdsip entry
	// 계속 +1씩 하되 아직도 쓰고 있는 entry인지는 확인할 것.
/*
	while(1) {
		if(entry[i].active != 0) {
			cur = i;
			break;
		} else i++;
		if(i >= ENTRY_SIZE) {
			cur = 0;
			break;
		}
	}

	cur++;
	ent_no[cur] = cur;
	
	if(cur >= ENTRY_SIZE) cur = 0;
	entry[cur].addr = their_addr;
*/
	// end of finding and selecting entry.
/* DEBUG */
/*
        printf("\n%.*s from %s(%d)\n",rcvdsip[cur]->methodlen, rcvdsip[cur]->method, inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port));
        printf("==============================================\n%s\n",buf);
*/

	sip_parse(buf, numbytes, rcvdsip[cur]);
	//write_parsed_context(rcvdsip);
	// Memory contained SIP Parsed Data Copying at this moment.

	if (pthread_create(&pth[cur], NULL, responder, (void*)&ent_no[cur]) < 0)
	{
		perror("Thread Creation error:");
		exit(0);
	}

	//pthread_join(pth[cur], (void**)&status);
	pthread_detach(pth[cur]);
//	printf("Thread End %d\n", status);

    }

    for(i = 0; i < ENTRY_SIZE; i++) {
        free(rcvdsip[i]->uri);
        free(rcvdsip[i]->from);
        free(rcvdsip[i]->to);
        free(rcvdsip[i]->contact);
        free(rcvdsip[i]->route);
        free(rcvdsip[i]->via[0]);
        free(rcvdsip[i]->via[1]);
        free(rcvdsip[i]->via[2]);
        free(rcvdsip[i]->via[3]);
        free(rcvdsip[i]->credential);
        free(rcvdsip[i]->sdp);
        free(rcvdsip[i]);
    }
        close(sockfd);
}

void *responder(void *data)
{
	int cur = *(int *)data;
	int numbytes;
	char respbuf[2048];

	// semaphore관리할 것
	//entry[cur].active = 1;

	/* FOR CLIENT */
	if(memcmp(rcvdsip[cur]->cseq_method, "REGISTER", 8) == 0) {
		if(memcmp(rcvdsip[cur]->status, "401", 3) == 0) {
			printf("RESPONDER : Rechallenging with Digest...\n");
			// write_parsed_context(rcvdsip[cur]);
			numbytes = buildreg(respbuf, rcvdsip[cur], 1);
			printf("SENDING MSG TO %s...\n=========================================\n%s\n", hostname, respbuf);
			sleep(3);
			sendto_raw(5060, hostname, respbuf, numbytes);
			
		}
	}

/*
	if(memcmp(rcvdsip[cur]->from->user, "0708015", 7) == 0
		|| memcmp(rcvdsip[cur]->from->host, "samsung8015.com", 15) == 0
	) {
		if(memcmp(rcvdsip[cur]->method, "REGISTER", 8) == 0) {
			oksendto(entry[cur].addr, rcvdsip[cur]);
		} else if(memcmp(rcvdsip[cur]->method, "INVITE", 6) == 0) {
			trying2invite(their_addr, rcvdsip[cur]);
			ringing2invite(their_addr, rcvdsip[cur]);
			sessprog2invite(their_addr, rcvdsip[cur]);
			sleep(10);
			ok2invite(their_addr, rcvdsip[cur]);
		} else if((memcmp(rcvdsip[cur]->method, "BYE", 3) == 0) 
			|| (memcmp(rcvdsip[cur]->method, "CANCEL", 6) == 0)) {
			oksendto(their_addr, rcvdsip[cur]);
		} 
	} else {
		if(memcmp(rcvdsip[cur]->method, "REGISTER", 8) == 0) {
			unauthsendto(entry[cur].addr, rcvdsip[cur]);
		} else if(memcmp(rcvdsip[cur]->method, "INVITE", 6) == 0) {
			unauthsendto(their_addr, rcvdsip[cur]);
		} else if((memcmp(rcvdsip[cur]->method, "BYE", 3) == 0) 
			|| (memcmp(rcvdsip[cur]->method, "CANCEL", 6) == 0)) {
			unauthsendto(their_addr, rcvdsip[cur]);
		} 
	}
*/
	// printf("\t\tend of %d\n", cur);
	//entry[cur].active = 0;
/*
	if((memcmp(rcvdsip->from->user, "0707139", 7) == 0
		&& memcmp(rcvdsip->from->host, "sniproxy", 8) == 0)
		|| memcmp(rcvdsip->from->user, "sipp", 4) == 0
	) {
		if(memcmp(rcvdsip->method, "REGISTER", 8) == 0) {
			oksendto(their_addr, rcvdsip[cur]);
		} else if(memcmp(rcvdsip->method, "INVITE", 6) == 0) {
			trying2invite(their_addr, rcvdsip[cur]);
			ringing2invite(their_addr, rcvdsip[cur]);
			sessprog2invite(their_addr, rcvdsip[cur]);
			ok2invite(their_addr, rcvdsip[cur]);
		} else if((memcmp(rcvdsip->method, "BYE", 3) == 0) 
			|| (memcmp(rcvdsip->method, "CANCEL", 6) == 0)) {
			oksendto(their_addr, rcvdsip[cur]);
		} 
	} else {
		if(memcmp(rcvdsip->method, "REGISTER", 8) == 0) {
			unauthsendto(their_addr, rcvdsip[cur]);
		} else if(memcmp(rcvdsip->method, "INVITE", 6) == 0) {
			unauthsendto(their_addr, rcvdsip[cur]);
		} else if((memcmp(rcvdsip->method, "BYE", 3) == 0) 
			|| (memcmp(rcvdsip->method, "CANCEL", 6) == 0)) {
			unauthsendto(their_addr, rcvdsip[cur]);
		} 
	}
*/
}

void write_parsed_context(sip_attrs_t *rcvdsip)
{
        int rcvdsip_expires;
        const char *rcvdsip_mthdstat;
        int rcvdsip_mthdstatlen;
	int i;

        rcvdsip_expires = rcvdsip->expires > rcvdsip->contact_expires ? rcvdsip->expires : rcvdsip->contact_expires;
        if(rcvdsip->methodlen > 0) {
                rcvdsip_mthdstat = rcvdsip->method;
                rcvdsip_mthdstatlen = rcvdsip->methodlen;
        } else if(rcvdsip->statuslen > 0) {
                rcvdsip_mthdstat = rcvdsip->status;
                rcvdsip_mthdstatlen = rcvdsip->statuslen + rcvdsip->status_phraselen + 1;
        } else {
//              printf("[ELSE]");
//              fflush(stdout);
                return;
        }

// FOR DEBUG
//        if(rcvdsip->cause > 0 && rcvdsip->cause < 255) {
                printf("Status-Code : %.*s\n",rcvdsip->statuslen, rcvdsip->status);
                printf("Status-Phrase : %.*s\n",rcvdsip->status_phraselen, rcvdsip->status_phrase);
                printf("Method : %.*s\n",rcvdsip->methodlen, rcvdsip->method);
                printf("From username: %.*s\n",rcvdsip->from_dispnamelen, rcvdsip->from_dispname);
                printf("From user: %.*s\n",rcvdsip->from->userlen, rcvdsip->from->user);
                printf("From host: %.*s\n",rcvdsip->from->hostlen, rcvdsip->from->host);
                printf("To username: %.*s\n",rcvdsip->to_dispnamelen, rcvdsip->to_dispname);
                printf("To user: %.*s\n",rcvdsip->to->userlen, rcvdsip->to->user);
                printf("To host: %.*s\n",rcvdsip->to->hostlen, rcvdsip->to->host);
	for(i = 0; i < rcvdsip->via_count; i++) {
                printf("Via protocol: %.*s\n",rcvdsip->via[i]->sent_protolen, rcvdsip->via[i]->sent_protocol);
                printf("Via host: %.*s\n",rcvdsip->via[i]->hostlen, rcvdsip->via[i]->host);
                printf("Via maddr: %.*s\n",rcvdsip->via[i]->maddrlen, rcvdsip->via[i]->maddr);
                printf("Via received: %.*s\n",rcvdsip->via[i]->receivedlen, rcvdsip->via[i]->received);
                printf("Via branch: %.*s\n",rcvdsip->via[i]->branchlen, rcvdsip->via[i]->branch);
	}
                printf("Contact user: %.*s\n",rcvdsip->contact->userlen, rcvdsip->contact->user);
                printf("Contact host: %.*s\n",rcvdsip->contact->hostlen, rcvdsip->contact->host);
                printf("CallID : %.*s\n",rcvdsip->callidlen, rcvdsip->callid);
                printf("Cseq : %lu\n",rcvdsip->cseq);
                printf("Cseq Method : %.*s\n",rcvdsip->cseq_methodlen, rcvdsip->cseq_method);
                printf("UserAgt : %.*s\n",rcvdsip->useragtlen, rcvdsip->useragt);
                printf("Real Expires : %d\n", rcvdsip_expires);
                printf("Reason : %.*s\n", rcvdsip->reasonlen, rcvdsip->reason);
                printf("Q.850 Cause : %d\n", rcvdsip->cause);
		printf("Authorization Nonce : %.*s\n", rcvdsip->credential->nlen, rcvdsip->credential->nonce);
		printf("Authorization CNonce : \"%.*s\"\n", rcvdsip->credential->clen, rcvdsip->credential->cnonce);
                printf("Media Selected : %.*s %d %.*s %d\n", rcvdsip->sdp->m_medialen[0], rcvdsip->sdp->m_media[0], rcvdsip->sdp->m_port[0], rcvdsip->sdp->m_protolen[0], rcvdsip->sdp->m_proto[0], rcvdsip->sdp->m_fmt[0][0]);
                printf("Media Attr : %.*s\n", rcvdsip->sdp->alen[0], rcvdsip->sdp->a[0]);
                printf("Media Addr : %.*s\n", rcvdsip->sdp->o_addrlen, rcvdsip->sdp->o_addr);
                printf("Media Port : %d\n", rcvdsip->sdp->m_port[0]);
                fflush(stdout);
//        }
}

