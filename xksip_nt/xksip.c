#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include "sip_attrs.h"

#define MYPORT 5060    /* the port users will be connecting to */
#define MAXBUFLEN 40960 

void write_parsed_context(sip_attrs_t *rcvdsip);
void trying2invite(struct sockaddr_in their_addr, sip_attrs_t *rcvdsip);

int main()
{
	int total_count = 0;
	int i;
        int sockfd;
        struct sockaddr_in my_addr;    /* my address information */
        struct sockaddr_in their_addr; /* connector's address information */
        int addr_len, numbytes;
        char buf[MAXBUFLEN];
        sip_attrs_t *rcvdsip;

        if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
            perror("socket");
            exit(1);
        }

        my_addr.sin_family = AF_INET;         /* host byte order */
        my_addr.sin_port = htons(MYPORT);     /* short, network byte order */
        my_addr.sin_addr.s_addr = INADDR_ANY; /* auto-fill with my IP */
        bzero(&(my_addr.sin_zero), 8);        /* zero the rest of the struct */

        if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) \
                                                                       == -1) {
            perror("bind");
            exit(1);
        }

        addr_len = sizeof(struct sockaddr);

        /* memory allocation */
        rcvdsip = (sip_attrs_t*)malloc(sizeof(sip_attrs_t));
        rcvdsip->uri = (uri_attrs_t*)malloc(sizeof(uri_attrs_t));
        rcvdsip->from = (uri_attrs_t*)malloc(sizeof(uri_attrs_t));
        rcvdsip->to = (uri_attrs_t*)malloc(sizeof(uri_attrs_t));
        rcvdsip->contact = (uri_attrs_t*)malloc(sizeof(uri_attrs_t));
        rcvdsip->route = (uri_attrs_t*)malloc(sizeof(uri_attrs_t));
        rcvdsip->via[0] = (via_attrs_t*)malloc(sizeof(via_attrs_t));
        rcvdsip->via[1] = (via_attrs_t*)malloc(sizeof(via_attrs_t));
        rcvdsip->via[2] = (via_attrs_t*)malloc(sizeof(via_attrs_t));
        rcvdsip->via[3] = (via_attrs_t*)malloc(sizeof(via_attrs_t));
        rcvdsip->credential = (digest_attrs_t*)malloc(sizeof(digest_attrs_t));
        rcvdsip->sdp = (sdp_attrs_t*)malloc(sizeof(sdp_attrs_t));

    while(1) {
        if ((numbytes=recvfrom(sockfd, buf, MAXBUFLEN, 0, \
                           (struct sockaddr *)&their_addr, &addr_len)) == -1) {
            perror("recvfrom");
            //exit(1);
            break;
        }

        buf[numbytes] = '\0';

	sip_parse(buf, numbytes, rcvdsip);
	//write_parsed_context(rcvdsip);

// DEBUG
	//if(memcmp(rcvdsip->from->user, "0708015",7) == 0) {
		total_count++;
//		printf("count:%d\t", total_count);
        	printf("\n%.*s from %s(%d)\n",rcvdsip->methodlen, rcvdsip->method, inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port));
       	printf("==============================================\n%s\n",buf);
//	}


//	if(memcmp(rcvdsip->from->user, "0708015", 7) == 0
//		|| memcmp(rcvdsip->from->host, "samsung8015.com", 15) == 0
	if(1 == 1
	) {
		if(memcmp(rcvdsip->method, "REGISTER", rcvdsip->methodlen) == 0) {
			oksendto(their_addr, rcvdsip);
		} else if(memcmp(rcvdsip->method, "INVITE", rcvdsip->methodlen) == 0) {
			trying2invite(their_addr, rcvdsip);
			ringing2invite(their_addr, rcvdsip);
		//	sessprog2invite(their_addr, rcvdsip);
		//	sleep(5);
			ok2invite(their_addr, rcvdsip);
		} else if((memcmp(rcvdsip->method, "BYE", rcvdsip->methodlen) == 0) 
			|| (memcmp(rcvdsip->method, "CANCEL", 6) == 0)) {
			oksendto(their_addr, rcvdsip);
		} 
	} else {
		if(memcmp(rcvdsip->method, "REGISTER", 8) == 0) {
			unauthsendto(their_addr, rcvdsip);
		} else if(memcmp(rcvdsip->method, "INVITE", 6) == 0) {
			unauthsendto(their_addr, rcvdsip);
		} else if((memcmp(rcvdsip->method, "BYE", 3) == 0) 
			|| (memcmp(rcvdsip->method, "CANCEL", 6) == 0)) {
			unauthsendto(their_addr, rcvdsip);
		} 
	}


    }

        free(rcvdsip->uri);
        free(rcvdsip->from);
        free(rcvdsip->to);
        free(rcvdsip->contact);
        free(rcvdsip->route);
        free(rcvdsip->via[0]);
        free(rcvdsip->via[1]);
        free(rcvdsip->via[2]);
        free(rcvdsip->via[3]);
        free(rcvdsip->credential);
        free(rcvdsip->sdp);
        free(rcvdsip);

        close(sockfd);
}

void write_parsed_context(sip_attrs_t *rcvdsip)
{
        int rcvdsip_expires;
        const char *rcvdsip_mthdstat;
        int rcvdsip_mthdstatlen;
	int i = 0;

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
                printf("CallID : %.*s\n",rcvdsip->callidlen, rcvdsip->callid);
                printf("Cseq : %lu\n",rcvdsip->cseq);
                printf("Cseq Method : %.*s\n",rcvdsip->cseq_methodlen, rcvdsip->cseq_method);
                printf("UserAgt : %.*s\n",rcvdsip->useragtlen, rcvdsip->useragt);
                printf("Real Expires : %d\n", rcvdsip_expires);
                printf("Reason : %.*s\n", rcvdsip->reasonlen, rcvdsip->reason);
                printf("Q.850 Cause : %d\n", rcvdsip->cause);
                printf("Media Selected : %.*s %d %.*s %d\n", rcvdsip->sdp->m_medialen[0], rcvdsip->sdp->m_media[0], rcvdsip->sdp->m_port[0], rcvdsip->sdp->m_protolen[0], rcvdsip->sdp->m_proto[0], rcvdsip->sdp->m_fmt[0][0]);
                printf("Media Attr : %.*s\n", rcvdsip->sdp->alen[0], rcvdsip->sdp->a[0]);
                printf("Media Addr : %.*s\n", rcvdsip->sdp->o_addrlen, rcvdsip->sdp->o_addr);
                printf("Media Port : %d\n", rcvdsip->sdp->m_port[0]);
                fflush(stdout);
//        }
}

