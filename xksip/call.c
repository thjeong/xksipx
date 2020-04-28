#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include "sip_attrs.h"

#define BUF_SIZE 2048

int total_send = 0;
/* Typical Response without SDP */
void trying2invite(struct sockaddr_in their_addr, sip_attrs_t *rcvdsip)
{
    char buf[BUF_SIZE];
    int i = 0;

//    printf("\n******************\n", buf);
    sprintf(buf, "%.*s 100 Trying\r\n", rcvdsip->sip_versionlen, rcvdsip->sip_version);

    for(i = 0; i < rcvdsip->via_count; i++) {
    	sprintf(buf + strlen(buf), "Via: %.*s %.*s", rcvdsip->via[i]->sent_protolen, rcvdsip->via[i]->sent_protocol, rcvdsip->via[i]->hostlen, rcvdsip->via[i]->host);
    	if(rcvdsip->via[i]->port > 0) sprintf(buf + strlen(buf), ":%d", rcvdsip->via[i]->port);
    	if(rcvdsip->via[i]->branchlen > 0) sprintf(buf + strlen(buf), ";branch=%.*s", rcvdsip->via[i]->branchlen, rcvdsip->via[i]->branch);
    	if(rcvdsip->via[i]->receivedlen > 0) sprintf(buf + strlen(buf), ";received=%.*s", rcvdsip->via[i]->receivedlen, rcvdsip->via[i]->received);
    	sprintf(buf + strlen(buf), "\r\n");
    }

    sprintf(buf + strlen(buf), "To: ");
    if(rcvdsip->to_dispnamelen > 0) sprintf(buf + strlen(buf), "%.*s ", rcvdsip->to_dispnamelen, rcvdsip->to_dispname);
    sprintf(buf + strlen(buf), "<sip:%.*s@%.*s", rcvdsip->to->userlen, rcvdsip->to->user, rcvdsip->to->hostlen, rcvdsip->to->host);
    if(rcvdsip->to->port > 0) sprintf(buf + strlen(buf), ":%d", rcvdsip->to->port);
    sprintf(buf + strlen(buf), ">");
    if(rcvdsip->to_taglen > 0) sprintf(buf + strlen(buf), ";tag=%.*s", rcvdsip->to_taglen, rcvdsip->to_tag);
    sprintf(buf + strlen(buf), "\r\n");

    sprintf(buf + strlen(buf), "From: ");
    if(rcvdsip->from_dispnamelen > 0) sprintf(buf + strlen(buf), "%.*s ", rcvdsip->from_dispnamelen, rcvdsip->from_dispname);
    sprintf(buf + strlen(buf), "<sip:%.*s@%.*s", rcvdsip->from->userlen, rcvdsip->from->user, rcvdsip->from->hostlen, rcvdsip->from->host);
    if(rcvdsip->from->port > 0) sprintf(buf + strlen(buf), ":%d", rcvdsip->from->port);
    sprintf(buf + strlen(buf), ">");

    if(rcvdsip->from_taglen > 0) sprintf(buf + strlen(buf), ";tag=%.*s", rcvdsip->from_taglen, rcvdsip->from_tag);
    sprintf(buf + strlen(buf), "\r\n");
    sprintf(buf + strlen(buf), "Call-ID: %.*s\r\n", rcvdsip->callidlen, rcvdsip->callid);
    sprintf(buf + strlen(buf), "CSeq: %d INVITE\r\n", rcvdsip->cseq);
    sprintf(buf + strlen(buf), "Content-Length: 0\r\n");
    sprintf(buf + strlen(buf), "\r\n");
    //printf("%s\n******************\n", buf);
    //fflush(stdout);
    shoot(their_addr, buf, rcvdsip);
    //shoot(their_addr, buf);
}

/* Typical Response without SDP */
void ringing2invite(struct sockaddr_in their_addr, sip_attrs_t *rcvdsip)
{
    char buf[BUF_SIZE];
    int i = 0;

    // printf("\n******************\n", buf);
    sprintf(buf, "%.*s 180 Ringing\r\n", rcvdsip->sip_versionlen, rcvdsip->sip_version);

    for(i = 0; i < rcvdsip->via_count; i++) {
    	sprintf(buf + strlen(buf), "Via: %.*s %.*s", rcvdsip->via[i]->sent_protolen, rcvdsip->via[i]->sent_protocol, rcvdsip->via[i]->hostlen, rcvdsip->via[i]->host);
    	if(rcvdsip->via[i]->port > 0) sprintf(buf + strlen(buf), ":%d", rcvdsip->via[i]->port);
    	if(rcvdsip->via[i]->branchlen > 0) sprintf(buf + strlen(buf), ";branch=%.*s", rcvdsip->via[i]->branchlen, rcvdsip->via[i]->branch);
    	if(rcvdsip->via[i]->receivedlen > 0) sprintf(buf + strlen(buf), ";received=%.*s", rcvdsip->via[i]->receivedlen, rcvdsip->via[i]->received);
    	sprintf(buf + strlen(buf), "\r\n");
    }
/*
    sprintf(buf + strlen(buf), "Via: %.*s %.*s", rcvdsip->via->sent_protolen, rcvdsip->via->sent_protocol, rcvdsip->via->hostlen, rcvdsip->via->host);
    if(rcvdsip->via->port > 0) sprintf(buf + strlen(buf), ":%d", rcvdsip->via->port);
    if(rcvdsip->via->branchlen > 0) sprintf(buf + strlen(buf), ";branch=%.*s", rcvdsip->via->branchlen, rcvdsip->via->branch);
    if(rcvdsip->via->receivedlen > 0) sprintf(buf + strlen(buf), ";received=%.*s", rcvdsip->via->receivedlen, rcvdsip->via->received);
    sprintf(buf + strlen(buf), "\r\n");
*/

    sprintf(buf + strlen(buf), "To: ");
    if(rcvdsip->to_dispnamelen > 0) sprintf(buf + strlen(buf), "%.*s ", rcvdsip->to_dispnamelen, rcvdsip->to_dispname);
    sprintf(buf + strlen(buf), "<sip:%.*s@%.*s", rcvdsip->to->userlen, rcvdsip->to->user, rcvdsip->to->hostlen, rcvdsip->to->host);
    if(rcvdsip->to->port > 0) sprintf(buf + strlen(buf), ":%d", rcvdsip->to->port);
    sprintf(buf + strlen(buf), ">");
    if(rcvdsip->to_taglen > 0) sprintf(buf + strlen(buf), ";tag=%.*s", rcvdsip->to_taglen, rcvdsip->to_tag);
    else sprintf(buf + strlen(buf), ";tag=xkstyle");
    sprintf(buf + strlen(buf), "\r\n");

    sprintf(buf + strlen(buf), "From: ");
    if(rcvdsip->from_dispnamelen > 0) sprintf(buf + strlen(buf), "%.*s ", rcvdsip->from_dispnamelen, rcvdsip->from_dispname);
    sprintf(buf + strlen(buf), "<sip:%.*s@%.*s", rcvdsip->from->userlen, rcvdsip->from->user, rcvdsip->from->hostlen, rcvdsip->from->host);
    if(rcvdsip->from->port > 0) sprintf(buf + strlen(buf), ":%d", rcvdsip->from->port);
    sprintf(buf + strlen(buf), ">");
    if(rcvdsip->from_taglen > 0) sprintf(buf + strlen(buf), ";tag=%.*s", rcvdsip->from_taglen, rcvdsip->from_tag);
    sprintf(buf + strlen(buf), "\r\n");

    sprintf(buf + strlen(buf), "Call-ID: %.*s\r\n", rcvdsip->callidlen, rcvdsip->callid);

    sprintf(buf + strlen(buf), "Contact: <sip:203.254.203.101:5060>\r\n");
/*
    sprintf(buf + strlen(buf), "Contact: ");
    sprintf(buf + strlen(buf), "%.*s ", rcvdsip->contact_dispnamelen, rcvdsip->contact_dispname);
    sprintf(buf + strlen(buf), "<sip:%.*s@%.*s:%d>", rcvdsip->contact->userlen, rcvdsip->contact->user, rcvdsip->contact->hostlen, rcvdsip->contact->host, rcvdsip->contact->port);
    sprintf(buf + strlen(buf), "\r\n");
*/

    sprintf(buf + strlen(buf), "CSeq: %d INVITE\r\n", rcvdsip->cseq);
    sprintf(buf + strlen(buf), "Content-Length: 0\r\n");
    sprintf(buf + strlen(buf), "\r\n");
    //printf("%s\n******************\n", buf);
    //fflush(stdout);
    //shoot(their_addr, buf);
    shoot(their_addr, buf, rcvdsip);
}

/* Typical Response without SDP */
void oksendto(struct sockaddr_in their_addr, sip_attrs_t *rcvdsip)
{
    char buf[BUF_SIZE];
    int i = 0;

    //printf("\n******************\n", buf);
    sprintf(buf, "%.*s 200 OK\r\n", rcvdsip->sip_versionlen, rcvdsip->sip_version);

    for(i = 0; i < rcvdsip->via_count; i++) {
    	sprintf(buf + strlen(buf), "Via: %.*s %.*s", rcvdsip->via[i]->sent_protolen, rcvdsip->via[i]->sent_protocol, rcvdsip->via[i]->hostlen, rcvdsip->via[i]->host);
    	if(rcvdsip->via[i]->port > 0) sprintf(buf + strlen(buf), ":%d", rcvdsip->via[i]->port);
    	if(rcvdsip->via[i]->branchlen > 0) sprintf(buf + strlen(buf), ";branch=%.*s", rcvdsip->via[i]->branchlen, rcvdsip->via[i]->branch);
    	if(rcvdsip->via[i]->receivedlen > 0) sprintf(buf + strlen(buf), ";received=%.*s", rcvdsip->via[i]->receivedlen, rcvdsip->via[i]->received);
    	sprintf(buf + strlen(buf), "\r\n");
    }
/*
    sprintf(buf + strlen(buf), "Via: %.*s %.*s", rcvdsip->via->sent_protolen, rcvdsip->via->sent_protocol, rcvdsip->via->hostlen, rcvdsip->via->host);
    if(rcvdsip->via->port > 0) sprintf(buf + strlen(buf), ":%d", rcvdsip->via->port);
    if(rcvdsip->via->branchlen > 0) sprintf(buf + strlen(buf), ";branch=%.*s", rcvdsip->via->branchlen, rcvdsip->via->branch);
    if(rcvdsip->via->receivedlen > 0) sprintf(buf + strlen(buf), ";received=%.*s", rcvdsip->via->receivedlen, rcvdsip->via->received);
    sprintf(buf + strlen(buf), "\r\n");
*/

    sprintf(buf + strlen(buf), "To: ");
    if(rcvdsip->to_dispnamelen > 0) sprintf(buf + strlen(buf), "%.*s ", rcvdsip->to_dispnamelen, rcvdsip->to_dispname);
    sprintf(buf + strlen(buf), "<sip:%.*s@%.*s", rcvdsip->to->userlen, rcvdsip->to->user, rcvdsip->to->hostlen, rcvdsip->to->host);
    if(rcvdsip->to->port > 0) sprintf(buf + strlen(buf), ":%d", rcvdsip->to->port);
    sprintf(buf + strlen(buf), ">");
    if(rcvdsip->to_taglen > 0) sprintf(buf + strlen(buf), ";tag=%.*s", rcvdsip->to_taglen, rcvdsip->to_tag);
    else sprintf(buf + strlen(buf), ";tag=xkstyle");
    sprintf(buf + strlen(buf), "\r\n");

    sprintf(buf + strlen(buf), "From: ");
    if(rcvdsip->from_dispnamelen > 0) sprintf(buf + strlen(buf), "%.*s ", rcvdsip->from_dispnamelen, rcvdsip->from_dispname);
    sprintf(buf + strlen(buf), "<sip:%.*s@%.*s", rcvdsip->from->userlen, rcvdsip->from->user, rcvdsip->from->hostlen, rcvdsip->from->host);
    if(rcvdsip->from->port > 0) sprintf(buf + strlen(buf), ":%d", rcvdsip->from->port);
    sprintf(buf + strlen(buf), ">");
    if(rcvdsip->from_taglen > 0) sprintf(buf + strlen(buf), ";tag=%.*s", rcvdsip->from_taglen, rcvdsip->from_tag);
    sprintf(buf + strlen(buf), "\r\n");

    sprintf(buf + strlen(buf), "Call-ID: %.*s\r\n", rcvdsip->callidlen, rcvdsip->callid);
//    sprintf(buf + strlen(buf), "Contact: <sip:203.254.203.101:5060>\r\n");

    if(rcvdsip->contact->userlen > 0) {
        sprintf(buf + strlen(buf), "Contact: ");
        if(rcvdsip->contact_dispnamelen > 0) sprintf(buf + strlen(buf), "%.*s ", rcvdsip->contact_dispnamelen, rcvdsip->contact_dispname);
        sprintf(buf + strlen(buf), "<sip:%.*s@%.*s", rcvdsip->contact->userlen, rcvdsip->contact->user, rcvdsip->contact->hostlen, rcvdsip->contact->host);
        if(rcvdsip->contact->port > 0) sprintf(buf + strlen(buf), ":%d", rcvdsip->contact->port);
        sprintf(buf + strlen(buf), ">");
        if(rcvdsip->contact_expires > 0) sprintf(buf + strlen(buf), ";expires=%d", rcvdsip->contact_expires);
        sprintf(buf + strlen(buf), "\r\n");
    }

    sprintf(buf + strlen(buf), "CSeq: %d %.*s\r\n", rcvdsip->cseq, rcvdsip->methodlen, rcvdsip->method);
    sprintf(buf + strlen(buf), "Content-Length: 0\r\n");
    sprintf(buf + strlen(buf), "\r\n");
    //printf("%s\n******************\n", buf);
    //fflush(stdout);
    //shoot(their_addr, buf);
    shoot(their_addr, buf, rcvdsip);
}

/* Typical Response without SDP */
void unauthsendto(struct sockaddr_in their_addr, sip_attrs_t *rcvdsip)
{
    char buf[BUF_SIZE];
    int i = 0;

    //printf("\n******************\n", buf);
    sprintf(buf, "%.*s 401 Unauthorized\r\n", rcvdsip->sip_versionlen, rcvdsip->sip_version);

    for(i = 0; i < rcvdsip->via_count; i++) {
    	sprintf(buf + strlen(buf), "Via: %.*s %.*s", rcvdsip->via[i]->sent_protolen, rcvdsip->via[i]->sent_protocol, rcvdsip->via[i]->hostlen, rcvdsip->via[i]->host);
    	if(rcvdsip->via[i]->port > 0) sprintf(buf + strlen(buf), ":%d", rcvdsip->via[i]->port);
    	if(rcvdsip->via[i]->branchlen > 0) sprintf(buf + strlen(buf), ";branch=%.*s", rcvdsip->via[i]->branchlen, rcvdsip->via[i]->branch);
    	if(rcvdsip->via[i]->receivedlen > 0) sprintf(buf + strlen(buf), ";received=%.*s", rcvdsip->via[i]->receivedlen, rcvdsip->via[i]->received);
    	sprintf(buf + strlen(buf), "\r\n");
    }
/*
    sprintf(buf + strlen(buf), "Via: %.*s %.*s", rcvdsip->via->sent_protolen, rcvdsip->via->sent_protocol, rcvdsip->via->hostlen, rcvdsip->via->host);
    if(rcvdsip->via->port > 0) sprintf(buf + strlen(buf), ":%d", rcvdsip->via->port);
    if(rcvdsip->via->branchlen > 0) sprintf(buf + strlen(buf), ";branch=%.*s", rcvdsip->via->branchlen, rcvdsip->via->branch);
    if(rcvdsip->via->receivedlen > 0) sprintf(buf + strlen(buf), ";received=%.*s", rcvdsip->via->receivedlen, rcvdsip->via->received);
    sprintf(buf + strlen(buf), "\r\n");
*/

    sprintf(buf + strlen(buf), "To: ");
    if(rcvdsip->to_dispnamelen > 0) sprintf(buf + strlen(buf), "%.*s ", rcvdsip->to_dispnamelen, rcvdsip->to_dispname);
    sprintf(buf + strlen(buf), "<sip:%.*s@%.*s", rcvdsip->to->userlen, rcvdsip->to->user, rcvdsip->to->hostlen, rcvdsip->to->host);
    if(rcvdsip->to->port > 0) sprintf(buf + strlen(buf), ":%d", rcvdsip->to->port);
    sprintf(buf + strlen(buf), ">");
    if(rcvdsip->to_taglen > 0) sprintf(buf + strlen(buf), ";tag=%.*s", rcvdsip->to_taglen, rcvdsip->to_tag);
    // else sprintf(buf + strlen(buf), ";tag=xkstyle");
    sprintf(buf + strlen(buf), "\r\n");

    sprintf(buf + strlen(buf), "From: ");
    if(rcvdsip->from_dispnamelen > 0) sprintf(buf + strlen(buf), "%.*s ", rcvdsip->from_dispnamelen, rcvdsip->from_dispname);
    sprintf(buf + strlen(buf), "<sip:%.*s@%.*s", rcvdsip->from->userlen, rcvdsip->from->user, rcvdsip->from->hostlen, rcvdsip->from->host);
    if(rcvdsip->from->port > 0) sprintf(buf + strlen(buf), ":%d", rcvdsip->from->port);
    sprintf(buf + strlen(buf), ">");
    if(rcvdsip->from_taglen > 0) sprintf(buf + strlen(buf), ";tag=%.*s", rcvdsip->from_taglen, rcvdsip->from_tag);
    sprintf(buf + strlen(buf), "\r\n");

    sprintf(buf + strlen(buf), "Call-ID: %.*s\r\n", rcvdsip->callidlen, rcvdsip->callid);
    sprintf(buf + strlen(buf), "Contact: ");
    sprintf(buf + strlen(buf), "%.*s ", rcvdsip->contact_dispnamelen, rcvdsip->contact_dispname);
    sprintf(buf + strlen(buf), "<sip:%.*s@%.*s:%d>", rcvdsip->contact->userlen, rcvdsip->contact->user, rcvdsip->contact->hostlen, rcvdsip->contact->host, rcvdsip->contact->port);
    sprintf(buf + strlen(buf), "\r\n");
    sprintf(buf + strlen(buf), "CSeq: %d %.*s\r\n", rcvdsip->cseq, rcvdsip->methodlen, rcvdsip->method);
    sprintf(buf + strlen(buf), "Content-Length: 0\r\n");
    sprintf(buf + strlen(buf), "\r\n");
    //printf("%s\n******************\n", buf);
    //fflush(stdout);
    shoot(their_addr, buf, rcvdsip);
    //shoot(their_addr, buf);
}

void sessprog2invite(struct sockaddr_in their_addr, sip_attrs_t *rcvdsip)
{
    char buf[BUF_SIZE];
    int i = 0;
    char sdp_buf[BUF_SIZE];

    //printf("\n******************\n", buf);
    sprintf(buf, "%.*s 183 Session Progress\r\n", rcvdsip->sip_versionlen, rcvdsip->sip_version);

    for(i = 0; i < rcvdsip->via_count; i++) {
    	sprintf(buf + strlen(buf), "Via: %.*s %.*s", rcvdsip->via[i]->sent_protolen, rcvdsip->via[i]->sent_protocol, rcvdsip->via[i]->hostlen, rcvdsip->via[i]->host);
    	if(rcvdsip->via[i]->port > 0) sprintf(buf + strlen(buf), ":%d", rcvdsip->via[i]->port);
    	if(rcvdsip->via[i]->branchlen > 0) sprintf(buf + strlen(buf), ";branch=%.*s", rcvdsip->via[i]->branchlen, rcvdsip->via[i]->branch);
    	if(rcvdsip->via[i]->receivedlen > 0) sprintf(buf + strlen(buf), ";received=%.*s", rcvdsip->via[i]->receivedlen, rcvdsip->via[i]->received);
    	sprintf(buf + strlen(buf), "\r\n");
    }
/*
    sprintf(buf + strlen(buf), "Via: %.*s %.*s", rcvdsip->via->sent_protolen, rcvdsip->via->sent_protocol, rcvdsip->via->hostlen, rcvdsip->via->host);
    if(rcvdsip->via->port > 0) sprintf(buf + strlen(buf), ":%d", rcvdsip->via->port);
    if(rcvdsip->via->branchlen > 0) sprintf(buf + strlen(buf), ";branch=%.*s", rcvdsip->via->branchlen, rcvdsip->via->branch);
    if(rcvdsip->via->receivedlen > 0) sprintf(buf + strlen(buf), ";received=%.*s", rcvdsip->via->receivedlen, rcvdsip->via->received);
    sprintf(buf + strlen(buf), "\r\n");
*/

    sprintf(buf + strlen(buf), "To: ");
    if(rcvdsip->to_dispnamelen > 0) sprintf(buf + strlen(buf), "%.*s ", rcvdsip->to_dispnamelen, rcvdsip->to_dispname);
    sprintf(buf + strlen(buf), "<sip:%.*s@%.*s", rcvdsip->to->userlen, rcvdsip->to->user, rcvdsip->to->hostlen, rcvdsip->to->host);
    if(rcvdsip->to->port > 0) sprintf(buf + strlen(buf), ":%d", rcvdsip->to->port);
    sprintf(buf + strlen(buf), ">");
    if(rcvdsip->to_taglen > 0) sprintf(buf + strlen(buf), ";tag=%.*s", rcvdsip->to_taglen, rcvdsip->to_tag);
    // else sprintf(buf + strlen(buf), ";tag=xkstyle");
    sprintf(buf + strlen(buf), "\r\n");

    sprintf(buf + strlen(buf), "From: ");
    if(rcvdsip->from_dispnamelen > 0) sprintf(buf + strlen(buf), "%.*s ", rcvdsip->from_dispnamelen, rcvdsip->from_dispname);
    sprintf(buf + strlen(buf), "<sip:%.*s@%.*s", rcvdsip->from->userlen, rcvdsip->from->user, rcvdsip->from->hostlen, rcvdsip->from->host);
    if(rcvdsip->from->port > 0) sprintf(buf + strlen(buf), ":%d", rcvdsip->from->port);
    sprintf(buf + strlen(buf), ">");
    if(rcvdsip->from_taglen > 0) sprintf(buf + strlen(buf), ";tag=%.*s", rcvdsip->from_taglen, rcvdsip->from_tag);
    sprintf(buf + strlen(buf), "\r\n");

    sprintf(buf + strlen(buf), "Call-ID: %.*s\r\n", rcvdsip->callidlen, rcvdsip->callid);
    sprintf(buf + strlen(buf), "Contact: ");
    sprintf(buf + strlen(buf), "%.*s ", rcvdsip->contact_dispnamelen, rcvdsip->contact_dispname);
    sprintf(buf + strlen(buf), "<sip:%.*s@%.*s:%d>", rcvdsip->contact->userlen, rcvdsip->contact->user, rcvdsip->contact->hostlen, rcvdsip->contact->host, rcvdsip->contact->port);
    sprintf(buf + strlen(buf), "\r\n");
    sprintf(buf + strlen(buf), "CSeq: %d INVITE\r\n", rcvdsip->cseq);
    sprintf(buf + strlen(buf), "Content-Type: application/sdp\r\n");

    sprintf(buf + strlen(buf), "Content-Length: %d\r\n", sdpbuild(sdp_buf, rcvdsip));
    sprintf(buf + strlen(buf), "\r\n");
    sprintf(buf + strlen(buf), "%s", sdp_buf);
    //printf("%s\n******************\n", buf);
    //fflush(stdout);
    shoot(their_addr, buf, rcvdsip);
    //shoot(their_addr, buf);
}

void ok2invite(struct sockaddr_in their_addr, sip_attrs_t *rcvdsip)
{
    char buf[BUF_SIZE];
    int i = 0;
    char sdp_buf[BUF_SIZE];

    //printf("\n******************\n", buf);
    sprintf(buf, "%.*s 200 OK\r\n", rcvdsip->sip_versionlen, rcvdsip->sip_version);

    for(i = 0; i < rcvdsip->via_count; i++) {
    	sprintf(buf + strlen(buf), "Via: %.*s %.*s", rcvdsip->via[i]->sent_protolen, rcvdsip->via[i]->sent_protocol, rcvdsip->via[i]->hostlen, rcvdsip->via[i]->host);
    	if(rcvdsip->via[i]->port > 0) sprintf(buf + strlen(buf), ":%d", rcvdsip->via[i]->port);
    	if(rcvdsip->via[i]->branchlen > 0) sprintf(buf + strlen(buf), ";branch=%.*s", rcvdsip->via[i]->branchlen, rcvdsip->via[i]->branch);
    	if(rcvdsip->via[i]->receivedlen > 0) sprintf(buf + strlen(buf), ";received=%.*s", rcvdsip->via[i]->receivedlen, rcvdsip->via[i]->received);
    	sprintf(buf + strlen(buf), "\r\n");
    }
/*
    sprintf(buf + strlen(buf), "Via: %.*s %.*s", rcvdsip->via->sent_protolen, rcvdsip->via->sent_protocol, rcvdsip->via->hostlen, rcvdsip->via->host);
    if(rcvdsip->via->port > 0) sprintf(buf + strlen(buf), ":%d", rcvdsip->via->port);
    if(rcvdsip->via->branchlen > 0) sprintf(buf + strlen(buf), ";branch=%.*s", rcvdsip->via->branchlen, rcvdsip->via->branch);
    if(rcvdsip->via->receivedlen > 0) sprintf(buf + strlen(buf), ";received=%.*s", rcvdsip->via->receivedlen, rcvdsip->via->received);
    sprintf(buf + strlen(buf), "\r\n");
*/

    sprintf(buf + strlen(buf), "To: ");
    if(rcvdsip->to_dispnamelen > 0) sprintf(buf + strlen(buf), "%.*s ", rcvdsip->to_dispnamelen, rcvdsip->to_dispname);
    sprintf(buf + strlen(buf), "<sip:%.*s@%.*s", rcvdsip->to->userlen, rcvdsip->to->user, rcvdsip->to->hostlen, rcvdsip->to->host);
    if(rcvdsip->to->port > 0) sprintf(buf + strlen(buf), ":%d", rcvdsip->to->port);
    sprintf(buf + strlen(buf), ">");
    if(rcvdsip->to_taglen > 0) sprintf(buf + strlen(buf), ";tag=%.*s", rcvdsip->to_taglen, rcvdsip->to_tag);
    // else sprintf(buf + strlen(buf), ";tag=xkstyle");
    sprintf(buf + strlen(buf), "\r\n");

    sprintf(buf + strlen(buf), "From: ");
    if(rcvdsip->from_dispnamelen > 0) sprintf(buf + strlen(buf), "%.*s ", rcvdsip->from_dispnamelen, rcvdsip->from_dispname);
    sprintf(buf + strlen(buf), "<sip:%.*s@%.*s", rcvdsip->from->userlen, rcvdsip->from->user, rcvdsip->from->hostlen, rcvdsip->from->host);
    if(rcvdsip->from->port > 0) sprintf(buf + strlen(buf), ":%d", rcvdsip->from->port);
    sprintf(buf + strlen(buf), ">");
    if(rcvdsip->from_taglen > 0) sprintf(buf + strlen(buf), ";tag=%.*s", rcvdsip->from_taglen, rcvdsip->from_tag);
    sprintf(buf + strlen(buf), "\r\n");

    sprintf(buf + strlen(buf), "Call-ID: %.*s\r\n", rcvdsip->callidlen, rcvdsip->callid);

    sprintf(buf + strlen(buf), "Contact: <sip:203.254.203.101:5060>\r\n");
/*
    sprintf(buf + strlen(buf), "Contact: ");
    sprintf(buf + strlen(buf), "%.*s ", rcvdsip->contact_dispnamelen, rcvdsip->contact_dispname);
    sprintf(buf + strlen(buf), "<sip:%.*s@%.*s:%d>", rcvdsip->contact->userlen, rcvdsip->contact->user, rcvdsip->contact->hostlen, rcvdsip->contact->host, rcvdsip->contact->port);
    sprintf(buf + strlen(buf), "\r\n");
*/
    sprintf(buf + strlen(buf), "CSeq: %d INVITE\r\n", rcvdsip->cseq);
    sprintf(buf + strlen(buf), "Content-Type: application/sdp\r\n");

    sprintf(buf + strlen(buf), "Content-Length: %d\r\n", sdpbuild(sdp_buf, rcvdsip));
    sprintf(buf + strlen(buf), "\r\n");
    sprintf(buf + strlen(buf), "%s", sdp_buf);
    //printf("%s\n******************\n", buf);
    //fflush(stdout);
    shoot(their_addr, buf, rcvdsip);
}

int sdpbuild(char msg[], sip_attrs_t* rcvdsip)
{
	int i = 0;

	sprintf(msg, "v=0\r\n");
	sprintf(msg + strlen(msg), "o=XkstyleSIP-GW-UserAgent 2379 5581 IN IP 203.254.203.203\r\n");
	sprintf(msg + strlen(msg), "s=SIP Call\r\n");
	sprintf(msg + strlen(msg), "c=IN IP4 203.254.203.203\r\n");
	sprintf(msg + strlen(msg), "t=0 0\r\n");
	sprintf(msg + strlen(msg), "m=%.*s %d %.*s %d\r\n", rcvdsip->sdp->m_medialen[0], rcvdsip->sdp->m_media[0], rcvdsip->sdp->m_port[0], rcvdsip->sdp->m_protolen[0], rcvdsip->sdp->m_proto[0], rcvdsip->sdp->m_fmt[0][0]);
	sprintf(msg + strlen(msg), "c=IN IP4 203.254.203.203\r\n");
    for(i = 0; i < rcvdsip->sdp->a_count; i++) {
	sprintf(msg + strlen(msg), "a=%.*s\r\n", rcvdsip->sdp->alen[i], rcvdsip->sdp->a[i]);
//	sprintf(msg + strlen(msg), "\r\n");
    }
	//sprintf(msg + strlen(msg), "a=sendrecv\r\n");
//	sprintf(msg + strlen(msg), "\r\n");
	return strlen(msg);
}

int shoot(struct sockaddr_in their_addr, char *msg[], sip_attrs_t* rcvdsip)
{
        int sockfd;
//        struct sockaddr_in their_addr; /* connector's address information */
        int numbytes;

        if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
            perror("socket");
            exit(1);
        }

        if ((numbytes=sendto(sockfd, msg, strlen(msg), 0, \
             (struct sockaddr *)&their_addr, sizeof(struct sockaddr))) == -1) {
            perror("sendto");
            exit(1);
        }
	total_send++;
//	printf("sent:%d\n", total_send);
//	fflush(stdout);

/* DEBUG */
//	if(memcmp(rcvdsip->from->user, "07080150001",11) == 0 || memcmp(rcvdsip->to->user, "07080150001",11) == 0) {
        	printf("%.*s to %s(%d)\n", 6, msg + 2, inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port));
		printf("**************************************************\n%s\n", msg);
//	}

        close(sockfd);

        return 0;
}
