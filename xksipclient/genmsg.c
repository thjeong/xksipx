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
#include "digcalc.h"

#define BUF_SIZE 2048

void* calcresponse(char *resp, sip_attrs_t *rcvdsip);

/* Typical Trying to regist */
int buildreg(char* buf, sip_attrs_t *rcvdsip, int flag)
{
//    char buf[BUF_SIZE];
    int i = 0;
    int numbytes;
    char tmpbuf[2048];
    char resp[128];
    FILE *fp;

    if(flag == 0) {
	fp = fopen("REGISTER.MSG", "r");
	numbytes = fread(tmpbuf, 1, BUF_SIZE, fp);
	fclose(fp);

//	printf("READ MESSAGE FILE (%d bytes) ***\n%s\n", numbytes, buf);
	sip_parse(tmpbuf, numbytes, rcvdsip);
    }

    sprintf(buf, "REGISTER sip:sniproxy.samsung070.com:5060 SIP/2.0\r\n");

    sprintf(buf + strlen(buf), "Max-Forwards: 70\r\n");

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
    else if(flag < 0) sprintf(buf + strlen(buf), ";tag=xkstyle");
    sprintf(buf + strlen(buf), "\r\n");

    sprintf(buf + strlen(buf), "From: ");
    if(rcvdsip->from_dispnamelen > 0) sprintf(buf + strlen(buf), "%.*s ", rcvdsip->from_dispnamelen, rcvdsip->from_dispname);
    sprintf(buf + strlen(buf), "<sip:%.*s@%.*s", rcvdsip->from->userlen, rcvdsip->from->user, rcvdsip->from->hostlen, rcvdsip->from->host);
    if(rcvdsip->from->port > 0) sprintf(buf + strlen(buf), ":%d", rcvdsip->from->port);
    sprintf(buf + strlen(buf), ">");
    if(rcvdsip->from_taglen > 0) sprintf(buf + strlen(buf), ";tag=%.*s", rcvdsip->from_taglen, rcvdsip->from_tag);
    sprintf(buf + strlen(buf), "\r\n");

    sprintf(buf + strlen(buf), "Call-ID: %.*s\r\n", rcvdsip->callidlen, rcvdsip->callid);

    if(rcvdsip->contact->userlen > 0) {
        sprintf(buf + strlen(buf), "Contact: ");
        if(rcvdsip->contact_dispnamelen > 0) sprintf(buf + strlen(buf), "%.*s ", rcvdsip->contact_dispnamelen, rcvdsip->contact_dispname);
        sprintf(buf + strlen(buf), "<sip:%.*s@%.*s", rcvdsip->contact->userlen, rcvdsip->contact->user, rcvdsip->contact->hostlen, rcvdsip->contact->host);
        if(rcvdsip->contact->port > 0) sprintf(buf + strlen(buf), ":%d", rcvdsip->contact->port);
        sprintf(buf + strlen(buf), ">");
        if(rcvdsip->contact_expires > 0) sprintf(buf + strlen(buf), ";expires=%d", rcvdsip->contact_expires);
        sprintf(buf + strlen(buf), "\r\n");
    }
    // for UAS
    else {
        sprintf(buf + strlen(buf), "Contact: ");
        if(rcvdsip->from_dispnamelen > 0) sprintf(buf + strlen(buf), "%.*s ", rcvdsip->from_dispnamelen, rcvdsip->from_dispname);
        //sprintf(buf + strlen(buf), "<sip:%.*s@%.*s", rcvdsip->from->userlen, rcvdsip->from->user, rcvdsip->from->hostlen, rcvdsip->from->host);
        sprintf(buf + strlen(buf), "<sip:%.*s@192.168.1.3", rcvdsip->from->userlen, rcvdsip->from->user);
        if(rcvdsip->from->port > 0) sprintf(buf + strlen(buf), ":%d", rcvdsip->from->port);
        sprintf(buf + strlen(buf), ">");
        if(rcvdsip->contact_expires > 0) sprintf(buf + strlen(buf), ";expires=%d", rcvdsip->contact_expires);
        sprintf(buf + strlen(buf), "\r\n");
    }

    // cseq plus 1
    sprintf(buf + strlen(buf), "CSeq: %d %.*s\r\n", rcvdsip->cseq + 1, rcvdsip->cseq_methodlen, rcvdsip->cseq_method);

	if(rcvdsip->contact_expires <= 0) {
		sprintf(buf + strlen(buf), "Expires: %d\n", 3600);
	}

//Authorization:Digest response="c111473c281ccb9b7ba4aee4028c6ff7",nc=00000369,username="07070156894",realm="BroadWorks",nonce="BroadWorksXftmwc4gmTyqqjx8BW",algorithm=MD5,qop=auth,cnonce="1a398f883af0ff817907027f06911dd3",uri="sip:sniproxy.samsung070.com:5060"

	// Authorizing
        if(rcvdsip->credential->nlen > 0) {
		calcresponse(resp, rcvdsip);
        //	sprintf(buf + strlen(buf), "WWW-Authenticate: Digest ");
		sprintf(buf + strlen(buf), "Authorization: Digest ");
		sprintf(buf + strlen(buf), "response=\"%s\"", resp);
		sprintf(buf + strlen(buf), ",username=\"%.*s\",realm=\"%.*s\",nonce=\"%.*s\"", rcvdsip->credential->ulen, rcvdsip->credential->user, rcvdsip->credential->rlen, rcvdsip->credential->realm, rcvdsip->credential->nlen, rcvdsip->credential->nonce);
		if(rcvdsip->credential->clen > 0) {
			sprintf(buf + strlen(buf), ",cnonce=\"%.*s\"", rcvdsip->credential->clen, rcvdsip->credential->cnonce);
		}

		if(rcvdsip->credential->urilen > 0) {
			sprintf(buf + strlen(buf), ",uri=\"%.*s\"", rcvdsip->credential->urilen, rcvdsip->credential->uri);
		}
		sprintf(buf + strlen(buf), ",algorithm=MD5");
		sprintf(buf + strlen(buf), ",nc=00000001,qop=auth\r\n");
	}

	sprintf(buf + strlen(buf), "Content-Length: 0\r\n");
	sprintf(buf + strlen(buf), "\r\n");

	return strlen(buf);
}

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
    shoot(their_addr, buf);
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
    shoot(their_addr, buf);
}

/* Typical Response without SDP */
void oksendto(struct sockaddr_in their_addr, sip_attrs_t *rcvdsip)
{
    char buf[BUF_SIZE];
    int i = 0;

    sprintf(buf, "%.*s 200 OK\r\n", rcvdsip->sip_versionlen, rcvdsip->sip_version);

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
    shoot(their_addr, buf);
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
    shoot(their_addr, buf);
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

    sprintf(buf + strlen(buf), "Content-Length: %d\r\n", buildsdp(sdp_buf, rcvdsip));
    sprintf(buf + strlen(buf), "\r\n");
    sprintf(buf + strlen(buf), "%s", sdp_buf);
    //printf("%s\n******************\n", buf);
    //fflush(stdout);
    shoot(their_addr, buf);
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

    sprintf(buf + strlen(buf), "Content-Length: %d\r\n", buildsdp(sdp_buf, rcvdsip));
    sprintf(buf + strlen(buf), "\r\n");
    sprintf(buf + strlen(buf), "%s", sdp_buf);
    //printf("%s\n******************\n", buf);
    //fflush(stdout);
    shoot(their_addr, buf);
}

int buildsdp(char msg[], sip_attrs_t* rcvdsip)
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

int shoot(struct sockaddr_in their_addr, char *msg)
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

//       	printf("%.*s to %s(%d)\n", 6, msg + 2, inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port));
	printf("**************************************************\n%s\n", msg);

        close(sockfd);

        return 0;
}


#define FIELDMAX    64

void* calcresponse(char *resp, sip_attrs_t *rcvdsip)
{
	digest_attrs_t *sipauth = rcvdsip->credential;
static char pszNonce[FIELDMAX];
static char pszCNonce[FIELDMAX];
static char pszRealm[FIELDMAX];
static char pszQop[FIELDMAX];
static char pszUser[FIELDMAX];
static char pszURI[FIELDMAX];
static char pszPass[FIELDMAX];
static char pszAlg[FIELDMAX];
static char szNonceCount[9] = "00000001";
static char pszMethod[FIELDMAX];
HASHHEX HA1;
HASHHEX HA2 = "";
const HASHHEX Response; // cur를 적용하지 않으면 multiuser환경에서 오류생길 것으로 추측됨. 

if(sipauth->nlen > 0 && sipauth->nlen < FIELDMAX) sprintf(pszNonce, "%.*s", sipauth->nlen, sipauth->nonce);
else return;

if(rcvdsip->cseq_methodlen > 0 && rcvdsip->cseq_methodlen < FIELDMAX) sprintf(pszMethod, "%.*s", rcvdsip->cseq_methodlen, rcvdsip->cseq_method);
else return;

if(sipauth->clen > 0 && sipauth->clen < FIELDMAX) sprintf(pszCNonce, "%.*s", sipauth->clen, sipauth->cnonce);
else {
    sprintf(pszCNonce, "0a4f113b");
    sipauth->cnonce = pszCNonce;
    sipauth->clen = strlen(pszCNonce);
}

if(sipauth->ulen > 0 && sipauth->ulen < FIELDMAX) sprintf(pszUser, "%.*s", sipauth->ulen, sipauth->user);
else {
    sprintf(pszUser, "%.*s", rcvdsip->from->userlen, rcvdsip->from->user);
    sipauth->user = rcvdsip->from->user;
    sipauth->ulen = rcvdsip->from->userlen;
}

if(sipauth->alen > 0 && sipauth->alen < FIELDMAX) sprintf(pszAlg, "%.*s", sipauth->alen, sipauth->algorithm);
else {
    sprintf(pszAlg, "MD5");
    sipauth->algorithm = pszAlg;
    sipauth->alen = strlen(pszAlg);
}

if(sipauth->urilen > 0 && sipauth->urilen < FIELDMAX) sprintf(pszURI, "%.*s", sipauth->urilen, sipauth->uri);
else {
    // sprintf(pszURI, "%.*s", rcvdsip->from->hostlen, rcvdsip->from->host);
	sprintf(pszURI, "sip:sniproxy.samsung070.com:5060");
	sipauth->uri = pszURI;
	sipauth->urilen = strlen(pszURI);
    //sipauth->uri = rcvdsip->from->host;
    //sipauth->urilen = rcvdsip->from->hostlen; 
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

sprintf(resp, "%s", Response);

//sipauth->resp = Response;
//sipauth->resplen = strlen(Response);
}
