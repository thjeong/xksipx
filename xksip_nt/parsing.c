#include <stdio.h> 
#include <math.h>
#include "sip_attrs.h"

#define MYPORT 5060/* the port users will be connecting to */
#define DEBUG

/* sip_attrs_t int count : 19 */

/*
	bzero(rcvdsip, sizeof(int)*19);
	bzero(rcvdsip->uri, sizeof(int)*11);
	bzero(rcvdsip->from, sizeof(int)*11);
	bzero(rcvdsip->to, sizeof(int)*11);
	bzero(rcvdsip->contact, sizeof(int)*11);
	bzero(rcvdsip->route, sizeof(int)*11);
	bzero(rcvdsip->via, sizeof(int)*7);
	bzero(rcvdsip->credential, sizeof(int)*16);
*/

/*

common : algorithm / opaque / realm / nonce / auth-param

challenge : domain / stale / qop-options

credentials : username / digest-uri / dresponse / cnonce / message-qop / nonce-count

*/
 int sip_parse(const char *str, int len, sip_attrs_t *attr_out);
 int uri_parse(const char *str, int len, uri_attrs_t *attr_out);
 int digest_parse(const char *str, int len, digest_attrs_t *attr_out);
 int sdp_parse(const char *str, int len, sdp_attrs_t *attr_out);
 int msg_parse(const char *str, int len, msg_attrs_t *attr_out);

int
strncmpi(const char *str1, const char *str2, int len)
{
	int i;
	for(i= 0; i < len; i++) {
		if((str1[i] - str2[i]) % 32 != 0) return -1;
	}
	return 0;
}

/* parse a SIP message string */
int
sip_parse(const char *str, int len, sip_attrs_t *attr_out)
{
	static const char accept_str[] = "Accept";
	static const char register_str[] = "REGISTER";
	static const char refer_str[] = "REFER";
	static const char invite_str[] = "INVITE";
	static const char message_str[] = "MESSAGE";
	static const char prack_str[] = "PRACK";
	static const char reason_str[] = "Reason";
	static const char cause_str[] = "cause";
	static const char subscribe_str[] = "SUBSCRIBE";
	static const char info_str[] = "INFO";
	static const char ack_str[] = "ACK";
	static const char cancel_str[] = "CANCEL";
	static const char options_str[] = "OPTIONS";
	static const char update_str[] = "UPDATE";
	static const char bye_str[] = "BYE";
	static const char from_str[] = "From";
	static const char from_sstr[] = "f:";
	static const char tag_str[] = "tag";
	static const char to_str[] = "To";
	static const char to_sstr[] = "t:";
	static const char contact_str[] = "Contact";
	static const char contact_sstr[] = "m:";
	static const char contact_expires_str[] = "expires";
	static const char via_str[] = "Via";
	static const char via_sstr[] = "v:";
	static const char via_branch_str[] = "branch";
	static const char via_maddr_str[] = "maddr";
	static const char via_received_str[] = "received";
	static const char via_ttl_str[] = "ttl";
	static const char route_str[] = "Route";
	static const char authorization_str[] = "Authorization";
	static const char callid_str[] = "Call-ID";
	static const char callid_sstr[] = "i:";
	static const char cseq_str[] = "CSeq";
	static const char ua_str[] = "User-Agent";
	static const char maxfwd_str[] = "Max-Forwards";
	static const char estr[] = "Expires";
	static const char astr[] = "WWW-Authenticate";
	static const char contlen_str[] = "Content-Length";
	static const char contlen_sstr[] = "l:";
	static const char status_str[] = "SIP/2.0";

	const char *scan, *attr, *val, *end;
	const char *probe, *probeend;
	int alen, vlen;

	bzero(attr_out, sizeof(int)*22);
	bzero(attr_out->uri, sizeof(int)*11);
	bzero(attr_out->from, sizeof(int)*11);
	bzero(attr_out->to, sizeof(int)*11);
	bzero(attr_out->contact, sizeof(int)*11);
	bzero(attr_out->route, sizeof(int)*11);
	bzero(attr_out->via[0], sizeof(int)*7);
	bzero(attr_out->via[1], sizeof(int)*7);
	bzero(attr_out->via[2], sizeof(int)*7);
	bzero(attr_out->via[3], sizeof(int)*7);
	bzero(attr_out->credential, sizeof(int)*16);
	// 20090302
	bzero(attr_out->sdp, sizeof(int)*117);
	attr_out->expires = 0;
	attr_out->contact_expires = 0;

	if (len == 0) len = strlen(str);
	scan = str;
	end = str + len;

	for (;;) {
		/* parse attribute */
		attr = scan;
		if (*attr == '\r' || *attr == '\n') {	// End of Header
			probe = attr;
			probeend = end;
			while(probe < probeend && isspace(*probe)) ++probe;
			// if length false, return
			if(attr_out->contentlen > strlen(probe)) {
				break;
			}
			if(attr_out->contentlen > 0) {
				attr_out->content = probe;
				// 20090302 ##########################################
				sdp_parse(attr_out->content, attr_out->contentlen, attr_out->sdp);
			}
			break;
		}

		while (scan < end && (*scan != ':' && *scan != ' ')) ++scan;
		alen = scan - attr;
		if (!alen || scan == end || scan + 1 == end) {
			break;
		}

		/* check attr */
		for(probe = attr; probe < attr + alen; probe++) {
			if(*probe >= 0 && *probe < ' ') {
				return (-1);
			}
		}

		/* parse value */
		++scan;
		/* skip over space */
		while(scan < end && isspace(*scan)) ++scan;
		val = scan;
		while (scan < end && *scan != '\r' && *scan != '\n') ++scan;
		vlen = scan - val;
		if (!vlen) {
			break;
		}

		/* check value */
		for(probe = val; probe < val + vlen; probe++) {
			if(*probe >= 0 && *probe < ' ') {
				return (-1);
			}
		}

		/* lookup the attribute */
		switch (*attr) {
			case 'a':
			case 'A':
				/* ACK CASE */
				if (strncmpi(ack_str,attr,alen) == 0) {
					attr_out->method = attr;
					attr_out->methodlen = alen;

					/* name-addr */
					probe = val;
					probeend = val + vlen;
					while(probe < probeend && *probe != ' ') ++probe;
					/* Request-URI */
					uri_parse(val, probe - val, attr_out->uri);
					if(*probe == ' ') ++probe;
					/* SIP-Version */
					attr_out->sip_version = probe;
					attr_out->sip_versionlen = probeend - probe;
				} else if (strncmpi(authorization_str,attr,alen) == 0) {
					/* Authorization case */
					digest_parse(val, vlen, attr_out->credential);
				} else if (strncmpi(accept_str,attr,alen) == 0) {
					/* Accept case */
					probe = val;
					probeend = val + vlen;
					/* media-range */
					attr_out->media_range = val;
					while(probe < probeend && *probe != ';') ++probe;
					attr_out->media_rangelen = probe - val;
					++probe;
					/* m-parameter */
					/* TO DO: user-defined parameter processing */
				}
				break;
			case 'u':
			case 'U':
				if (strncmpi(ua_str,attr,alen) == 0) {
					attr_out->useragt = val;
					attr_out->useragtlen = vlen;
					break;
				}	/* for UPDATE case */
			case 'b':
			case 'B':
//			case 'i':	/* for i: case */
			case 'I':
			case 'o':
			case 'O':
			case 'P':
			case 'p':
				/* METHOD CASE */
				if (strncmpi(invite_str,attr,alen) == 0 ^ strncmpi(ack_str,attr,alen) == 0 ^ strncmpi(options_str,attr,alen) == 0
				^ strncmpi(bye_str,attr,alen) == 0 ^ strncmpi(prack_str,attr,alen) == 0 ^ strncmpi(info_str,attr,alen) == 0 ^ strncmpi(update_str,attr,alen) == 0) {
					attr_out->method = attr;
					attr_out->methodlen = alen;

					/* name-addr */
					probe = val;
					probeend = val + vlen;
					while(probe < probeend && *probe != ' ') ++probe;
					/* Request-URI */
					uri_parse(val, probe - val, attr_out->uri);
					if(*probe == ' ') ++probe;
					/* SIP-Version */
					attr_out->sip_version = probe;
					attr_out->sip_versionlen = probeend - probe;
				}
				break;
			case 'm':
			case 'M':
				if (strncmpi(maxfwd_str,attr,alen) == 0) {
					attr_out->maxfwd = atol(val);
				/* ACK CASE */
				} else if (strncmpi(message_str,attr,alen) == 0) {
					attr_out->method = attr;
					attr_out->methodlen = alen;
				
					/* name-addr */
					probe = val;
					probeend = val + vlen; 
					while(probe < probeend && *probe != ' ') ++probe;
					/* Request-URI */
					uri_parse(val, probe - val, attr_out->uri);
					if(*probe == ' ') ++probe;
					/* SIP-Version */
					attr_out->sip_version = probe;
					attr_out->sip_versionlen = probeend - probe;
				}

   				if (strncmpi(contact_sstr,attr,alen) == 0) { /* Go to case 'C' */ }
				else break;
			case 'c':
			case 'C':
			case 'i':
//			case 'I':	/* for INVITE case */
			case 'l':
			case 'L':
				/* Call-id case */
   				if (strncmpi(callid_str,attr,alen) == 0 ^ strncmpi(callid_sstr,attr,alen) == 0) {
					attr_out->callid = val;
					attr_out->callidlen = vlen;
				}
				/* Cseq case */
				else if (strncmpi(cseq_str,attr,alen) == 0) {
					attr_out->cseq = atoi(val);
					probe = val;
					probeend = val + vlen;
					while (probe < probeend && *probe != ' ') ++probe;
					++probe;
					attr_out->cseq_method = probe;
					attr_out->cseq_methodlen = probeend - probe;
				}
				/* Context-Length case */
				else if (strncmpi(contlen_str,attr,alen) == 0 ^ strncmpi(contlen_sstr,attr,alen) == 0) {
					attr_out->contentlen = atoi(val);
				}
				/* Contact case */
				else if (strncmpi(contact_str,attr,alen) == 0 ^ strncmpi(contact_sstr,attr,alen) == 0) {
					/* PLEASE ADD COMMA CIRCULAR PROCESSING !!! */
					/* name-addr */
					probe = val;
					probeend = val + vlen;
					/* display name */
					if(*probe == '\"') {
						probe++;
						attr_out->contact_dispname = probe;
						while(probe < probeend && *probe != '\"') ++probe;
						attr_out->contact_dispnamelen = probe - attr_out->contact_dispname;
						probe++;
						/* skip over space */
						while(probe < probeend && isspace(*probe)) ++probe;
					}
					/* LAQUOT addr-spec RAQUOT */
					if(*probe == '<') {
						probe++;
						val = probe;
						while(probe < probeend && *probe != '>') ++probe;
						/* addr-spec */
						uri_parse(val, probe - val, attr_out->contact);
						while(probe < probeend && *probe != ';') ++probe;
					} else {	/* illegal case handling */
						val = probe;
						while(probe < probeend && *probe != ';') ++probe;
						uri_parse(val, probe - val, attr_out->from);
					}

					/* contact-params */
					for (;;) {
						/* parse attribute */
						++probe;
						attr = probe;
						while (probe < probeend && (*probe != '=')) ++probe;
						alen = probe - attr;
						/* parse value */
						++probe;
						val = probe;
						while (probe < probeend && *probe != ';') ++probe;
						vlen = probe - val;
						switch(*attr) {
							case 'e':	/* Contact - expires */
								if(memcmp(contact_expires_str,attr,alen) == 0) {
									attr_out->contact_expires = atol(val);
								}
								break;
						}
						if(probe >= probeend) break;
					}
				} else if (strncmpi(cancel_str,attr,alen) == 0) {
					/* CANCEL METHOD */
					attr_out->method = attr;
					attr_out->methodlen = alen;

					/* name-addr */
					probe = val;
					probeend = val + vlen;
					while(probe < probeend && *probe != ' ') ++probe;
					/* Request-URI */
					uri_parse(val, probe - val, attr_out->uri);
					if(*probe == ' ') ++probe;
					/* SIP-Version */
					attr_out->sip_version = probe;
					attr_out->sip_versionlen = probeend - probe;
				}
				break;
			case 'e':
			case 'E':
				if (strncmpi(estr,attr,alen) == 0) {
					attr_out->expires = atol(val);
				}
				break;
			case 'f':
			case 'F':
				if (strncmpi(from_str,attr,alen) == 0 ^ strncmpi(from_sstr,attr,alen) == 0) {
					probe = val;
					probeend = val + vlen;
					/* display name */
					if(*probe == '\"') {
						probe++;
						attr_out->from_dispname = probe;
						while(probe < probeend && *probe != '\"') ++probe;
						attr_out->from_dispnamelen = probe - attr_out->from_dispname;
						probe++;
					} else if(*probe != '<') {
						attr_out->from_dispname = probe;
						while(probe < probeend && *probe != ' ') ++probe;
						attr_out->from_dispnamelen = probe - attr_out->from_dispname;
						probe++;
					}
					/* skip over space */
					while(probe < probeend && isspace(*probe)) ++probe;
					
					/* addr-spec */
					if(*probe == '<') {
						probe++;
						val = probe;
						while(probe < probeend && *probe != '>') ++probe;
						uri_parse(val, probe - val, attr_out->from);
						while(probe < probeend && *probe != ';') ++probe;
					} else {	/* illegal case handling */
						val = probe;
						while(probe < probeend && *probe != ';') ++probe;
						uri_parse(val, probe - val, attr_out->from);
					}
				}
				/* from-params */
				for (;;) {
					/* parse attribute */
					++probe;
					attr = probe;
					while (probe < probeend && (*probe != '=')) ++probe;
					alen = probe - attr;
					/* parse value */
					++probe;
					val = probe;
					while (probe < probeend && *probe != ';') ++probe;
					vlen = probe - val;
					switch(*attr) {
						case 't':	/* From - tag */
							if(strncmpi(tag_str,attr,alen) == 0) {
								attr_out->from_tag = val;
								attr_out->from_taglen = vlen;
							}
							break;
					}
					if(probe >= probeend) break;
				}
				break;
			case 'r':
			case 'R':
				/* REGISTER METHOD */
				if (strncmpi(register_str,attr,alen) == 0) {
					attr_out->method = attr;
					attr_out->methodlen = alen;

					/* name-addr */
					probe = val;
					probeend = val + vlen;
					while(probe < probeend && *probe != ' ') ++probe;
					/* Request-URI */
					uri_parse(val, probe - val, attr_out->uri);
					if(*probe == ' ') ++probe;
					/* SIP-Version */
					attr_out->sip_version = probe;
					attr_out->sip_versionlen = probeend - probe;
				} else if (strncmpi(route_str,attr,alen) == 0) {
					/* name-addr */
					probe = val;
					probeend = val + vlen;

					/* Route case */
					for(;;) {
						/* display name */
						if(*probe == '\"') {
							probe++;
							attr_out->route_dispname = probe;
							while(probe < probeend && *probe != '\"') ++probe;
							attr_out->route_dispnamelen = probe - attr_out->route_dispname;
							probe++;
							/* skip over space */
							while(probe < probeend && isspace(*probe)) ++probe;
						}
						/* LAQUOT addr-spec RAQUOT */
						if(*probe == '<') {
							probe++;
							val = probe;
							while(probe < probeend && *probe != '>') ++probe;
							/* addr-spec */
							uri_parse(val, probe - val, attr_out->route);
						} else {	/* illegal case handling */
							val = probe;
							while(probe < probeend && *probe != ';') ++probe;
							uri_parse(val, probe - val, attr_out->route);
						}
						/* route-params */
						/* user defined rr-params. IGNORE ? */

						/* COMMA route-param */
						while(probe < probeend && *probe != ',') ++probe;
						if(probe >= probeend) break;
					}
				}/* REFER METHOD (RFC.3515) CASE */ else if (strncmpi(refer_str,attr,alen) == 0) {
					attr_out->method = attr;
					attr_out->methodlen = alen;

					/* name-addr */
					probe = val;
					probeend = val + vlen;
					while(probe < probeend && *probe != ' ') ++probe;
					/* Request-URI */
					uri_parse(val, probe - val, attr_out->uri);
					if(*probe == ' ') ++probe;
					/* SIP-Version */
					attr_out->sip_version = probe;
					attr_out->sip_versionlen = probeend - probe;
				}/* Reason Case */ else if (strncmpi(reason_str, attr, alen) == 0) {
					probe = val;
					probeend = val + vlen;

					/* Type of reason */
					attr_out->reason = probe;
					while(probe < probeend && *probe != ';') ++probe;
					attr_out->reasonlen = probe - attr_out->reason;
					++probe;
					/* skip over space just in cases */
					//while(probe < probeend && isspace(*probe)) ++probe;
					/* Reason params */
					for(;;) {
						/* parse attribute */
						attr = probe;
						while (probe < probeend && *probe != '=') ++probe;
						alen = probe - attr;
						/* parse value */
						++probe;
						val = probe;
						while (probe < probeend && *probe != ';') ++probe;
						vlen = probe - val;
						// printf("<<%s>>\n", attr);
						switch(*attr) {
							case 'c':	/* cause - tag */
								if(strncmpi(cause_str,attr,alen) == 0) {
									attr_out->cause = atoi(val);
								}
								break;
							case 't':	/* text - tag */
							/*
								if(strncmpi(text_str,attr,alen) == 0) {
									attr_out->text = val;
									attr_out->reason_textlen = vlen;
								}
							*/
								break;
						}
						if(probe >= probeend) break;
						else ++probe;	/* skip ';' */
					}
				}
				break;
			case 's':
			case 'S':
				if (strncmpi(status_str,attr,alen) == 0) { /* status_code */
					probe = val;
					probeend = val + vlen;

					attr_out->status = probe;
					while(probe < probeend && *probe != ' ') ++probe;
					attr_out->statuslen = probe - val;
					probe++;
					attr_out->status_phrase = probe;
					attr_out->status_phraselen = probeend - probe;
				} else if (strncmpi(subscribe_str,attr,alen) == 0) {  /* METHOD CASE */
                                        attr_out->method = attr;
                                        attr_out->methodlen = alen;

                                        /* name-addr */
                                        probe = val;
                                        probeend = val + vlen;
                                        while(probe < probeend && *probe != ' ') ++probe;
                                        /* Request-URI */
                                        uri_parse(val, probe - val, attr_out->uri);
                                        if(*probe == ' ') ++probe;
                                        /* SIP-Version */
                                        attr_out->sip_version = probe;
                                        attr_out->sip_versionlen = probeend - probe;
                                }
				break;
			case 't':
			case 'T':
				if (strncmpi(to_str,attr,alen) == 0 ^ strncmpi(to_sstr,attr,alen) == 0) {
					probe = val;
					probeend = val + vlen;
					/* display name */
					if(*probe == '\"') {
						probe++;
						attr_out->to_dispname = probe;
						while(probe < probeend && *probe != '\"') ++probe;
						attr_out->to_dispnamelen = probe - attr_out->to_dispname;
						probe++;
					} else if(*probe != '<') {
						attr_out->to_dispname = probe;
						while(probe < probeend && *probe != ' ') ++probe;
						attr_out->to_dispnamelen = probe - attr_out->to_dispname;
						probe++;
					}
					/* skip over space */
					while(probe < probeend && isspace(*probe)) ++probe;

					/* addr-spec */
					if(*probe == '<') {
						probe++;
						val = probe;
						while(probe < probeend && *probe != '>') ++probe;
						uri_parse(val, probe - val, attr_out->to);
						while(probe < probeend && *probe != ';') ++probe;
					} else {	/* illegal case handling */
						val = probe;
						while(probe < probeend && *probe != ';') ++probe;
						uri_parse(val, probe - val, attr_out->to);
					}
				}
				/* to-params */
				for (;;) {
					/* parse attribute */
					++probe;
					attr = probe;
					while (probe < probeend && (*probe != '=')) ++probe;
					alen = probe - attr;
					/* parse value */
					++probe;
					val = probe;
					while (probe < probeend && *probe != ';') ++probe;
					vlen = probe - val;
					switch(*attr) {
						case 't':	/* to - tag */
							if(strncmpi(tag_str,attr,alen) == 0) {
								attr_out->to_tag = val;
								attr_out->to_taglen = vlen;
							}
							break;
					}
					if(probe >= probeend) break;
				}
				break;
			case 'v':
			case 'V':
				if (strncmpi(via_str,attr,alen) == 0 ^ strncmpi(via_sstr,attr,alen) == 0) {

					/* Via sent-protocol */
					probe = val;	// for 1st via header-value
					probeend = val + vlen;

					for(;;) {	/* TEMPORARY: via-count */
					attr_out->via[attr_out->via_count]->sent_protocol = probe;
					while (probe < probeend && *probe != ' ') ++probe;
					attr_out->via[attr_out->via_count]->sent_protolen = probe - attr_out->via[attr_out->via_count]->sent_protocol;
					++probe;
					/* Via sent-by host */
					attr_out->via[attr_out->via_count]->host = probe;
					while (probe < probeend && *probe != ':' && *probe != ';') ++probe;
					attr_out->via[attr_out->via_count]->hostlen = probe - attr_out->via[attr_out->via_count]->host;
					if(*probe == ':') {
						/* Via sent-by port */
						++probe;
						attr_out->via[attr_out->via_count]->port = atoi(probe);
						while (probe < probeend && *probe != ';') ++probe;
					}
					++probe;
					/* via-params */
					for (;;) {
						/* parse attribute */
						attr = probe;
						while (probe < probeend && (*probe != '=')) ++probe;
						alen = probe - attr;
						/* parse value */
						++probe;
						val = probe;
						while (probe < probeend && *probe != ';' && *probe != ',') ++probe;
						vlen = probe - val;
						switch(*attr) {
							case 'b':	/* Via - branch */
								if(strncmpi(via_branch_str,attr,alen) == 0) {
									attr_out->via[attr_out->via_count]->branch = val;
									attr_out->via[attr_out->via_count]->branchlen = vlen;
								}
								break;
							case 'm':	/* Via - branch */
								if(strncmpi(via_maddr_str,attr,alen) == 0) {
									attr_out->via[attr_out->via_count]->maddr = val;
									attr_out->via[attr_out->via_count]->maddrlen = vlen;
								}
								break;
							case 'r':	/* Via - branch */
								if(strncmpi(via_received_str,attr,alen) == 0) {
									attr_out->via[attr_out->via_count]->received = val;
									attr_out->via[attr_out->via_count]->receivedlen = vlen;
								}
								break;
							case 't':	/* Via - ttl */
								if(strncmpi(via_ttl_str,attr,alen) == 0) {
									attr_out->via[attr_out->via_count]->ttl = atoi(val);
								}
								break;
						}
						//printf("%c\t%c\n", *probe, *probe-1);
						if(probe >= probeend || *probe == ',') break; // end or goto next via
					}
					attr_out->via_count++;
					if(probe >= probeend) break; // end or goto next via
					else {
						//printf("%c\t%c\n", *probe, *(probe+1));
						probe++;
						//while(probe < probeend && isspace(*probe)) ++probe;
					}

					} // TEMPORARY : END OF via count
				}
				break;
			case 'w':
			case 'W':
				if (strncmpi(astr,attr,alen) == 0) {
					/* TO DO: */
				}
				break;
			default:
				break;
		}

		/* skip over cr */
		while(scan < end && *scan == '\r') ++scan;
		while(scan < end && *scan == '\n') ++scan;
	}

        if((attr_out->statuslen > 0 || attr_out->methodlen > 0) && attr_out->cseq_methodlen > 0) return (1);
        else return (-1);
}

/* NEED TO BE ADD FOR Absolute URI case !!! */
/* NEED TO BE MODIFIED FOR '>' PROCESSING */
/* parse a URI parsing */
 int
uri_parse(const char *str, int len, uri_attrs_t *attr_out)
{
	static const char uri_transport_str[] = "transport";
	static const char uri_user_str[] = "user";
	static const char uri_method_str[] = "method";
	static const char uri_ttl_str[] = "ttl";
	static const char uri_maddr_str[] = "maddr";
	static const char uri_lr_str[] = "lr";

	const char *scan, *attr, *val, *end;
	const char *probe, *probeend;
	int alen, vlen;

	if (len == 0) len = strlen(str);
	probe = str;
	probeend = str + len;

	/* name-addr */
	/* SIP-URI / SIPS-URI */
	attr_out->sip = probe;
	while(probe < probeend && *probe != ':') ++probe;
	attr_out->siplen = probe - attr_out->sip;

	/* finding userinfo */
	probe++;
	val = probe;
	while(probe < probeend && *probe != '@' && *probe != ';' && *probe != '>') ++probe;
	vlen = probe - val;
	if(*probe == '@') {		/* if userinfo exist, */
		attr_out->user = val;
		while(val < probe && *val != ':') ++val;
		if(val < probe) {		/* if password exist, */
			attr_out->userlen = val - attr_out->user;
			val++;
			attr_out->password = val;
			attr_out->passwordlen = probe - val;
		} else {
			attr_out->userlen = val - attr_out->user;
		}
		probe++;
		val = probe;
		while(probe < probeend && *probe != ';' && *probe != '>') ++probe;
		vlen = probe - val;
	}
	/* hostport */
	attr_out->host = val;
	while(val < probe && *val != ':') ++val;
	if(val < probe) {		/* if port exist, */
		attr_out->hostlen = val - attr_out->host;
		val++;
		attr_out->port = atoi(val);
	} else {
		attr_out->hostlen = val - attr_out->host;
	}
	probe++;
	val = probe;
	while(probe < probeend && *probe != ';' && *probe != '>') ++probe;
	vlen = probe - val;
	

	if(*probe == ';') {	/* uri-parameters */
		probe++;
		for (;;) {
			attr = probe;
			while (probe < probeend && (*probe != '=' && *probe != ';')) ++probe;
			alen = probe - attr;
			/* parse value */
			if(*probe == '=') {
				++probe;
				val = probe;
				while (probe < probeend && *probe != ';' && *probe != '>') ++probe;
				vlen = probe - val;
			} else ++probe;
			switch(*attr) {
				case 't':
					if(memcmp(uri_transport_str,attr,alen) == 0) {
						attr_out->transport = val;
						attr_out->transportlen = vlen;
					} else if(memcmp(uri_ttl_str,attr,alen) == 0) {
						attr_out->ttl = atoi(val);
					}
					break;
				case 'u':
					if(memcmp(uri_user_str,attr,alen) == 0) {
						attr_out->user_p = val;
						attr_out->user_plen = vlen;
					}
					break;
				case 'm':
					if(memcmp(uri_method_str,attr,alen) == 0) {
						attr_out->method = val;
						attr_out->methodlen = vlen;
					} else if(memcmp(uri_maddr_str,attr,alen) == 0) {
						attr_out->maddr = val;
						attr_out->maddrlen = vlen;
					}
					break;
				case 'l':
					if(memcmp(uri_lr_str,attr,alen) == 0) {
						attr_out->lr = attr;
						attr_out->lrlen = alen;
					}
					break;
			}
			if(*probe == '>') probe++;
			if(probe >= probeend) break;
		}
	}
}

#define	lstreqcase(conststr, val, len) ((len) == sizeof (conststr) - 1 && \
		strncasecmp((conststr), (val), sizeof (conststr) - 1) == 0)

/* parse a digest credential string */
 int
digest_parse(const char *str, int len, digest_attrs_t *attr_out)
{
	static const char astr[] = "algorithm";
	static const char rstr[] = "realm";
	static const char nstr[] = "nonce";
	static const char cnstr[] = "cnonce";
	static const char qstr[] = "qop";
	static const char userstr[] = "username";
	static const char ostr[] = "opaque";
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
/*		if (!vlen)
			return (-5);	*/

		/* lookup the attribute */
		switch (*attr) {
			case 'a':
			case 'A':
			if (lstreqcase(astr, attr, alen)) {
				attr_out->algorithm = val;
				attr_out->alen = vlen;
			}
			break;
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
			case 'o':
			case 'O':
			if (lstreqcase(ostr, attr, alen)) {
				attr_out->opaque = val;
				attr_out->olen = vlen;
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

 int
sdp_parse(const char *str, int len, sdp_attrs_t *attr_out)
{
	const char *scan, *attr, *val, *end;
	const char *probe, *probeend;   
	int alen, vlen;		 
//	int a_count = 0;
	int m_count = 0;
	int fmt_count = 0;

	if (len == 0) len = strlen(str);
	scan = str;			 
	end = str + len;		
	/* isspace */
	for (;;) {			  
		/* parse attribute */   
		attr = scan;		
		if (*attr == '\r') {	/* End of message content header */
/*			probe = attr;
			probeend = end;
			while(probe < probeend && isspace(*probe)) ++probe;
			attr_out->base64 = probe;
			while(probe < probeend && !isspace(*probe)) ++probe;
			attr_out->base64len = probe - attr_out->base64; */
			return (-5);
		}
		while (scan < end && *scan != '=') ++scan;
		alen = scan - attr;
		if (!alen || scan == end || scan + 1 == end) {
			return (-5);
		}
		/* parse value */
		++scan; 
		/* skip over space : not needed */
		val = scan;
		while (scan < end && *scan != '\r') ++scan; /* cut off per line */
		vlen = scan - val;
		if (!vlen) return (-5);

		/* lookup the attribute */
		switch (*attr) {	
			case 'v':
				attr_out->version = atoi(val);
				break;
			case 'o':	  /* origin-field */ 
				probe = val;
				probeend = val + vlen;

				attr_out->o_username = probe;
				while(probe < probeend && *probe != ' ') ++probe;
				attr_out->o_usernamelen = probe - attr_out->o_username;
				probe++;

				attr_out->o_sess_id = atoi(probe);
				while(probe < probeend && *probe != ' ') ++probe;
				probe++;

				attr_out->o_sess_version = atoi(probe);
				while(probe < probeend && *probe != ' ') ++probe;
				probe++;

				attr_out->o_net_type = probe;
				while(probe < probeend && *probe != ' ') ++probe;
				attr_out->o_net_typelen = probe - attr_out->o_net_type;
				probe++;

				attr_out->o_addr_type = probe;
				while(probe < probeend && *probe != ' ') ++probe;
				attr_out->o_addr_typelen = probeend - attr_out->o_addr_type;
				probe++;

				attr_out->o_addr = probe;
				attr_out->o_addrlen = probeend - attr_out->o_addr;
				break;
			case 's':	/* session-name */
				attr_out->s = val;
				attr_out->slen = vlen;
				break;
			case 'i':	/* information-field */
				attr_out->i = val;
				attr_out->ilen = vlen;
				break;
			case 'u':	/* uri-field */
				attr_out->u = val;
				attr_out->ulen = vlen;
				break;
			case 'e':	/* email-field : It should be fix to handle multiple attr */
				attr_out->e = val;
				attr_out->elen = vlen;
				break;
			case 'p':	/* phone-field : It should be fix to handle multiple attr */
				attr_out->p = val;
				attr_out->plen = vlen;
				break;
			case 'c':	/* connection-field */
				probe = val;
				probeend = val + vlen;

				attr_out->c_net_type = probe;
				while(probe < probeend && *probe != ' ') ++probe;
				attr_out->c_net_typelen = probe - attr_out->c_net_type;
				probe++;

				attr_out->c_addr_type = probe;
				while(probe < probeend && *probe != ' ') ++probe;
				attr_out->c_addr_typelen = probe - attr_out->c_addr_type;
				probe++;

				attr_out->c_addr = probe;
				attr_out->c_addrlen = probeend - attr_out->c_addr;

				break;
			case 'b':	/* bandwidth-field */
				attr_out->b = val;
				attr_out->blen = vlen;
				break;
			case 't':	/* time-field : It should be fix to handle multiple attr */
				probe = val;
				probeend = val + vlen;

				attr_out->start_time = atoi(probe);
				while(probe < probeend && *probe != ' ') ++probe;
				probe++;
				attr_out->end_time = atoi(probe);
				break;
			case 'r':	/* repeat-field : It should be fix to handle multiple attr */
				attr_out->r = val;
				attr_out->rlen = vlen;
				break;
			case 'k':	/* key-field */
				attr_out->k = val;
				attr_out->klen = vlen;
				break;
			case 'a':	/* attribute-field */
				attr_out->a[attr_out->a_count] = val;
				attr_out->alen[attr_out->a_count] = vlen;
				attr_out->a_count++;
				break;
			case 'm':	/* attribute-field */
				probe = val;
				probeend = val + vlen;

				attr_out->m_media[m_count] = probe;
				while(probe < probeend && *probe != ' ') ++probe;
				attr_out->m_medialen[m_count] = probe - attr_out->m_media[m_count];
				probe++;

				attr_out->m_port[m_count] = atoi(probe);
				while(probe < probeend && *probe != ' ') ++probe;
				probe++;

				attr_out->m_proto[m_count] = probe;
				while(probe < probeend && *probe != ' ') ++probe;
				attr_out->m_protolen[m_count] = probe - attr_out->m_proto[m_count];
				probe++;

				for(fmt_count = 0; fmt_count < 12; fmt_count++) {
					attr_out->m_fmt[m_count][fmt_count] = atoi(probe);
					while(probe < probeend && *probe != ' ') ++probe;
					probe++;
					if(probe >= probeend) {
						fmt_count++;
						if(fmt_count < 12) {
							attr_out->m_fmt[m_count][fmt_count] = -1;
						}
						break;
					}
				}

				m_count++;
				break;
			default:
				break;
		}	   
		while(scan < end && *scan == '\r') ++scan;
		while(scan < end && *scan == '\n') ++scan;
	}
	//attr_out->a_count = a_count;
}

 int
msg_parse(const char *str, int len, msg_attrs_t *attr_out)
{
	const char *scan, *attr, *val, *end;
	const char *probe, *probeend;   
	int alen, vlen;		 

	if (len == 0) len = strlen(str);
	scan = str;			 
	end = str + len;		
	/* isspace */
	for (;;) {			  
		/* parse attribute */   
		attr = scan;		
		if (*attr == '\r') {	/* End of message content header */
			probe = attr;
			probeend = end;
			while(probe < probeend && isspace(*probe)) ++probe;
			attr_out->base64 = probe;
			while(probe < probeend && !isspace(*probe)) ++probe;
			attr_out->base64len = probe - attr_out->base64;
			return (-5);
		}
		while (scan < end && *scan != ':' && *scan != ' ') ++scan;
		alen = scan - attr;
		if (!alen || scan == end || scan + 1 == end) {
			return (-5);
		}
		/* parse value */
		++scan; 
		/* skip over space */
		while(scan < end && isspace(*scan)) ++scan;
		val = scan;
		while (scan < end && *scan != '\r') ++scan; /* cut off per line */
		vlen = scan - val;
		if (!vlen) return (-5);

		/* lookup the attribute */
		switch (*attr) {	
			case 'r':
				attr_out->r = val;
				attr_out->rlen = vlen;
				break;
			case 'e':	   
				attr_out->e = val;
				attr_out->elen = vlen;
				break;
			case 't':
				attr_out->t = val;
				attr_out->tlen = vlen;
				break;
			case 'i':
				attr_out->i = val;
				attr_out->ilen = vlen;
				break;
			case 's':
				attr_out->s = val;
				attr_out->slen = vlen;
				break;
			default:
				break;
		}	   
		while(scan < end && *scan == '\r') ++scan;
		while(scan < end && *scan == '\n') ++scan;
	}
}
