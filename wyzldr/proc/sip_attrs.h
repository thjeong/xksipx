/*
 *  * broken-out digest attributes (with quotes removed)
 *  *  probably not NUL terminated.
 *  */

typedef struct {
/* common digest (QOP : in challenge, qop-options. in response, message-qop.) */
int alen, olen, rlen, nlen, qlen, auth_paramlen;
/* challenge digest */
int dlen, slen;
/* response digest (credentials) */
int ulen, urilen, resplen, clen;
int mlen, nclen, charsetlen, pwdlen;
/* common digest (QOP : in challenge, qop-options. in response, message-qop.) */
const char *algorithm, *opaque, *realm, *nonce, *qop, *auth_param;
/* challenge digest */
const char *dom, *stale;
/* response digest (credentials) */
const char *user, *uri, *resp, *cnonce;
const char *max, *ncount, *charset, *passwd;
char ncbuf[9];
} digest_attrs_t;
/* digest_attrs_t int count : 16 */

typedef struct {
int siplen, userlen, passwordlen, hostlen, transportlen, user_plen, methodlen, maddrlen, lrlen;
int port, ttl;
const char *sip, *user, *password, *host, *transport, *user_p, *method, *maddr, *lr;
} uri_attrs_t;
/* uri_attrs_t int count : 11 */

typedef struct {
int sent_protolen, hostlen, maddrlen, receivedlen, branchlen;
int port, ttl;
const char *sent_protocol, *host, *maddr, *received, *branch;
} via_attrs_t;
/* via_attrs_t int count : 7 */

typedef struct {
int rlen, elen, tlen, ilen, slen, base64len;
const char *r, *e, *t, *i, *s, *base64;
} msg_attrs_t;

typedef struct {
int version, o_usernamelen, o_sess_id, o_sess_version, o_net_typelen, o_addr_typelen, o_addrlen;
int slen, ilen, ulen, elen, plen;
int c_net_typelen, c_addr_typelen, c_addrlen;
int blen, start_time, end_time, rlen, klen, alen[16];
int m_medialen[4], m_port[4], m_protolen[4], m_fmt[4][16];	/* m_fmt[media-desc][attribute] */
const char *o_username, *o_net_type, *o_addr_type, *o_addr, *s, *i, *u, *e, *p;
const char *c_net_type, *c_addr_type, *c_addr;
const char *b, *r, *k, *a[16], *m_media[4], *m_proto[4];
} sdp_attrs_t;

typedef struct {
int methodlen, sip_versionlen, from_dispnamelen, from_taglen, to_dispnamelen, to_taglen;
int route_dispnamelen, callidlen, cseq_methodlen, contact_dispnamelen;
int media_rangelen, useragtlen, contentlen, statuslen, status_phraselen;
int reasonlen, cause;
unsigned int cseq, contact_expires, expires, maxfwd;
const char *method, *sip_version, *from_dispname, *from_tag, *to_dispname, *to_tag;
const char *route_dispname, *callid, *cseq_method, *contact_dispname;
const char *media_range, *useragt, *content, *status, *status_phrase;
const char *reason;
uri_attrs_t *uri;
uri_attrs_t *from;
uri_attrs_t *to;
uri_attrs_t *contact;
uri_attrs_t *route;
via_attrs_t *via;
digest_attrs_t *credential;
sdp_attrs_t *sdp;
} sip_attrs_t;
