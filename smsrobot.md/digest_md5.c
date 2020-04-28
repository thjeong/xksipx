#define	lstreqcase(conststr, val, len) ((len) == sizeof (conststr) - 1 && \
		strncasecmp((conststr), (val), sizeof (conststr) - 1) == 0)

/* parse a digest auth string */
static int
digest_parse(const char *str, int len, digest_attrs_t *attr_out)
{
	static const char rstr[] = "realm";
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
	const char *scan, *attr, *val, *end;
	int alen, vlen;

	if (len == 0) len = strlen(str);
	scan = str;
	end = str + len;
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
			if (lstreqcase(cstr, attr, alen)) {
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
			if (lstreqcase(mstr, attr, alen)) {
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
			if (lstreqcase(sstr, attr, alen)) {
				attr_out->stale = val;
				attr_out->slen = vlen;
			}
			break;
		    case 'u':
		    case 'U':
			if (lstreqcase(ustr, attr, alen)) {
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
