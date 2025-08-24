#include <postgres.h>
#include <access/hash.h>
#include <catalog/pg_type.h>
#include <fmgr.h>
#include <lib/stringinfo.h>
#include <utils/array.h>
#include <utils/builtins.h>
#include <utils/inet.h>
#include <utils/json.h>

#include <uriparser/Uri.h>


PG_MODULE_MAGIC;


typedef struct varlena uritype;


#define DatumGetUriP(X)		((uritype *) PG_DETOAST_DATUM(X))
#define DatumGetUriPP(X)	((uritype *) PG_DETOAST_DATUM_PACKED(X))
#define UriPGetDatum(X)		PointerGetDatum(X)

#define PG_GETARG_URI_P(n)	DatumGetUriP(PG_GETARG_DATUM(n))
#define PG_GETARG_URI_PP(n)	DatumGetUriPP(PG_GETARG_DATUM(n))
#define PG_RETURN_URI_P(x)	PG_RETURN_POINTER(x)


static int
parse_uri(const char *s, UriUriA *urip, int failure_critical)
{
	UriParserStateA state;

	state.uri = urip;
	uriParseUriA(&state, s);

	switch (state.errorCode)
	{
		case URI_SUCCESS:
			return 0;
		case URI_ERROR_SYNTAX:
			if (failure_critical) {
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
						 errmsg("invalid input syntax for type uri at or near \"%s\"",
								state.errorPos)));
			}
			return 1;
		default:
			elog(ERROR, "liburiparser error code %d", state.errorCode);
	}
}

/* Report an error to the user if the uri fails to parse (this used to be the only behaviour) */
static int
parse_uri_error(const char *s, UriUriA *urip)
{
	return parse_uri(s, urip, 1);
}

/* Do not report an error to the user if the uri fails to parse */
static int
parse_uri_noerror(const char *s, UriUriA *urip)
{
	return parse_uri(s, urip, 0);
}

static text *
uri_text_range_to_text(UriTextRangeA r)
{
	if (!r.first || !r.afterLast)
		return NULL;

	return cstring_to_text_with_len(r.first, r.afterLast - r.first);
}

PG_FUNCTION_INFO_V1(uri_scheme);
Datum
uri_scheme(PG_FUNCTION_ARGS)
{
	Datum arg = PG_GETARG_DATUM(0);
	char *s = TextDatumGetCString(arg);
	UriUriA uri;
	text *result;

	parse_uri_noerror(s, &uri);
	result = uri_text_range_to_text(uri.scheme);
	uriFreeUriMembersA(&uri);
	if (result)
		PG_RETURN_TEXT_P(result);
	else
		PG_RETURN_NULL();
}

PG_FUNCTION_INFO_V1(uri_userinfo);
Datum
uri_userinfo(PG_FUNCTION_ARGS)
{
	Datum arg = PG_GETARG_DATUM(0);
	char *s = TextDatumGetCString(arg);
	UriUriA uri;
	text *result;

	parse_uri_noerror(s, &uri);
	result = uri_text_range_to_text(uri.userInfo);
	uriFreeUriMembersA(&uri);
	if (result)
		PG_RETURN_TEXT_P(result);
	else
		PG_RETURN_NULL();
}

PG_FUNCTION_INFO_V1(uri_host);
Datum
uri_host(PG_FUNCTION_ARGS)
{
	Datum arg = PG_GETARG_DATUM(0);
	char *s = TextDatumGetCString(arg);
	UriUriA uri;
	text *result;

	parse_uri_noerror(s, &uri);
	result = uri_text_range_to_text(uri.hostText);
	uriFreeUriMembersA(&uri);
	if (result)
		PG_RETURN_TEXT_P(result);
	else
		PG_RETURN_NULL();
}

PG_FUNCTION_INFO_V1(uri_host_inet);
Datum
uri_host_inet(PG_FUNCTION_ARGS)
{
	Datum arg = PG_GETARG_DATUM(0);
	char *s = TextDatumGetCString(arg);
	UriUriA uri;

	parse_uri_noerror(s, &uri);
	if (uri.hostData.ip4)
	{
		unsigned char *data = uri.hostData.ip4->data;
		char *tmp = palloc(16);
		snprintf(tmp, 16, "%u.%u.%u.%u", data[0], data[1], data[2], data[3]);
		uriFreeUriMembersA(&uri);
		PG_RETURN_INET_P(DirectFunctionCall1(inet_in, CStringGetDatum(tmp)));
	}
	else if (uri.hostData.ip6)
	{
		unsigned char *data = uri.hostData.ip6->data;
		char *tmp = palloc(40);
		snprintf(tmp, 40, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
				 data[0], data[1], data[2], data[3],
				 data[4], data[5], data[6], data[7],
				 data[8], data[9], data[10], data[11],
				 data[12], data[13], data[14], data[15]);
		uriFreeUriMembersA(&uri);
		PG_RETURN_INET_P(DirectFunctionCall1(inet_in, CStringGetDatum(tmp)));
	}
	else
	{
		uriFreeUriMembersA(&uri);
		PG_RETURN_NULL();
	}
}

static int
_uri_port_num(UriUriA *urip)
{
	if (!urip->portText.first || !urip->portText.afterLast
		|| urip->portText.afterLast == urip->portText.first)
		return -1;
	return strtol(pnstrdup(urip->portText.first, urip->portText.afterLast - urip->portText.first),
				 NULL, 10);
}

PG_FUNCTION_INFO_V1(uri_port);
Datum
uri_port(PG_FUNCTION_ARGS)
{
	Datum arg = PG_GETARG_DATUM(0);
	char *s = TextDatumGetCString(arg);
	UriUriA uri;
	int num;

	parse_uri_noerror(s, &uri);
	num = _uri_port_num(&uri);
	uriFreeUriMembersA(&uri);
	if (num < 0)
		PG_RETURN_NULL();
	PG_RETURN_INT32(num);
}

PG_FUNCTION_INFO_V1(uri_query);
Datum
uri_query(PG_FUNCTION_ARGS)
{
	Datum arg = PG_GETARG_DATUM(0);
	char *s = TextDatumGetCString(arg);
	UriUriA uri;
	text *result;

	parse_uri_noerror(s, &uri);
	result = uri_text_range_to_text(uri.query);
	uriFreeUriMembersA(&uri);
	if (result)
		PG_RETURN_TEXT_P(result);
	else
		PG_RETURN_NULL();
}

PG_FUNCTION_INFO_V1(uri_query_json);
Datum
uri_query_json(PG_FUNCTION_ARGS)
{
	Datum arg = PG_GETARG_DATUM(0);
	char *s = TextDatumGetCString(arg);
	UriUriA uri;
	UriQueryListA *queryList;
	int itemCount;
	StringInfoData dst;

	parse_uri_noerror(s, &uri);
	if(uriDissectQueryMallocA(&queryList, &itemCount,
	  uri.query.first, uri.query.afterLast) == URI_SUCCESS) {
	  UriQueryListA *p = queryList;
	  initStringInfo(&dst);
	  appendStringInfoChar(&dst, '{');
	  while(p) {
	    escape_json(&dst,p->key);
	    appendStringInfoChar(&dst, ':');
	    escape_json(&dst,p->value);
	    if(p->next) appendStringInfoChar(&dst,',');
	    p = p->next;
	  }
	  uriFreeQueryListA(queryList);
	  uriFreeUriMembersA(&uri);
	  appendStringInfoChar(&dst, '}');
	  PG_RETURN_TEXT_P(cstring_to_text(dst.data));
	}
	uriFreeUriMembersA(&uri);

	PG_RETURN_NULL();
}

PG_FUNCTION_INFO_V1(uri_fragment);
Datum
uri_fragment(PG_FUNCTION_ARGS)
{
	Datum arg = PG_GETARG_DATUM(0);
	char *s = TextDatumGetCString(arg);
	UriUriA uri;
	text *result;

	parse_uri_noerror(s, &uri);
	result = uri_text_range_to_text(uri.fragment);
	uriFreeUriMembersA(&uri);
	if (result)
		PG_RETURN_TEXT_P(result);
	else
		PG_RETURN_NULL();
}

/*
 * Defined in uriparser library, but not exported, so we keep a local version
 * here.
 */
static bool
_is_host_set(UriUriA *uri)
{
	return (uri != NULL)
		&& ((uri->hostText.first != NULL)
			|| (uri->hostData.ip4 != NULL)
			|| (uri->hostData.ip6 != NULL)
			|| (uri->hostData.ipFuture.first != NULL)
			);
}

PG_FUNCTION_INFO_V1(uri_path);
Datum
uri_path(PG_FUNCTION_ARGS)
{
	Datum arg = PG_GETARG_DATUM(0);
	char *s = TextDatumGetCString(arg);
	UriUriA uri;
	StringInfoData buf;
	UriPathSegmentA *p;

	initStringInfo(&buf);

	parse_uri_noerror(s, &uri);

	if (uri.absolutePath || (_is_host_set(&uri) && uri.pathHead))
		appendStringInfoChar(&buf, '/');

	for (p = uri.pathHead; p; p = p->next)
	{
		appendBinaryStringInfo(&buf, p->text.first, p->text.afterLast - p->text.first);
		if (p->next)
			appendStringInfoChar(&buf, '/');
	}

	uriFreeUriMembersA(&uri);
	PG_RETURN_TEXT_P(cstring_to_text(buf.data));
}

PG_FUNCTION_INFO_V1(uri_path_array);
Datum
uri_path_array(PG_FUNCTION_ARGS)
{
	Datum arg = PG_GETARG_DATUM(0);
	char *s = TextDatumGetCString(arg);
	UriUriA uri;
	ArrayBuildState *astate = NULL;
	UriPathSegmentA *pa;

	parse_uri_noerror(s, &uri);
	for (pa = uri.pathHead; pa; pa = pa->next)
	{
		text *piece = uri_text_range_to_text(pa->text);
		astate = accumArrayResult(astate,
								  PointerGetDatum(piece),
								  !piece,
								  TEXTOID,
								  CurrentMemoryContext);
	}
	uriFreeUriMembersA(&uri);

	if (astate)
		PG_RETURN_ARRAYTYPE_P(makeArrayResult(astate, CurrentMemoryContext));
	else
		PG_RETURN_ARRAYTYPE_P(construct_empty_array(TEXTOID));
}

PG_FUNCTION_INFO_V1(uri_normalize);
Datum
uri_normalize(PG_FUNCTION_ARGS)
{
	Datum arg = PG_GETARG_DATUM(0);
	char *s = TextDatumGetCString(arg);
	UriUriA uri;
	int rc;
	int charsRequired;
	char *ret;

	parse_uri_noerror(s, &uri);

	if ((rc = uriNormalizeSyntaxA(&uri)) != URI_SUCCESS)
		elog(ERROR, "uriNormalizeSyntaxA() failed: error code %d", rc);

	if ((rc = uriToStringCharsRequiredA(&uri, &charsRequired)) != URI_SUCCESS)
		elog(ERROR, "uriToStringCharsRequiredA() failed: error code %d", rc);
	charsRequired++;

	ret = palloc(charsRequired);
	if ((rc = uriToStringA(ret, &uri, charsRequired, NULL)) != URI_SUCCESS)
		elog(ERROR, "uriToStringA() failed: error code %d", rc);

	uriFreeUriMembersA(&uri);

	PG_RETURN_URI_P((uritype *) cstring_to_text(ret));
}

PG_FUNCTION_INFO_V1(uri_escape);
Datum
uri_escape(PG_FUNCTION_ARGS)
{
	text *arg = PG_GETARG_TEXT_PP(0);
	bool space_to_plus = PG_GETARG_BOOL(1);
	bool normalize_breaks = PG_GETARG_BOOL(2);

	size_t chars_required;
	char *ret;

	chars_required = (VARSIZE_ANY_EXHDR(arg)) * (normalize_breaks ? 6 : 3) + 1;
	ret = palloc(chars_required);
	uriEscapeExA(VARDATA_ANY(arg),
				 VARDATA_ANY(arg) + VARSIZE_ANY_EXHDR(arg),
				 ret,
				 space_to_plus, normalize_breaks);

	PG_RETURN_TEXT_P(cstring_to_text(ret));
}

PG_FUNCTION_INFO_V1(uri_unescape);
Datum
uri_unescape(PG_FUNCTION_ARGS)
{
	text *arg = PG_GETARG_TEXT_PP(0);
	bool plus_to_space = PG_GETARG_BOOL(1);
	bool break_conversion = PG_GETARG_BOOL(2);

	char *s = text_to_cstring(arg);

	uriUnescapeInPlaceExA(s, plus_to_space, break_conversion);

	PG_RETURN_TEXT_P(cstring_to_text(s));
}
