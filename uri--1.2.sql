-- pguri version 1.2

SET client_min_messages = warning;

CREATE FUNCTION uri_scheme(text) RETURNS text
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/uri';

CREATE FUNCTION uri_userinfo(text) RETURNS text
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/uri';

CREATE FUNCTION uri_host(text) RETURNS text
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/uri';

CREATE FUNCTION uri_host_inet(text) RETURNS inet
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/uri';

CREATE FUNCTION uri_port(text) RETURNS integer
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/uri';

CREATE FUNCTION uri_query(text) RETURNS text
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/uri';

CREATE FUNCTION uri_fragment(text) RETURNS text
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/uri';

CREATE FUNCTION uri_path(text) RETURNS text
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/uri';

CREATE FUNCTION uri_path_array(text) RETURNS text[]
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/uri';


CREATE FUNCTION uri_normalize(text) RETURNS uri
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/uri';


CREATE FUNCTION uri_escape(text, space_to_plus boolean DEFAULT false, normalize_breaks boolean DEFAULT false) RETURNS text
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/uri';

CREATE FUNCTION uri_unescape(text, plus_to_space boolean DEFAULT false, break_conversion boolean DEFAULT false) RETURNS text
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/uri';

-- version 1.1

CREATE FUNCTION uri_query_json(text) RETURNS json
    IMMUTABLE
    STRICT
    LANGUAGE C
    AS '$libdir/uri';

-- version 1.2

CREATE FUNCTION uri_query_jsonb(text) RETURNS jsonb
    IMMUTABLE STRICT LANGUAGE sql
    AS $$ select uri_query_json($1)::jsonb $$;
