#include "cos_sys_util.h"
#include "cos_log.h"
#include "cos_define.h"
#include <ctype.h>

static const char *g_s_wday[] = {
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

static const char *g_s_mon[] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

static const char g_s_gmt_format[] = "%s, %.2d %s %.4d %.2d:%.2d:%.2d GMT";
static int retry_change_domin_config = COS_FALSE;
static int object_key_simplify_check = COS_TRUE;
static int test_retry_change_domin_config = COS_FALSE;

static cos_table_t *g_sign_header_table = NULL;
static cos_pool_t *g_table_pool = NULL;

int get_retry_change_domin() {
    return retry_change_domin_config;
}
void set_retry_change_domin(int user_retry_change_domin) {
    retry_change_domin_config = user_retry_change_domin;
}

int get_test_retry_change_domin_config() {
    return test_retry_change_domin_config;
}
void set_test_retry_change_domin_config(int user_retry_change_domin) {
    test_retry_change_domin_config = user_retry_change_domin;
}

int get_object_key_simplify_check() {
    return object_key_simplify_check;
}
void set_object_key_simplify_check(int user_object_key_simplify_check) {
    object_key_simplify_check = user_object_key_simplify_check;
}
int cos_parse_xml_body(cos_list_t *bc, mxml_node_t **root) {
    cos_buf_t *b;
    size_t len;

    *root = NULL;
    len = (size_t)cos_buf_list_len(bc);

    {
        int nsize = 0;
        char *buffer = (char*)malloc(sizeof(char)*(len+1));
        memset(buffer, 0, len + 1);
        cos_list_for_each_entry(cos_buf_t, b, bc, node) {
            memcpy(buffer + nsize, (char *)b->pos, cos_buf_size(b));
            nsize += cos_buf_size(b);
        }
        *root = mxmlLoadString(NULL, buffer, MXML_OPAQUE_CALLBACK);
        free(buffer);
        if (NULL == *root) {
           return COSE_INTERNAL_ERROR;
        }
    }

    return COSE_OK;
}

int cos_convert_to_gmt_time(char* date, const char* format, apr_time_exp_t *tm) {
    int size = apr_snprintf(date, COS_MAX_GMT_TIME_LEN, format,
        g_s_wday[tm->tm_wday], tm->tm_mday, g_s_mon[tm->tm_mon], 1900 + tm->tm_year, tm->tm_hour, tm->tm_min, tm->tm_sec);
    if (size >= 0 && size < COS_MAX_GMT_TIME_LEN) {
        return COSE_OK;
    } else {
        return COSE_INTERNAL_ERROR;
    }
}

int cos_get_gmt_str_time(char datestr[COS_MAX_GMT_TIME_LEN]) {
    int s;
    apr_time_t now;
    char buf[128];
    apr_time_exp_t result;

    now = apr_time_now();
    if ((s = apr_time_exp_gmt(&result, now)) != APR_SUCCESS) {
        cos_error_log("apr_time_exp_gmt fialure, code:%d %s.", s, apr_strerror(s, buf, sizeof(buf)));
        return COSE_INTERNAL_ERROR;
    }

    if ((s = cos_convert_to_gmt_time(datestr, g_s_gmt_format, &result))
        != COSE_OK) {
        cos_error_log("cos_convert_to_GMT failure, code:%d.", s);
    }

    return s;
}

int cos_url_encode(char *dest, const char *src, int maxSrcSize) {
    static const char *hex = "0123456789ABCDEF";

    int len = 0;
    unsigned char c;

    while (*src) {
        if (++len > maxSrcSize) {
            *dest = 0;
            return COSE_INVALID_ARGUMENT;
        }
        c = *src;
        if (isalnum(c) || (c == '-') || (c == '_') || (c == '.') || (c == '~')) {
            *dest++ = c;
        } else if (*src == ' ') {
            *dest++ = '%';
            *dest++ = '2';
            *dest++ = '0';
        } else {
            *dest++ = '%';
            *dest++ = hex[c >> 4];
            *dest++ = hex[c & 15];
        }
        src++;
    }

    *dest = 0;

    return COSE_OK;
}

static int table_dict_cmp(const void * a, const void * b) {
   return strcasecmp(((cos_table_entry_t*)a)->key, ((cos_table_entry_t*)b)->key);
}

void cos_table_sort_by_dict(cos_table_t *table) {
    const cos_array_header_t *tarr;
    const cos_table_entry_t *telts;

    if (apr_is_empty_table(table)) {
        return;
    }

    tarr = cos_table_elts(table);
    telts = (cos_table_entry_t*)tarr->elts;

    qsort((void *)telts, tarr->nelts, tarr->elt_size, table_dict_cmp);
}

void cos_init_sign_header_table() {
    int idx = 0;

    if (g_sign_header_table != NULL && !apr_is_empty_table(g_sign_header_table)) {
        return;
    }

    cos_pool_create(&g_table_pool, NULL);
    g_sign_header_table = cos_table_make(g_table_pool, SIGN_HEADER_NUM);
    for (; idx < SIGN_HEADER_NUM; idx++) {
        apr_table_add(g_sign_header_table, SIGN_HEADER[idx], "");
    }
}

void cos_deinit_sign_header_table() {
    if (g_sign_header_table != NULL) {
        apr_table_clear(g_sign_header_table);
        g_sign_header_table = NULL;
    }

    if (g_table_pool != NULL) {
        cos_pool_destroy(g_table_pool);
        g_table_pool = NULL;
    }
}

static void cos_strlow(char *str) {
    while (*str) {
        *str = tolower(*str);
        str++;
    }
}

int cos_query_params_to_string(cos_pool_t *p, cos_table_t *query_params, cos_string_t *querystr) {
    int rs;
    int pos;
    int len;
    char sep = '?';
    char ebuf[COS_MAX_QUERY_ARG_LEN*3+1];
    char abuf[COS_MAX_QUERY_ARG_LEN*6+128];
    int max_len;
    const cos_array_header_t *tarr;
    const cos_table_entry_t *telts;
    cos_buf_t *querybuf;

    if (apr_is_empty_table(query_params)) {
        return COSE_OK;
    }

    max_len = sizeof(abuf)-1;
    querybuf = cos_create_buf(p, 256);
    cos_str_null(querystr);

    tarr = cos_table_elts(query_params);
    telts = (cos_table_entry_t*)tarr->elts;

    for (pos = 0; pos < tarr->nelts; ++pos) {
        if ((rs = cos_url_encode(ebuf, telts[pos].key, COS_MAX_QUERY_ARG_LEN)) != COSE_OK) {
            cos_error_log("query params args too big, key:%s.", telts[pos].key);
            return COSE_INVALID_ARGUMENT;
        }
        len = apr_snprintf(abuf, max_len, "%c%s", sep, ebuf);
        if (telts[pos].val != NULL && *telts[pos].val != '\0') {
            if ((rs = cos_url_encode(ebuf, telts[pos].val, COS_MAX_QUERY_ARG_LEN)) != COSE_OK) {
                cos_error_log("query params args too big, value:%s.", telts[pos].val);
                return COSE_INVALID_ARGUMENT;
            }
            len += apr_snprintf(abuf+len, max_len-len, "=%s", ebuf);
            if (len >= COS_MAX_QUERY_ARG_LEN) {
                cos_error_log("query params args too big, %s.", abuf);
                return COSE_INVALID_ARGUMENT;
            }
        }
        cos_buf_append_string(p, querybuf, abuf, len);
        sep = '&';
    }

    // result
    querystr->data = (char *)querybuf->pos;
    querystr->len = cos_buf_size(querybuf);

    return COSE_OK;
}

static int is_sign_header(const char *header) {
    return (apr_table_get(g_sign_header_table, header) != NULL) ||
            (strstr(header, X_COS_HEADER) == header) ||
            (strstr(header, X_CI_HEADER) == header);
}

static int is_empty_header_value(char *value) {
    return value != NULL && *value == '\0';
}

int cos_table_to_string(cos_pool_t *p, const cos_table_t *table, cos_string_t *querystr, sign_content_type_e sign_type) {
    int rs;
    int pos;
    int len;
    char *sep = "";
    char ebuf[COS_MAX_QUERY_ARG_LEN*3+1];
    char abuf[COS_MAX_QUERY_ARG_LEN*6+128];
    int max_len;
    const cos_array_header_t *tarr;
    const cos_table_entry_t *telts;
    cos_buf_t *querybuf;

    if (apr_is_empty_table(table)) {
        return COSE_OK;
    }

    max_len = sizeof(abuf)-1;
    querybuf = cos_create_buf(p, COS_MAX_QUERY_ARG_LEN);
    cos_str_null(querystr);

    tarr = cos_table_elts(table);
    telts = (cos_table_entry_t*)tarr->elts;

    for (pos = 0; pos < tarr->nelts; ++pos) {
        if ((rs = cos_url_encode(ebuf, telts[pos].key, COS_MAX_QUERY_ARG_LEN)) != COSE_OK) {
            cos_error_log("table params args too big, key:%s.", telts[pos].key);
            return COSE_INVALID_ARGUMENT;
        }
        cos_strlow(ebuf);

        if (sign_type == sign_content_header) {
            if (!is_sign_header(ebuf) || is_empty_header_value(telts[pos].val)) {
                continue;
            }
        }

        len = apr_snprintf(abuf, max_len, "%s%s", sep, ebuf);
        if (telts[pos].val != NULL) {
            if ((rs = cos_url_encode(ebuf, telts[pos].val, COS_MAX_QUERY_ARG_LEN)) != COSE_OK) {
                cos_error_log("table params args too big, value:%s.", telts[pos].val);
                return COSE_INVALID_ARGUMENT;
            }
            len += apr_snprintf(abuf+len, max_len-len, "=%s", ebuf);
            if (len >= COS_MAX_QUERY_ARG_LEN) {
                cos_error_log("table params args too big, %s.", abuf);
                return COSE_INVALID_ARGUMENT;
            }
        }
        cos_buf_append_string(p, querybuf, abuf, len);
        sep = "&";
    }

    // result
    querystr->data = (char *)querybuf->pos;
    querystr->len = cos_buf_size(querybuf);

    return COSE_OK;
}

int cos_table_key_to_string(cos_pool_t *p, const cos_table_t *table, cos_string_t *querystr, sign_content_type_e sign_type) {
    int rs;
    int pos;
    int len;
    char *sep = "";
    char ebuf[COS_MAX_QUERY_ARG_LEN*3+1];
    char abuf[COS_MAX_QUERY_ARG_LEN*6+128];
    int max_len;
    const cos_array_header_t *tarr;
    const cos_table_entry_t *telts;
    cos_buf_t *querybuf;

    if (apr_is_empty_table(table)) {
        return COSE_OK;
    }

    max_len = sizeof(abuf)-1;
    querybuf = cos_create_buf(p, 256);
    cos_str_null(querystr);

    tarr = cos_table_elts(table);
    telts = (cos_table_entry_t*)tarr->elts;

    for (pos = 0; pos < tarr->nelts; ++pos) {
        if ((rs = cos_url_encode(ebuf, telts[pos].key, COS_MAX_QUERY_ARG_LEN)) != COSE_OK) {
            cos_error_log("table params args too big, key:%s.", telts[pos].key);
            return COSE_INVALID_ARGUMENT;
        }
        cos_strlow(ebuf);

        if (sign_type == sign_content_header) {
            if (!is_sign_header(ebuf) || is_empty_header_value(telts[pos].val)) {
                continue;
            }
        }

        len = apr_snprintf(abuf, max_len, "%s%s", sep, ebuf);
        cos_buf_append_string(p, querybuf, abuf, len);
        sep = ";";
    }

    // result
    querystr->data = (char *)querybuf->pos;
    querystr->len = cos_buf_size(querybuf);

    return COSE_OK;
}

const char* cos_http_method_to_string_lower(http_method_e method) {
    switch (method) {
        case HTTP_GET:
            return "get";
        case HTTP_HEAD:
            return "head";
        case HTTP_PUT:
            return "put";
        case HTTP_POST:
            return "post";
        case HTTP_DELETE:
            return "delete";
        default:
            return "unknown";
    }
}


int cos_base64_encode(const unsigned char *in, int inLen, char *out) {
    static const char *ENC =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    char *original_out = out;

    while (inLen) {
        // first 6 bits of char 1
        *out++ = ENC[*in >> 2];
        if (!--inLen) {
            // last 2 bits of char 1, 4 bits of 0
            *out++ = ENC[(*in & 0x3) << 4];
            *out++ = '=';
            *out++ = '=';
            break;
        }
        // last 2 bits of char 1, first 4 bits of char 2
        *out++ = ENC[((*in & 0x3) << 4) | (*(in + 1) >> 4)];
        in++;
        if (!--inLen) {
            // last 4 bits of char 2, 2 bits of 0
            *out++ = ENC[(*in & 0xF) << 2];
            *out++ = '=';
            break;
        }
        // last 4 bits of char 2, first 2 bits of char 3
        *out++ = ENC[((*in & 0xF) << 2) | (*(in + 1) >> 6)];
        in++;
        // last 6 bits of char 3
        *out++ = ENC[*in & 0x3F];
        in++, inLen--;
    }

    return (out - original_out);
}

// HMAC-SHA-1:
//
// K - is key padded with zeros to 512 bits
// m - is message
// OPAD - 0x5c5c5c...
// IPAD - 0x363636...
//
// HMAC(K,m) = SHA1((K ^ OPAD) . SHA1((K ^ IPAD) . m))
void HMAC_SHA1(unsigned char hmac[20], const unsigned char *key, int key_len,
               const unsigned char *message, int message_len) {
    unsigned char kopad[64], kipad[64];
    int i;
    unsigned char digest[APR_SHA1_DIGESTSIZE];
    apr_sha1_ctx_t context;

    if (key_len > 64) {
        key_len = 64;
    }

    for (i = 0; i < key_len; i++) {
        kopad[i] = key[i] ^ 0x5c;
        kipad[i] = key[i] ^ 0x36;
    }

    for ( ; i < 64; i++) {
        kopad[i] = 0 ^ 0x5c;
        kipad[i] = 0 ^ 0x36;
    }

    apr_sha1_init(&context);
    apr_sha1_update(&context, (const char *)kipad, 64);
    apr_sha1_update(&context, (const char *)message, (unsigned int)message_len);
    apr_sha1_final(digest, &context);

    apr_sha1_init(&context);
    apr_sha1_update(&context, (const char *)kopad, 64);
    apr_sha1_update(&context, (const char *)digest, 20);
    apr_sha1_final(hmac, &context);
}

unsigned char* cos_md5(cos_pool_t* pool, const char *in, apr_size_t in_len) {
    unsigned char* out;
    apr_md5_ctx_t context;

    //APR_MD5_DIGESTSIZE: The MD5 digest size, value is 16
    out = cos_palloc(pool, APR_MD5_DIGESTSIZE + 1);
    if (!out) {
        return NULL;
    }

    if (0 != apr_md5_init(&context)) {
        return NULL;
    }

    if (0 != apr_md5_update(&context, in, in_len)) {
        return NULL;
    }

    if (0 != apr_md5_final(out, &context)) {
        return NULL;
    }
    out[APR_MD5_DIGESTSIZE] = '\0';
    return out;
};

int cos_url_decode(const char *in, char *out) {
    static const char tbl[256] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         0, 1, 2, 3, 4, 5, 6, 7,  8, 9, -1, -1, -1, -1, -1, -1,
        -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
    };
    char c, v1, v2;

    if(in != NULL) {
        while((c=*in++) != '\0') {
            if(c == '%') {
                if(!(v1 = *in++) || (v1 = tbl[(unsigned char)v1]) < 0 ||
                   !(v2 = *in++) || (v2 = tbl[(unsigned char)v2]) < 0) {
                    *out = '\0';
                    return -1;
                }
                c = (v1<<4)|v2;
            } else if (c == '+') {
                c = ' ';
            }
            *out++ = c;
        }
    }
    *out = '\0';
    return 0;
}

/*
 * Convert a string to a int64_t integer.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
 */
int64_t cos_strtoll(const char *nptr, char **endptr, int base) {
    const char *s;
    /* LONGLONG */
    int64_t acc, cutoff;
    int c;
    int neg, any, cutlim;

    /* endptr may be NULL */

#ifdef __GNUC__
    /* This outrageous construct just to shut up a GCC warning. */
    (void) &acc; (void) &cutoff;
#endif

    /*
     * Skip white space and pick up leading +/- sign if any.
     * If base is 0, allow 0x for hex and 0 for octal, else
     * assume decimal; if base is already 16, allow 0x.
     */
    s = nptr;
    do {
        c = (unsigned char) *s++;
    } while (isspace(c));
    if (c == '-') {
        neg = 1;
        c = *s++;
    } else {
        neg = 0;
        if (c == '+')
            c = *s++;
    }
    if ((base == 0 || base == 16) &&
        c == '0' && (*s == 'x' || *s == 'X')) {
        c = s[1];
        s += 2;
        base = 16;
    }
    if (base == 0)
        base = c == '0' ? 8 : 10;

    /*
     * Compute the cutoff value between legal numbers and illegal
     * numbers.  That is the largest legal value, divided by the
     * base.  An input number that is greater than this value, if
     * followed by a legal input character, is too big.  One that
     * is equal to this value may be valid or not; the limit
     * between valid and invalid numbers is then based on the last
     * digit.  For instance, if the range for int64_ts is
     * [-9223372036854775808..9223372036854775807] and the input base
     * is 10, cutoff will be set to 922337203685477580 and cutlim to
     * either 7 (neg==0) or 8 (neg==1), meaning that if we have
     * accumulated a value > 922337203685477580, or equal but the
     * next digit is > 7 (or 8), the number is too big, and we will
     * return a range error.
     *
     * Set any if any `digits' consumed; make it negative to indicate
     * overflow.
     */
    cutoff = neg ? LLONG_MIN : LLONG_MAX;
    cutlim = (int)(cutoff % base);
    cutoff /= base;
    if (neg) {
        if (cutlim > 0) {
            cutlim -= base;
            cutoff += 1;
        }
        cutlim = -cutlim;
    }
    for (acc = 0, any = 0;; c = (unsigned char) *s++) {
        if (isdigit(c))
            c -= '0';
        else if (isalpha(c))
            c -= isupper(c) ? 'A' - 10 : 'a' - 10;
        else
            break;
        if (c >= base)
            break;
        if (any < 0)
            continue;
        if (neg) {
            if (acc < cutoff || (acc == cutoff && c > cutlim)) {
                any = -1;
                acc = LLONG_MIN;
                errno = ERANGE;
            } else {
                any = 1;
                acc *= base;
                acc -= c;
            }
        } else {
            if (acc > cutoff || (acc == cutoff && c > cutlim)) {
                any = -1;
                acc = LLONG_MAX;
                errno = ERANGE;
            } else {
                any = 1;
                acc *= base;
                acc += c;
            }
        }
    }
    if (endptr != 0)
        /* LINTED interface specification */
        *endptr = (char *)(any ? s - 1 : nptr);
    return (acc);
}

int64_t cos_atoi64(const char *nptr) {
    return cos_strtoull(nptr, NULL, 10);
}

uint64_t cos_strtoull(const char *nptr, char **endptr, int base) {
    const char *s;
    uint64_t acc, cutoff;
    int c;
    int neg, any, cutlim;

    /*
     * See strtoq for comments as to the logic used.
     */
    s = nptr;
    do {
        c = (unsigned char) *s++;
    } while (isspace(c));
    if (c == '-') {
        neg = 1;
        c = *s++;
    } else {
        neg = 0;
        if (c == '+')
            c = *s++;
    }
    if ((base == 0 || base == 16) &&
        c == '0' && (*s == 'x' || *s == 'X')) {
        c = s[1];
        s += 2;
        base = 16;
    }
    if (base == 0)
        base = c == '0' ? 8 : 10;

    cutoff = ULLONG_MAX / (uint64_t)base;
    cutlim = ULLONG_MAX % (uint64_t)base;
    for (acc = 0, any = 0;; c = (unsigned char) *s++) {
        if (isdigit(c))
            c -= '0';
        else if (isalpha(c))
            c -= isupper(c) ? 'A' - 10 : 'a' - 10;
        else
            break;
        if (c >= base)
            break;
        if (any < 0)
            continue;
        if (acc > cutoff || (acc == cutoff && c > cutlim)) {
            any = -1;
            acc = ULLONG_MAX;
            errno = ERANGE;
        } else {
            any = 1;
            acc *= (uint64_t)base;
            acc += c;
        }
    }
    if (neg && any > 0)
#ifdef WIN32
#pragma warning(disable : 4146)
#endif
        acc = -acc;
#ifdef WIN32
#pragma warning(default : 4146)
#endif
    if (endptr != 0)
        *endptr = (char *) (any ? s - 1 : nptr);
    return (acc);
}

uint64_t cos_atoui64(const char *nptr) {
    return cos_strtoull(nptr, NULL, 10);
}


void cos_get_hex_from_digest(unsigned char hexdigest[40], unsigned char digest[20]) {
    unsigned char hex_digits[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                                    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    int j = 0;
    int i = 0;

    for(; i < 20; i++)
    {
        hexdigest[j++] = hex_digits[(digest[i] >> 4) & 0x0f];
        hexdigest[j++] = hex_digits[digest[i] & 0x0f];
    }
}

void cos_get_hmac_sha1_hexdigest(unsigned char hexdigest[40], const unsigned char *key, int key_len,
                                               const unsigned char *message, int message_len) {
    unsigned char hmac[20];

    HMAC_SHA1(hmac, key, key_len, message, message_len);

    cos_get_hex_from_digest(hexdigest, hmac);
}

void cos_get_sha1_hexdigest(unsigned char hexdigest[40], const unsigned char *message, int message_len) {
    unsigned char digest[20];
    apr_sha1_ctx_t context;

    apr_sha1_init(&context);
    apr_sha1_update(&context, (const char *)message, (unsigned int)message_len);
    apr_sha1_final(digest, &context);

    cos_get_hex_from_digest(hexdigest, digest);
}



