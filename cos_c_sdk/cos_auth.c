#include "cos_auth.h"
#include "cos_log.h"
#include "cos_utility.h"

#if 0
static const char *g_s_cos_sub_resource_list[] = {
    "acl",
    "uploadId",
    "uploads",
    "partNumber",
    "response-content-type",
    "response-content-language",
    "response-expires",
    "response-cache-control",
    "response-content-disposition",
    "response-content-encoding",
    "append",
    "position",
    "lifecycle",
    "delete",
    "live",
    "status",
    "comp",
    "vod",
    "startTime",
    "endTime",
    "x-cos-process",
    "security-token",
    NULL,
};
#endif

int cos_get_string_to_sign(cos_pool_t *p,
                           http_method_e method,
                           const cos_string_t *secret_id,
                           const cos_string_t *secret_key,
                           const cos_string_t *canon_res,
                           const cos_table_t *headers,
                           const cos_table_t *params,
                           const int64_t expire,
                           cos_string_t *signstr) {
    cos_buf_t *fmt_str;
    cos_buf_t *sign_str;
    const char *value;
    apr_time_t now;
    unsigned char time_str[64];
    int time_str_len = 0;
    unsigned char hexdigest[40];
    unsigned char sign_key[40];
    cos_table_t *sort_headers;
    cos_table_t *sort_params;
    cos_string_t params_str = cos_null_string;
    cos_string_t header_str = cos_null_string;
    cos_string_t paramslist_str;
    cos_string_t header_list_str;
    int res;

    cos_str_null(signstr);

    // used copy to sort for build http param(must be copy, otherwise apr_table_get() will be abnormal)
    sort_headers = apr_table_copy(p, headers);
    sort_params = apr_table_copy(p, params);
    cos_table_sort_by_dict(sort_headers);
    cos_table_sort_by_dict(sort_params);

    fmt_str = cos_create_buf(p, 1024);
    if (NULL == fmt_str) {
        cos_error_log("failed to call cos_create_buf.");
        return COSE_OVER_MEMORY;
    }
    sign_str = cos_create_buf(p, 256);
    if (NULL == sign_str) {
        cos_error_log("failed to call cos_create_buf.");
        return COSE_OVER_MEMORY;
    }

    // method
    value = cos_http_method_to_string_lower(method);
    cos_buf_append_string(p, fmt_str, value, strlen(value));
    cos_buf_append_string(p, fmt_str, "\n", sizeof("\n")-1);

    // canonicalized resource(URI)
    cos_buf_append_string(p, fmt_str, canon_res->data, canon_res->len);
    cos_buf_append_string(p, fmt_str, "\n", sizeof("\n")-1);

    // query-parameters
    res = cos_table_to_string(p, sort_params, &params_str, sign_content_query_params);
    if (res != COSE_OK) return res;

    cos_buf_append_string(p, fmt_str, params_str.data, params_str.len);
    cos_buf_append_string(p, fmt_str, "\n", sizeof("\n")-1);

    // headers
    res = cos_table_to_string(p, sort_headers, &header_str, sign_content_header);
    if (res != COSE_OK) return res;

    cos_buf_append_string(p, fmt_str, header_str.data, header_str.len);
    cos_buf_append_string(p, fmt_str, "\n", sizeof("\n")-1);

    // Format-String sha1hash
    cos_get_sha1_hexdigest(hexdigest, fmt_str->pos, cos_buf_size(fmt_str));

    // construct the string to sign
    cos_buf_append_string(p, sign_str, "sha1\n", sizeof("sha1\n")-1);
    now = apr_time_sec(apr_time_now());
    time_str_len = apr_snprintf((char*)time_str, 64, "%"APR_INT64_T_FMT";%"APR_INT64_T_FMT, now, now + expire);
    cos_buf_append_string(p, sign_str, (char*)time_str, time_str_len);
    cos_buf_append_string(p, sign_str, "\n", sizeof("\n")-1);
    cos_buf_append_string(p, sign_str, (const char*)hexdigest, sizeof(hexdigest));
    cos_buf_append_string(p, sign_str, "\n", sizeof("\n")-1);
    cos_get_hmac_sha1_hexdigest(sign_key, (unsigned char*)secret_key->data, secret_key->len, time_str, time_str_len);
    cos_get_hmac_sha1_hexdigest(hexdigest, sign_key, sizeof(sign_key), sign_str->pos, cos_buf_size(sign_str));

    cos_str_set(&header_list_str, "");
    (void)cos_table_key_to_string(p, sort_headers, &header_list_str, sign_content_header);
    cos_str_set(&paramslist_str, "");
    (void)cos_table_key_to_string(p, sort_params, &paramslist_str, sign_content_query_params);

    value = apr_psprintf(p, "q-sign-algorithm=sha1&q-ak=%.*s&q-sign-time=%.*s&q-key-time=%.*s&q-header-list=%.*s&q-url-param-list=%.*s&q-signature=%.*s",
                         secret_id->len, secret_id->data,
                         time_str_len, (char*)time_str,
                         time_str_len, (char*)time_str,
                         header_list_str.len, header_list_str.data,
                         paramslist_str.len, paramslist_str.data,
                         (int)sizeof(hexdigest), hexdigest);

    // result
    signstr->data = (char *)value;
    signstr->len = strlen(value);

    return COSE_OK;
}

void cos_sign_headers(cos_pool_t *p,
                      const cos_string_t *signstr,
                      const cos_string_t *access_key_id,
                      const cos_string_t *access_key_secret,
                      cos_table_t *headers) {
    apr_table_setn(headers, COS_AUTHORIZATION, signstr->data);

    return;
}

int cos_get_signed_headers(cos_pool_t *p, 
                           const cos_string_t *access_key_id,
                           const cos_string_t *access_key_secret,
                           const cos_string_t* canon_res,
                           cos_http_request_t *req) {
    int res;
    cos_string_t signstr;
    if (cos_is_null_string(access_key_id)) return COSE_OK;

    res = cos_get_string_to_sign(p, req->method, access_key_id, access_key_secret, canon_res,
                                 req->headers, req->query_params, COS_AUTH_EXPIRE_DEFAULT, &signstr);
    
    if (res != COSE_OK) return res;

    cos_debug_log("signstr:%.*s.", signstr.len, signstr.data);

    cos_sign_headers(p, &signstr, access_key_id, access_key_secret, req->headers);

    return COSE_OK;
}

int cos_sign_request(cos_http_request_t *req,
                     const cos_config_t *config) {
    cos_string_t canon_res;
    char canon_buf[COS_MAX_URI_LEN];
    char datestr[COS_MAX_GMT_TIME_LEN];
    const char *value;
    int res = COSE_OK;
    int len = 0;

    len = strlen(req->resource);
    if (len >= COS_MAX_URI_LEN - 1) {
        cos_error_log("http resource too long, %s.", req->resource);
        return COSE_INVALID_ARGUMENT;
    }

    canon_res.data = canon_buf;
    canon_res.len = apr_snprintf(canon_buf, sizeof(canon_buf), "/%s", req->resource);

    if ((value = apr_table_get(req->headers, COS_CANNONICALIZED_HEADER_DATE)) == NULL) {
        cos_get_gmt_str_time(datestr);
        apr_table_set(req->headers, COS_DATE, datestr);
    }

    if (req->host && !apr_table_get(req->headers, COS_HOST)) {
        apr_table_set(req->headers, COS_HOST, req->host);
    }

    res = cos_get_signed_headers(req->pool, &config->access_key_id,
                                 &config->access_key_secret, &canon_res, req);
    return res;
}

