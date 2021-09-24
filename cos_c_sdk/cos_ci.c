#include "cos_log.h"
#include "cos_sys_util.h"
#include "cos_string.h"
#include "cos_status.h"
#include "cos_auth.h"
#include "cos_utility.h"
#include "cos_xml.h"
#include "cos_api.h"


static cos_string_t video_auditing_uri = cos_string("video/auditing");
static cos_status_t init_status = {0};


static inline ci_video_auditing_job_result_t *ci_create_video_auditing_job_result(cos_pool_t *p)
{
    ci_video_auditing_job_result_t *res = (ci_video_auditing_job_result_t *)cos_pcalloc(p, sizeof(ci_video_auditing_job_result_t));
    return res;
}

static inline ci_auditing_job_result_t *ci_create_get_auditing_job_result(cos_pool_t *p)
{
    ci_auditing_job_result_t *res = (ci_auditing_job_result_t *)cos_pcalloc(p, sizeof(ci_auditing_job_result_t));
    return res;
}

cos_status_t *ci_create_video_auditing_job(const cos_request_options_t *options,
                                           const cos_string_t *bucket, 
                                           const ci_video_auditing_job_options_t *job_options,
                                           cos_table_t *headers, 
                                           cos_table_t **resp_headers,
                                           ci_video_auditing_job_result_t **job_result)
{
    int res;
    cos_status_t *s = NULL;
    cos_http_request_t *req = NULL;
    cos_http_response_t *resp = NULL;
    cos_list_t body;

    headers = cos_table_create_if_null(options, headers, 1);

    cos_init_object_request(options, bucket, &video_auditing_uri, HTTP_POST, &req,
            NULL, headers, NULL, 0, &resp);
    
    apr_table_addn(headers, COS_CONTENT_TYPE, "application/xml");
    build_video_auditing_job_body(options->pool, job_options, &body);
    cos_write_request_body_from_buffer(&body, req);

    s = cos_process_request(options, req, resp);
    cos_fill_read_response_header(resp, resp_headers);
    if (!cos_status_is_ok(s)) {
        return s;
    }

    *job_result = ci_create_video_auditing_job_result(options->pool);
    if (*job_result == NULL) {
        cos_xml_error_status_set(s, COSE_OUT_MEMORY);
        return s;
    }
    res = ci_video_auditing_result_parse_from_body(options->pool, &resp->body, *job_result, s);
    if (res != COSE_OK) {
        cos_xml_error_status_set(s, res);
    }

    return s;
}

cos_status_t *ci_get_auditing_job(const cos_request_options_t *options,
                                  const cos_string_t *bucket, 
                                  const cos_string_t *job_id,
                                  cos_table_t *headers, 
                                  cos_table_t **resp_headers,
                                  ci_auditing_job_result_t **job_result)
{
    int res;
    cos_string_t uri;
    cos_status_t *s = NULL;
    cos_http_request_t *req = NULL;
    cos_http_response_t *resp = NULL;

    headers = cos_table_create_if_null(options, headers, 0);

    uri.len = video_auditing_uri.len + 1 + job_id->len + 1;
    uri.data = cos_palloc(options->pool, uri.len);
    if (uri.data == NULL) {
        cos_xml_error_status_set(&init_status, COSE_OUT_MEMORY);
        return &init_status;
    }
    strncpy(uri.data, video_auditing_uri.data, video_auditing_uri.len);
    uri.data[video_auditing_uri.len] = '/';
    strncpy(uri.data + video_auditing_uri.len + 1, job_id->data, job_id->len);
    uri.data[uri.len - 1] = '\0';
    uri.len--;

    cos_init_object_request(options, bucket, &uri, HTTP_GET, &req,
            NULL, headers, NULL, 0, &resp);

    s = cos_process_request(options, req, resp);
    cos_fill_read_response_header(resp, resp_headers);
    if (!cos_status_is_ok(s)) {
        return s;
    }

    *job_result = ci_create_get_auditing_job_result(options->pool);
    if (*job_result == NULL) {
        cos_xml_error_status_set(s, COSE_OUT_MEMORY);
        return s;
    }
    res = ci_get_auditing_result_parse_from_body(options->pool, &resp->body, *job_result, s);
    if (res != COSE_OK) {
        cos_xml_error_status_set(s, res);
    }

    return s;
}