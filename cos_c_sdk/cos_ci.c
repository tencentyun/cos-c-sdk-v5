#include "cos_log.h"
#include "cos_sys_util.h"
#include "cos_string.h"
#include "cos_status.h"
#include "cos_auth.h"
#include "cos_utility.h"
#include "cos_xml.h"
#include "cos_api.h"


static cos_string_t video_auditing_uri = cos_string("video/auditing");


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

static inline ci_media_buckets_result_t *ci_create_media_buckets_result(cos_pool_t *p)
{
    ci_media_buckets_result_t *res = (ci_media_buckets_result_t *)cos_pcalloc(p, sizeof(ci_media_buckets_result_t));
    return res;
}

static inline ci_media_info_result_t *ci_create_media_info_result(cos_pool_t *p)
{
    ci_media_info_result_t *res = (ci_media_info_result_t *)cos_pcalloc(p, sizeof(ci_media_info_result_t));
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

    uri.data = apr_psprintf(options->pool, "%.*s/%.*s", video_auditing_uri.len, video_auditing_uri.data,
            job_id->len, job_id->data);
    uri.len = strlen(uri.data);

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

static cos_table_t* build_media_bucket_query_params(cos_pool_t *p, const ci_media_buckets_request_t *media_request)
{
    char *value = NULL;
    cos_table_t *query_params = NULL;

    if (media_request != NULL) {
        query_params = cos_table_make(p, 0);
        if (cos_string_valid(&media_request->regions)) {
            value = apr_psprintf(p, "%.*s", media_request->regions.len, media_request->regions.data);
            apr_table_add(query_params, "regions", value);
        }
        if (cos_string_valid(&media_request->bucket_names)) {
            value = apr_psprintf(p, "%.*s", media_request->bucket_names.len, media_request->bucket_names.data);
            apr_table_add(query_params, "bucketNames", value);
        }
        if (cos_string_valid(&media_request->bucket_name)) {
            value = apr_psprintf(p, "%.*s", media_request->bucket_name.len, media_request->bucket_name.data);
            apr_table_add(query_params, "bucketName", value);
        }
        if (cos_string_valid(&media_request->page_number)) {
            value = apr_psprintf(p, "%.*s", media_request->page_number.len, media_request->page_number.data);
            apr_table_add(query_params, "pageNumber", value);
        }
        if (cos_string_valid(&media_request->page_size)) {
            value = apr_psprintf(p, "%.*s", media_request->page_size.len, media_request->page_size.data);
            apr_table_add(query_params, "pageSize", value);
        }
    }

    return query_params;
}

cos_status_t *ci_describe_media_buckets(const cos_request_options_t *options,
                                        const ci_media_buckets_request_t *media_request,
                                        cos_table_t *headers, 
                                        cos_table_t **resp_headers,
                                        ci_media_buckets_result_t **media_result)
{
    int res;
    cos_status_t *s = NULL;
    cos_http_request_t *req = NULL;
    cos_http_response_t *resp = NULL;
    cos_table_t *query_params = NULL;

    headers = cos_table_create_if_null(options, headers, 1);
    query_params = build_media_bucket_query_params(options->pool, media_request);

    cos_init_media_buckets_request(options, HTTP_GET, &req, query_params, headers, &resp);
    apr_table_addn(headers, COS_CONTENT_TYPE, "application/xml");

    s = cos_process_request(options, req, resp);
    cos_fill_read_response_header(resp, resp_headers);
    if (!cos_status_is_ok(s)) {
        return s;
    }

    *media_result = ci_create_media_buckets_result(options->pool);
    if (*media_result == NULL) {
        cos_xml_error_status_set(s, COSE_OUT_MEMORY);
        return s;
    }
    res = ci_media_buckets_result_parse_from_body(options->pool, &resp->body, *media_result, s);
    if (res != COSE_OK) {
        cos_xml_error_status_set(s, res);
    }

    return s;
}

static cos_table_t* build_snapshot_query_params(cos_pool_t *p, const ci_get_snapshot_request_t *snapshot_request)
{
    char *value;
    cos_table_t *query_params = cos_table_make(p, 1);
    apr_table_add(query_params, "ci-process", "snapshot");

    if (snapshot_request != NULL) {
        cos_table_add_float(query_params, "time", snapshot_request->time);
        cos_table_add_int(query_params, "width", snapshot_request->width);
        cos_table_add_int(query_params, "height", snapshot_request->height);
        if (cos_string_valid(&snapshot_request->format)) {
            value = apr_psprintf(p, "%.*s", snapshot_request->format.len, snapshot_request->format.data);
            apr_table_add(query_params, "format", value);
        }
        if (cos_string_valid(&snapshot_request->rotate)) {
            value = apr_psprintf(p, "%.*s", snapshot_request->rotate.len, snapshot_request->rotate.data);
            apr_table_add(query_params, "rotate", value);
        }
        if (cos_string_valid(&snapshot_request->mode)) {
            value = apr_psprintf(p, "%.*s", snapshot_request->mode.len, snapshot_request->mode.data);
            apr_table_add(query_params, "mode", value);
        }
    }

    return query_params;
}

cos_status_t *ci_get_snapshot_to_buffer(const cos_request_options_t *options,
                                        const cos_string_t *bucket, 
                                        const cos_string_t *object,
                                        const ci_get_snapshot_request_t *snapshot_request,
                                        cos_table_t *headers, 
                                        cos_list_t *buffer, 
                                        cos_table_t **resp_headers)
{
    cos_status_t *s = NULL;
    cos_http_request_t *req = NULL;
    cos_http_response_t *resp = NULL;
    cos_table_t *query_params = NULL;

    headers = cos_table_create_if_null(options, headers, 0);
    query_params = build_snapshot_query_params(options->pool, snapshot_request);

    cos_init_object_request(options, bucket, object, HTTP_GET, 
                            &req, query_params, headers, NULL, 0, &resp);

    s = cos_process_request(options, req, resp);
    cos_fill_read_response_body(resp, buffer);
    cos_fill_read_response_header(resp, resp_headers);

    return s;
}

cos_status_t *ci_get_snapshot_to_file(const cos_request_options_t *options,
                                      const cos_string_t *bucket, 
                                      const cos_string_t *object,
                                      const ci_get_snapshot_request_t *snapshot_request,
                                      cos_table_t *headers, 
                                      cos_string_t *filename, 
                                      cos_table_t **resp_headers)
{
    cos_status_t *s = NULL;
    cos_http_request_t *req = NULL;
    cos_http_response_t *resp = NULL;
    cos_table_t *query_params = NULL;
    int res = COSE_OK;
    cos_string_t tmp_filename;

    headers = cos_table_create_if_null(options, headers, 0);
    query_params = build_snapshot_query_params(options->pool, snapshot_request);

    cos_get_temporary_file_name(options->pool, filename, &tmp_filename);

    cos_init_object_request(options, bucket, object, HTTP_GET, 
                            &req, query_params, headers, NULL, 0, &resp);

    s = cos_status_create(options->pool);
    res = cos_init_read_response_body_to_file(options->pool, &tmp_filename, resp);
    if (res != COSE_OK) {
        cos_file_error_status_set(s, res);
        return s;
    }

    s = cos_process_request(options, req, resp);
    cos_fill_read_response_header(resp, resp_headers);

    cos_temp_file_rename(s, tmp_filename.data, filename->data, options->pool);

    return s;
}

static cos_table_t* build_media_info_query_params(cos_pool_t *p)
{
    cos_table_t *query_params = cos_table_make(p, 1);
    apr_table_add(query_params, "ci-process", "videoinfo");

    return query_params;
}

cos_status_t *ci_get_media_info(const cos_request_options_t *options,
                                const cos_string_t *bucket, 
                                const cos_string_t *object,
                                cos_table_t *headers, 
                                cos_table_t **resp_headers,
                                ci_media_info_result_t **media_result)
{
    int res;
    cos_status_t *s = NULL;
    cos_http_request_t *req = NULL;
    cos_http_response_t *resp = NULL;
    cos_table_t *query_params = NULL;

    headers = cos_table_create_if_null(options, headers, 0);
    query_params = build_media_info_query_params(options->pool);

    cos_init_object_request(options, bucket, object, HTTP_GET, 
                            &req, query_params, headers, NULL, 0, &resp);

    s = cos_process_request(options, req, resp);
    cos_fill_read_response_header(resp, resp_headers);
    if (!cos_status_is_ok(s)) {
        return s;
    }

    *media_result = ci_create_media_info_result(options->pool);
    if (*media_result == NULL) {
        cos_xml_error_status_set(s, COSE_OUT_MEMORY);
        return s;
    }
    res = ci_media_info_result_parse_from_body(options->pool, &resp->body, *media_result);
    if (res != COSE_OK) {
        cos_xml_error_status_set(s, res);
    }

    return s;
}