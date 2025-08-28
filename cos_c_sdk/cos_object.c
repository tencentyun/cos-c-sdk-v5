#include "cos_log.h"
#include "cos_sys_util.h"
#include "cos_string.h"
#include "cos_status.h"
#include "cos_auth.h"
#include "cos_utility.h"
#include "cos_xml.h"
#include "cos_api.h"

cos_status_t *cos_put_object_from_buffer(const cos_request_options_t *options,
                                         const cos_string_t *bucket,
                                         const cos_string_t *object,
                                         cos_list_t *buffer,
                                         cos_table_t *headers,
                                         cos_table_t **resp_headers) {
    return cos_do_put_object_from_buffer(options, bucket, object, buffer,
                                         headers, NULL, NULL, resp_headers, NULL);
}

cos_status_t *cos_do_put_object_from_buffer(const cos_request_options_t *options,
                                            const cos_string_t *bucket,
                                            const cos_string_t *object,
                                            cos_list_t *buffer,
                                            cos_table_t *headers,
                                            cos_table_t *params,
                                            cos_progress_callback progress_callback,
                                            cos_table_t **resp_headers,
                                            cos_list_t *resp_body) {
    cos_status_t *s = NULL;
    cos_http_request_t *req = NULL;
    cos_http_response_t *resp = NULL;
    cos_table_t *query_params = NULL;
    char *error_msg = NULL;

    headers = cos_table_create_if_null(options, headers, 2);
    set_content_type(NULL, object->data, headers);
    apr_table_add(headers, COS_EXPECT, "");

    query_params = cos_table_create_if_null(options, params, 0);

    cos_add_content_md5_from_buffer(options, buffer, headers);

    if (!cos_init_object_request(options, bucket, object, HTTP_PUT,
                            &req, query_params, headers, progress_callback, 0, &resp, &error_msg)) {
        cos_invalid_param_status_set(options, s, error_msg);
        return s;
    }
    cos_write_request_body_from_buffer(options->pool, buffer, req, headers);

    s = cos_process_request(options, req, resp, 1);
    cos_fill_read_response_body(resp, resp_body);
    cos_fill_read_response_header(resp, resp_headers);

    if (is_enable_crc(options) && has_crc_in_response(resp)) {
        cos_check_crc_consistent(req->crc64, resp->headers, s);
    }

    return s;
}

cos_status_t *cos_put_object_from_file(const cos_request_options_t *options,
                                       const cos_string_t *bucket,
                                       const cos_string_t *object,
                                       const cos_string_t *filename,
                                       cos_table_t *headers,
                                       cos_table_t **resp_headers) {
    return cos_do_put_object_from_file(options, bucket, object, filename,
                                       headers, NULL, NULL, resp_headers, NULL);
}

cos_status_t *cos_do_put_object_from_file(const cos_request_options_t *options,
                                          const cos_string_t *bucket,
                                          const cos_string_t *object,
                                          const cos_string_t *filename,
                                          cos_table_t *headers,
                                          cos_table_t *params,
                                          cos_progress_callback progress_callback,
                                          cos_table_t **resp_headers,
                                          cos_list_t *resp_body) {
    cos_status_t *s = NULL;
    cos_http_request_t *req = NULL;
    cos_http_response_t *resp = NULL;
    cos_table_t *query_params = NULL;
    int res = COSE_OK;
    char *error_msg = NULL;

    s = cos_status_create(options->pool);

    headers = cos_table_create_if_null(options, headers, 2);
    set_content_type(filename->data, object->data, headers);
    apr_table_add(headers, COS_EXPECT, "");

    query_params = cos_table_create_if_null(options, params, 0);

    cos_add_content_md5_from_file(options, filename, headers);

    if (!cos_init_object_request(options, bucket, object, HTTP_PUT, &req,
                            query_params, headers, progress_callback, 0, &resp, &error_msg)) {
        cos_invalid_param_status_set(options, s, error_msg);
        return s;
    }

    res = cos_write_request_body_from_file(options->pool, filename, req, headers);
    if (res != COSE_OK) {
        cos_file_error_status_set(s, res);
        return s;
    }

    s = cos_process_request(options, req, resp, 1);
    cos_fill_read_response_body(resp, resp_body);
    cos_fill_read_response_header(resp, resp_headers);

    if (is_enable_crc(options) && has_crc_in_response(resp)) {
        cos_check_crc_consistent(req->crc64, resp->headers, s);
    }

    return s;
}

cos_status_t *cos_get_object_to_buffer(const cos_request_options_t *options,
                                       const cos_string_t *bucket,
                                       const cos_string_t *object,
                                       cos_table_t *headers,
                                       cos_table_t *params,
                                       cos_list_t *buffer,
                                       cos_table_t **resp_headers) {
    return cos_do_get_object_to_buffer(options, bucket, object, headers,
                                       params, buffer, NULL, resp_headers);
}

cos_status_t *cos_do_get_object_to_buffer(const cos_request_options_t *options,
                                          const cos_string_t *bucket,
                                          const cos_string_t *object,
                                          cos_table_t *headers,
                                          cos_table_t *params,
                                          cos_list_t *buffer,
                                          cos_progress_callback progress_callback,
                                          cos_table_t **resp_headers) {
    cos_status_t *s = NULL;
    if (!object_key_simplify_check(object->data)) {
        s = cos_status_create(options->pool);
        cos_status_set(s, COSE_INVALID_ARGUMENT, COS_CLIENT_ERROR_CODE, "The Getobject Key is illegal");
        return s;
    }
    cos_http_request_t *req = NULL;
    cos_http_response_t *resp = NULL;
    char *error_msg = NULL;

    headers = cos_table_create_if_null(options, headers, 0);
    params = cos_table_create_if_null(options, params, 0);

    if (!cos_init_object_request(options, bucket, object, HTTP_GET,
                            &req, params, headers, progress_callback, 0, &resp, &error_msg)) {
        cos_invalid_param_status_set(options, s, error_msg);
        return s;
    }

    s = cos_process_request(options, req, resp, 1);
    cos_fill_read_response_body(resp, buffer);
    cos_fill_read_response_header(resp, resp_headers);

    if (is_enable_crc(options) && has_crc_in_response(resp) &&
        !has_range_or_process_in_request(req)) {
        cos_check_crc_consistent(resp->crc64, resp->headers, s);
    } else if (is_enable_crc(options)) {
        cos_check_len_consistent(buffer, resp->headers, s);
    }

    return s;
}

cos_status_t *cos_get_object_to_file(const cos_request_options_t *options,
                                     const cos_string_t *bucket,
                                     const cos_string_t *object,
                                     cos_table_t *headers,
                                     cos_table_t *params,
                                     cos_string_t *filename,
                                     cos_table_t **resp_headers) {
    return cos_do_get_object_to_file(options, bucket, object, headers,
                                     params, filename, NULL, resp_headers);
}

cos_status_t *cos_do_get_object_to_file(const cos_request_options_t *options,
                                        const cos_string_t *bucket,
                                        const cos_string_t *object,
                                        cos_table_t *headers,
                                        cos_table_t *params,
                                        cos_string_t *filename,
                                        cos_progress_callback progress_callback,
                                        cos_table_t **resp_headers) {
    cos_status_t *s = NULL;
    if (!object_key_simplify_check(object->data)) {
        s = cos_status_create(options->pool);
        cos_status_set(s, COSE_INVALID_ARGUMENT, COS_CLIENT_ERROR_CODE, "The Getobject Key is illegal");
        return s;
    }
    cos_http_request_t *req = NULL;
    cos_http_response_t *resp = NULL;
    int res = COSE_OK;
    cos_string_t tmp_filename;
    char *error_msg = NULL;

    headers = cos_table_create_if_null(options, headers, 0);
    params = cos_table_create_if_null(options, params, 0);

    cos_get_temporary_file_name(options->pool, filename, &tmp_filename);

    if (!cos_init_object_request(options, bucket, object, HTTP_GET,
                            &req, params, headers, progress_callback, 0, &resp, &error_msg)) {
        cos_invalid_param_status_set(options, s, error_msg);
        return s;
    }

    s = cos_status_create(options->pool);
    res = cos_init_read_response_body_to_file(options->pool, &tmp_filename, resp);
    if (res != COSE_OK) {
        cos_file_error_status_set(s, res);
        return s;
    }

    s = cos_process_request(options, req, resp, 1);
    cos_fill_read_response_header(resp, resp_headers);

    if (is_enable_crc(options) && has_crc_in_response(resp) &&
        !has_range_or_process_in_request(req)) {
            cos_check_crc_consistent(resp->crc64, resp->headers, s);
    }

    cos_temp_file_rename(s, tmp_filename.data, filename->data, options->pool);

    return s;
}

cos_status_t *cos_head_object(const cos_request_options_t *options,
                              const cos_string_t *bucket,
                              const cos_string_t *object,
                              cos_table_t *headers,
                              cos_table_t **resp_headers) {
    cos_status_t *s = NULL;
    cos_http_request_t *req = NULL;
    cos_http_response_t *resp = NULL;
    cos_table_t *query_params = NULL;
    char *error_msg = NULL;

    headers = cos_table_create_if_null(options, headers, 0);

    query_params = cos_table_create_if_null(options, query_params, 0);

    if (!cos_init_object_request(options, bucket, object, HTTP_HEAD,
                            &req, query_params, headers, NULL, 0, &resp, &error_msg)) {
        cos_invalid_param_status_set(options, s, error_msg);
        return s;
    }

    s = cos_process_request(options, req, resp, 1);
    cos_fill_read_response_header(resp, resp_headers);
    if(s != NULL && s->code == 404) {
        s->error_code = "NosuchKey";
    }

    return s;
}

cos_status_t *cos_check_object_exist(const cos_request_options_t *options,
                                     const cos_string_t *bucket,
                                     const cos_string_t *object,
                                     cos_table_t *headers,
                                     cos_object_exist_status_e *object_exist,
                                     cos_table_t **resp_headers) {
    cos_status_t *s = NULL;

    s = cos_head_object(options, bucket, object, headers, resp_headers);
    if (s->code == 200 || s->code == 304 || s->code == 412) {
        *object_exist = COS_OBJECT_EXIST;
    } else if (s->code == 404) {
        *object_exist = COS_OBJECT_NON_EXIST;
    } else {
        *object_exist = COS_OBJECT_UNKNOWN_EXIST;
    }

    return s;
}

cos_status_t *cos_delete_object(const cos_request_options_t *options,
                                const cos_string_t *bucket,
                                const cos_string_t *object,
                                cos_table_t **resp_headers) {
    return cos_do_delete_object(options, bucket, object, NULL, resp_headers);
}

cos_status_t *cos_do_delete_object(const cos_request_options_t *options,
                                const cos_string_t *bucket,
                                const cos_string_t *object,
                                cos_table_t *headers,
                                cos_table_t **resp_headers) {
    cos_status_t *s = NULL;
    cos_http_request_t *req = NULL;
    cos_http_response_t *resp = NULL;
    cos_table_t *pHeaders = NULL;
    cos_table_t *query_params = NULL;
    char *error_msg = NULL;

    if (cos_is_null_string((cos_string_t *)object)) {
        s = cos_status_create(options->pool);
        cos_status_set(s, COSE_INVALID_ARGUMENT, COS_CLIENT_ERROR_CODE, "Object is invalid");
        return s;
    }

    pHeaders = cos_table_create_if_null(options, headers, 0);
    query_params = cos_table_create_if_null(options, query_params, 0);

    if (!cos_init_object_request(options, bucket, object, HTTP_DELETE,
                            &req, query_params, pHeaders, NULL, 0, &resp, &error_msg)) {
        cos_invalid_param_status_set(options, s, error_msg);
        return s;
    }
    (void)cos_get_object_uri(options, bucket, object, req, &error_msg);

    s = cos_process_request(options, req, resp, 1);
    cos_fill_read_response_header(resp, resp_headers);

    return s;
}


cos_status_t *cos_append_object_from_buffer(const cos_request_options_t *options,
                                            const cos_string_t *bucket,
                                            const cos_string_t *object,
                                            int64_t position,
                                            cos_list_t *buffer,
                                            cos_table_t *headers,
                                            cos_table_t **resp_headers) {
    cos_status_t *s = NULL;
    cos_http_request_t *req = NULL;
    cos_http_response_t *resp = NULL;
    cos_table_t *query_params = NULL;
    char *error_msg = NULL;

    /* init query_params */
    query_params = cos_table_create_if_null(options, query_params, 2);
    apr_table_add(query_params, COS_APPEND, "");
    cos_table_add_int64(query_params, COS_POSITION, position);

    /* init headers */
    headers = cos_table_create_if_null(options, headers, 2);
    set_content_type(NULL, object->data, headers);
    apr_table_add(headers, COS_EXPECT, "");

    if (!cos_init_object_request(options, bucket, object, HTTP_POST,
                            &req, query_params, headers, NULL, 0, &resp, &error_msg)) {
        cos_invalid_param_status_set(options, s, error_msg);
        return s;
    }
    cos_write_request_body_from_buffer(options->pool, buffer, req, headers);

    s = cos_process_request(options, req, resp, 1);
    cos_fill_read_response_header(resp, resp_headers);

    return s;
}

cos_status_t *cos_do_append_object_from_buffer(const cos_request_options_t *options,
                                               const cos_string_t *bucket,
                                               const cos_string_t *object,
                                               int64_t position,
                                               uint64_t init_crc,
                                               cos_list_t *buffer,
                                               cos_table_t *headers,
                                               cos_table_t *params,
                                               cos_progress_callback progress_callback,
                                               cos_table_t **resp_headers,
                                               cos_list_t *resp_body) {
    cos_status_t *s = NULL;
    cos_http_request_t *req = NULL;
    cos_http_response_t *resp = NULL;
    cos_table_t *query_params = NULL;
    char *error_msg = NULL;

    /* init query_params */
    query_params = cos_table_create_if_null(options, params, 2);
    apr_table_add(query_params, COS_APPEND, "");
    cos_table_add_int64(query_params, COS_POSITION, position);

    /* init headers */
    headers = cos_table_create_if_null(options, headers, 2);
    set_content_type(NULL, object->data, headers);
    apr_table_add(headers, COS_EXPECT, "");

    if (!cos_init_object_request(options, bucket, object, HTTP_POST, &req, query_params,
                            headers, progress_callback, init_crc, &resp, &error_msg)) {
        cos_invalid_param_status_set(options, s, error_msg);
        return s;
    }
    cos_write_request_body_from_buffer(options->pool, buffer, req, headers);

    s = cos_process_request(options, req, resp, 1);
    cos_fill_read_response_header(resp, resp_headers);
    cos_fill_read_response_body(resp, resp_body);

    if (is_enable_crc(options) && has_crc_in_response(resp)) {
        cos_check_crc_consistent(req->crc64, resp->headers, s);
    }

    return s;
}

cos_status_t *cos_append_object_from_file(const cos_request_options_t *options,
                                          const cos_string_t *bucket,
                                          const cos_string_t *object,
                                          int64_t position,
                                          const cos_string_t *append_file,
                                          cos_table_t *headers,
                                          cos_table_t **resp_headers) {
    cos_status_t *s = NULL;
    cos_http_request_t *req = NULL;
    cos_http_response_t *resp = NULL;
    cos_table_t *query_params = NULL;
    int res = COSE_OK;
    char *error_msg = NULL;

    /* init query_params */
    query_params = cos_table_create_if_null(options, query_params, 2);
    apr_table_add(query_params, COS_APPEND, "");
    cos_table_add_int64(query_params, COS_POSITION, position);

    /* init headers */
    headers = cos_table_create_if_null(options, headers, 2);
    set_content_type(append_file->data, object->data, headers);
    apr_table_add(headers, COS_EXPECT, "");

    if (!cos_init_object_request(options, bucket, object, HTTP_POST,
                            &req, query_params, headers, NULL, 0, &resp, &error_msg)) {
        cos_invalid_param_status_set(options, s, error_msg);
        return s;
    }
    res = cos_write_request_body_from_file(options->pool, append_file, req, headers);

    s = cos_status_create(options->pool);
    if (res != COSE_OK) {
        cos_file_error_status_set(s, res);
        return s;
    }

    s = cos_process_request(options, req, resp, 1);
    cos_fill_read_response_header(resp, resp_headers);

    return s;
}

cos_status_t *cos_do_append_object_from_file(const cos_request_options_t *options,
                                             const cos_string_t *bucket,
                                             const cos_string_t *object,
                                             int64_t position,
                                             uint64_t init_crc,
                                             const cos_string_t *append_file,
                                             cos_table_t *headers,
                                             cos_table_t *params,
                                             cos_progress_callback progress_callback,
                                             cos_table_t **resp_headers,
                                             cos_list_t *resp_body) {
    cos_status_t *s = NULL;
    cos_http_request_t *req = NULL;
    cos_http_response_t *resp = NULL;
    cos_table_t *query_params = NULL;
    int res = COSE_OK;
    char *error_msg = NULL;

    /* init query_params */
    query_params = cos_table_create_if_null(options, params, 2);
    apr_table_add(query_params, COS_APPEND, "");
    cos_table_add_int64(query_params, COS_POSITION, position);

    /* init headers */
    headers = cos_table_create_if_null(options, headers, 2);
    set_content_type(append_file->data, object->data, headers);
    apr_table_add(headers, COS_EXPECT, "");

    if (!cos_init_object_request(options, bucket, object, HTTP_POST,  &req, query_params,
                            headers, progress_callback, init_crc, &resp, &error_msg)) {
        cos_invalid_param_status_set(options, s, error_msg);
        return s;
    }
    res = cos_write_request_body_from_file(options->pool, append_file, req, headers);

    s = cos_status_create(options->pool);
    if (res != COSE_OK) {
        cos_file_error_status_set(s, res);
        return s;
    }

    s = cos_process_request(options, req, resp, 1);
    cos_fill_read_response_header(resp, resp_headers);
    cos_fill_read_response_body(resp, resp_body);

    if (is_enable_crc(options) && has_crc_in_response(resp)) {
        cos_check_crc_consistent(req->crc64, resp->headers, s);
    }

    return s;
}

cos_status_t *cos_put_object_acl(const cos_request_options_t *options,
                                 const cos_string_t *bucket,
                                 const cos_string_t *object,
                                 cos_acl_e cos_acl,
                                 const cos_string_t *grant_read,
                                 const cos_string_t *grant_write,
                                 const cos_string_t *grant_full_ctrl,
                                 cos_table_t **resp_headers) {
    cos_status_t *s = NULL;
    cos_http_request_t *req = NULL;
    cos_http_response_t *resp = NULL;
    cos_table_t *query_params = NULL;
    cos_table_t *headers = NULL;
    const char *cos_acl_str = NULL;
    char *error_msg = NULL;

    query_params = cos_table_create_if_null(options, query_params, 1);
    apr_table_add(query_params, COS_ACL, "");

    headers = cos_table_create_if_null(options, headers, 4);
    cos_acl_str = get_cos_acl_str(cos_acl);
    if (cos_acl_str) {
        apr_table_add(headers, COS_CANNONICALIZED_HEADER_ACL, cos_acl_str);
    }
    if (grant_read && !cos_is_null_string((cos_string_t *)grant_read)) {
        apr_table_add(headers, COS_GRANT_READ, grant_read->data);
    }
    if (grant_write && !cos_is_null_string((cos_string_t *)grant_write)) {
        apr_table_add(headers, COS_GRANT_WRITE, grant_write->data);
    }
    if (grant_full_ctrl && !cos_is_null_string((cos_string_t *)grant_full_ctrl)) {
        apr_table_add(headers, COS_GRANT_FULL_CONTROL, grant_full_ctrl->data);
    }

    if (!cos_init_object_request(options, bucket, object, HTTP_PUT, &req,
                            query_params, headers, NULL, 0, &resp, &error_msg)) {
        cos_invalid_param_status_set(options, s, error_msg);
        return s;
    }

    s = cos_process_request(options, req, resp, 1);
    cos_fill_read_response_header(resp, resp_headers);

    return s;
}

cos_status_t *cos_get_object_acl(const cos_request_options_t *options,
                                 const cos_string_t *bucket,
                                 const cos_string_t *object,
                                 cos_acl_params_t *acl_param,
                                 cos_table_t **resp_headers) {
    cos_status_t *s = NULL;
    int res;
    cos_http_request_t *req = NULL;
    cos_http_response_t *resp = NULL;
    cos_table_t *query_params = NULL;
    cos_table_t *headers = NULL;
    char *error_msg = NULL;

    query_params = cos_table_create_if_null(options, query_params, 1);
    apr_table_add(query_params, COS_ACL, "");

    headers = cos_table_create_if_null(options, headers, 0);

    if (!cos_init_object_request(options, bucket, object, HTTP_GET, &req,
                            query_params, headers, NULL, 0, &resp, &error_msg)) {
        cos_invalid_param_status_set(options, s, error_msg);
        return s;
    }

    s = cos_process_request(options, req, resp, 1);
    cos_fill_read_response_header(resp, resp_headers);
    if (!cos_status_is_ok(s)) return s;

    res = cos_acl_parse_from_body(options->pool, &resp->body, acl_param);
    if (res != COSE_OK) cos_xml_error_status_set(s, res);

    return s;
}

cos_status_t *cos_copy_object(const cos_request_options_t *options,
                              const cos_string_t *src_bucket,
                              const cos_string_t *src_object,
                              const cos_string_t *src_endpoint,
                              const cos_string_t *dest_bucket,
                              const cos_string_t *dest_object,
                              cos_table_t *headers,
                              cos_copy_object_params_t *copy_object_param,
                              cos_table_t **resp_headers) {
    cos_status_t *s = NULL;
    int res;
    cos_http_request_t *req = NULL;
    cos_http_response_t *resp = NULL;
    cos_table_t *query_params = NULL;
    char *copy_source = NULL;
    char *error_msg = NULL;

    s = cos_status_create(options->pool);

    headers = cos_table_create_if_null(options, headers, 2);
    query_params = cos_table_create_if_null(options, query_params, 0);

    /* init headers */
    copy_source = apr_psprintf(options->pool, "%.*s.%.*s/%.*s",
                               src_bucket->len, src_bucket->data,
                               src_endpoint->len, src_endpoint->data,
                               src_object->len, src_object->data);
    apr_table_add(headers, COS_CANNONICALIZED_HEADER_COPY_SOURCE, copy_source);
    set_content_type(NULL, dest_object->data, headers);

    if (!cos_init_object_request(options, dest_bucket, dest_object, HTTP_PUT,
                            &req, query_params, headers, NULL, 0, &resp, &error_msg)) {
        cos_invalid_param_status_set(options, s, error_msg);
        return s;
    }

    s = cos_process_request_put_copy(options, req, resp, 1);
    cos_fill_read_response_header(resp, resp_headers);
    if (!cos_status_is_ok(s)) return s;

    res = cos_copy_object_parse_from_body(options->pool, &resp->body, copy_object_param);
    if (res != COSE_OK) cos_xml_error_status_set(s, res);

    if ((s->code / 100 == 2) && ((resp->body_len == 0) || (check_status_with_resp_body(&resp->body, resp->body_len, "ETag") != COS_TRUE))) {
        cos_status_set(s, COSE_SERVICE_ERROR, COS_SERVER_ERROR_CODE, "Server Error");
    }
    return s;
}

cos_status_t *copy
(
    cos_request_options_t *options,
    const cos_string_t *src_bucket,
    const cos_string_t *src_object,
    const cos_string_t *src_endpoint,
    const cos_string_t *dest_bucket,
    const cos_string_t *dest_object,
    int32_t thread_num
) {
    cos_pool_t *subpool = NULL;
    cos_pool_t *parent_pool = NULL;
    cos_status_t *s = NULL;
    cos_status_t *ret = NULL;
    int64_t total_size = 0;
    int64_t part_size = 0;

    parent_pool = options->pool;
    cos_pool_create(&subpool, options->pool);
    options->pool = subpool;

    //get object size
    cos_table_t *head_resp_headers = NULL;
    cos_request_options_t *head_options = cos_request_options_create(subpool);
    head_options->config = cos_config_create(subpool);
    cos_str_set(&head_options->config->endpoint, src_endpoint->data);
    cos_str_set(&head_options->config->access_key_id, options->config->access_key_id.data);
    cos_str_set(&head_options->config->access_key_secret, options->config->access_key_secret.data);
    cos_str_set(&head_options->config->appid, options->config->appid.data);
    head_options->ctl = cos_http_controller_create(subpool, 0);
    s = cos_head_object(head_options, src_bucket, src_object, NULL, &head_resp_headers);
    if (!cos_status_is_ok(s)) {
        ret = cos_status_dup(parent_pool, s);
        cos_pool_destroy(subpool);
        options->pool = parent_pool;
        return ret;
    }
    total_size = atol((char*)apr_table_get(head_resp_headers, COS_CONTENT_LENGTH));
    options->pool = parent_pool;
    cos_pool_destroy(subpool);

    if (thread_num < 1) {
        thread_num = 1;
    }

    part_size = 5*1024*1024;
    while (part_size * 10000 < total_size) {
        part_size *= 2;
    }
    if (part_size > (int64_t)5*1024*1024*1024) {
        part_size = (int64_t)5*1024*1024*1024;
    }

    //use part copy if the object is larger than 5G
    if (total_size > (int64_t)5*1024*1024*1024 && 0 != strcmp(src_endpoint->data, options->config->endpoint.data)) {
        s = cos_upload_object_by_part_copy_mt(options, (cos_string_t *)src_bucket, (cos_string_t *)src_object, (cos_string_t *)src_endpoint, (cos_string_t *)dest_bucket, (cos_string_t *)dest_object, part_size, thread_num, NULL);
    }
    //use object copy if the object is no larger than 5G
    else {
        cos_copy_object_params_t *params = NULL;
        params = cos_create_copy_object_params(options->pool);
        s = cos_copy_object(options, (cos_string_t *)src_bucket, (cos_string_t *)src_object, (cos_string_t *)src_endpoint, dest_bucket, dest_object, NULL, params, NULL);
    }

    ret = cos_status_dup(parent_pool, s);
    return ret;
}

cos_status_t *cos_post_object_restore(const cos_request_options_t *options,
                                            const cos_string_t *bucket,
                                            const cos_string_t *object,
                                            cos_object_restore_params_t *restore_params,
                                            cos_table_t *headers,
                                            cos_table_t *params,
                                            cos_table_t **resp_headers) {
    cos_status_t *s = NULL;
    cos_http_request_t *req = NULL;
    cos_http_response_t *resp = NULL;
    cos_table_t *query_params = NULL;
    cos_list_t body;
    unsigned char *md5 = NULL;
    char *buf = NULL;
    int64_t body_len;
    char *b64_value = NULL;
    int b64_buf_len = (20 + 1) * 4 / 3;
    int b64_len;
    char *error_msg = NULL;

    query_params = cos_table_create_if_null(options, params, 1);
    apr_table_add(query_params, COS_RESTORE, "");

    headers = cos_table_create_if_null(options, headers, 1);

    if (!cos_init_object_request(options, bucket, object, HTTP_POST,
                            &req, query_params, headers, NULL, 0, &resp, &error_msg)) {
        cos_invalid_param_status_set(options, s, error_msg);
        return s;
    }

    build_object_restore_body(options->pool, restore_params, &body);

    //add Content-MD5
    body_len = cos_buf_list_len(&body);
    buf = cos_buf_list_content(options->pool, &body);
    md5 = cos_md5(options->pool, buf, (apr_size_t)body_len);
    b64_value = cos_pcalloc(options->pool, b64_buf_len);
    b64_len = cos_base64_encode(md5, 16, b64_value);
    b64_value[b64_len] = '\0';
    apr_table_addn(headers, COS_CONTENT_MD5, b64_value);
    apr_table_addn(headers, COS_CONTENT_TYPE, "application/xml");

    cos_write_request_body_from_buffer(options->pool, &body, req, headers);

    s = cos_process_request(options, req, resp, 1);
    cos_fill_read_response_header(resp, resp_headers);

    return s;
}

static void cos_add_version_id_params(cos_pool_t *p,
                                     const cos_string_t *version_id,
                                     cos_table_t *query_params) {
    char *version = NULL;

    if (version_id && version_id->len > 0 && version_id->data != NULL) {
        version = apr_psprintf(p, "%.*s", version_id->len, version_id->data);
        apr_table_add(query_params, COS_VERSION_ID, version);
    }
}

cos_status_t *cos_put_object_tagging(const cos_request_options_t *options,
                                    const cos_string_t *bucket,
                                    const cos_string_t *object,
                                    const cos_string_t *version_id,
                                    cos_table_t *headers,
                                    cos_tagging_params_t *tagging_params,
                                    cos_table_t **resp_headers) {
    cos_status_t *s = NULL;
    cos_http_request_t *req = NULL;
    cos_http_response_t *resp = NULL;
    cos_table_t *query_params = NULL;
    char *error_msg = NULL;

    cos_list_t body;
    unsigned char *md5 = NULL;
    char *buf = NULL;
    int64_t body_len;
    char *b64_value = NULL;
    int b64_buf_len = (20 + 1) * 4 / 3;
    int b64_len;

    query_params = cos_table_create_if_null(options, query_params, 1);
    apr_table_add(query_params, COS_TAGGING, "");
    cos_add_version_id_params(options->pool, version_id, query_params);

    headers = cos_table_create_if_null(options, headers, 0);

    if (!cos_init_object_request(options, bucket, object, HTTP_PUT, &req,
            query_params, headers, NULL, 0, &resp, &error_msg)) {
        cos_invalid_param_status_set(options, s, error_msg);
        return s;
    }

    build_tagging_body(options->pool, tagging_params, &body);

    //add Content-MD5
    body_len = cos_buf_list_len(&body);
    buf = cos_buf_list_content(options->pool, &body);
    md5 = cos_md5(options->pool, buf, (apr_size_t)body_len);
    b64_value = cos_pcalloc(options->pool, b64_buf_len);
    b64_len = cos_base64_encode(md5, 16, b64_value);
    b64_value[b64_len] = '\0';
    apr_table_addn(headers, COS_CONTENT_MD5, b64_value);

    apr_table_addn(headers, COS_CONTENT_TYPE, "application/xml");

    cos_write_request_body_from_buffer(options->pool, &body, req, headers);
    s = cos_process_request(options, req, resp, 1);
    cos_fill_read_response_header(resp, resp_headers);

    return s;
}

cos_status_t *cos_get_object_tagging(const cos_request_options_t *options,
                                    const cos_string_t *bucket,
                                    const cos_string_t *object,
                                    const cos_string_t *version_id,
                                    cos_table_t *headers,
                                    cos_tagging_params_t *tagging_params,
                                    cos_table_t **resp_headers) {
    int res;
    cos_status_t *s = NULL;
    cos_http_request_t *req = NULL;
    cos_http_response_t *resp = NULL;
    cos_table_t *query_params = NULL;
    char *error_msg = NULL;

    query_params = cos_table_create_if_null(options, query_params, 1);
    apr_table_add(query_params, COS_TAGGING, "");
    cos_add_version_id_params(options->pool, version_id, query_params);

    headers = cos_table_create_if_null(options, headers, 0);

    if (!cos_init_object_request(options, bucket, object, HTTP_GET, &req,
            query_params, headers, NULL, 0, &resp, &error_msg)) {
        cos_invalid_param_status_set(options, s, error_msg);
        return s;
    }

    s = cos_process_request(options, req, resp, 1);
    cos_fill_read_response_header(resp, resp_headers);
    if (!cos_status_is_ok(s)) return s;

    res = cos_get_tagging_parse_from_body(options->pool, &resp->body, tagging_params);
    if (res != COSE_OK) cos_xml_error_status_set(s, res);
    return s;
}

cos_status_t *cos_delete_object_tagging(const cos_request_options_t *options,
                                       const cos_string_t *bucket,
                                       const cos_string_t *object,
                                       const cos_string_t *version_id,
                                       cos_table_t *headers,
                                       cos_table_t **resp_headers) {
    cos_status_t *s = NULL;
    cos_http_request_t *req = NULL;
    cos_http_response_t *resp = NULL;
    cos_table_t *query_params = NULL;
    char *error_msg = NULL;

    query_params = cos_table_create_if_null(options, query_params, 1);
    apr_table_add(query_params, COS_TAGGING, "");
    cos_add_version_id_params(options->pool, version_id, query_params);

    headers = cos_table_create_if_null(options, headers, 0);

    if (!cos_init_object_request(options, bucket, object, HTTP_DELETE, &req,
            query_params, headers, NULL, 0, &resp, &error_msg)) {
        cos_invalid_param_status_set(options, s, error_msg);
        return s;
    }

    s = cos_process_request(options, req, resp, 1);
    cos_fill_read_response_header(resp, resp_headers);

    return s;
}

int cos_gen_sign_string(const cos_request_options_t *options,
                        const cos_string_t *bucket,
                        const cos_string_t *object,
                        const int64_t expire,
                        cos_http_request_t *req,
                        cos_string_t *signstr) {
    char canon_buf[COS_MAX_URI_LEN];
    cos_string_t canon_res;
    int res;
    int len;

    len = strlen(req->resource);
    if (len >= COS_MAX_URI_LEN - 1) {
        cos_error_log("http resource too long, %s.", req->resource);
        return COSE_INVALID_ARGUMENT;
    }

    canon_res.data = canon_buf;
    canon_res.len = apr_snprintf(canon_buf, sizeof(canon_buf), "/%s", req->resource);

    res = cos_get_string_to_sign(options->pool, req->method, &options->config->access_key_id, &options->config->access_key_secret, &canon_res,
                                 req->headers, req->query_params, expire, signstr);

    if (res != COSE_OK) return res;

    return COSE_OK;
}

int cos_gen_presigned_url(const cos_request_options_t *options,
                          const cos_string_t *bucket,
                          const cos_string_t *object,
                          const int64_t expire,
                          http_method_e method,
                          cos_string_t *presigned_url) {
    if (object == NULL || object->len == 0) {
        cos_str_set(presigned_url, "ObjectName does not support empty, please check!");
        return COSE_UNKNOWN_ERROR;
    }
    cos_string_t signstr;
    int res;
    cos_http_request_t *req = NULL;
    cos_http_response_t *resp = NULL;
    char uristr[3*COS_MAX_URI_LEN+1];
    char param[3*COS_MAX_QUERY_ARG_LEN+1];
    char *url = NULL;
    const char *proto;
    char *delimiter;
    cos_string_t unenc_uri = cos_null_string;
    char *enc_uri;
    char *error_msg = NULL;

    uristr[0] = '\0';
    param[0] = '\0';
    cos_str_null(&signstr);

    if (!cos_init_object_request(options, bucket, object, method,
                            &req, cos_table_make(options->pool, 1), cos_table_make(options->pool, 1), NULL, 0, &resp, &error_msg)) return COSE_INVALID_ARGUMENT;
    if (req->host) {
        apr_table_set(req->headers, COS_HOST, req->host);
    }
    res = cos_gen_sign_string(options, bucket, object, expire, req, &signstr);
    if (res != COSE_OK) {
        cos_error_log("failed to call cos_gen_sign_string, res=%d", res);
        return res;
    }

    enc_uri = req->uri;
    if (options->config->is_cname) {
        if ((delimiter = strchr(req->uri, '/')) != NULL) {
            enc_uri = delimiter + 1;
            unenc_uri.data = req->uri;
            unenc_uri.len = enc_uri - req->uri;
        }
    }
    strncpy(uristr, unenc_uri.data, unenc_uri.len);
    res = cos_url_encode(uristr + unenc_uri.len, enc_uri, COS_MAX_URI_LEN);
    if (res != COSE_OK) {
        cos_error_log("failed to call cos_url_encode, res=%d", res);
        return res;
    }

    res = cos_url_encode(param, signstr.data, COS_MAX_QUERY_ARG_LEN);
    if (res != COSE_OK) {
        cos_error_log("failed to call cos_url_encode, res=%d", res);
        return res;
    }

    proto = req->proto != NULL && strlen(req->proto) != 0 ? req->proto : COS_HTTP_PREFIX;

    url = apr_psprintf(options->pool, "%s%s/%s?sign=%s",
                       proto,
                       req->host,
                       uristr,
                       param);
    cos_str_set(presigned_url, url);

    return COSE_OK;
}

int cos_gen_presigned_url_safe(const cos_request_options_t *options,
                          const cos_string_t *bucket,
                          const cos_string_t *object,
                          const int64_t expire,
                          http_method_e method,
                          cos_table_t *headers,
                          cos_table_t *params,
                          int sign_host,
                          cos_string_t *presigned_url) {
    if (object == NULL || object->len == 0) {
        cos_str_set(presigned_url, "ObjectName does not support empty, please check!");
        return COSE_UNKNOWN_ERROR;
    }
    cos_string_t signstr;
    int res;
    cos_http_request_t *req = NULL;
    cos_http_response_t *resp = NULL;
    char uristr[3*COS_MAX_URI_LEN+1];
    char param[3*COS_MAX_QUERY_ARG_LEN+1];
    char *url = NULL;
    const char *proto;
    cos_string_t query_str;
    char *delimiter;
    cos_string_t unenc_uri = cos_null_string;
    char *enc_uri;
    char *error_msg = NULL;

    uristr[0] = '\0';
    param[0] = '\0';
    cos_str_null(&signstr);

    params = cos_table_create_if_null(options, params, 1);
    headers = cos_table_create_if_null(options, headers, 1);

    if (!cos_init_object_request(options, bucket, object, method,
                            &req, params, headers, NULL, 0, &resp, &error_msg)) {
        return COSE_INVALID_ARGUMENT;
    }
    if (sign_host && req->host) {
        apr_table_set(req->headers, COS_HOST, req->host);
    }
    res = cos_gen_sign_string(options, bucket, object, expire, req, &signstr);
    if (res != COSE_OK) {
        cos_error_log("failed to call cos_gen_sign_string, res=%d", res);
        return res;
    }

    enc_uri = req->uri;
    if (options->config->is_cname) {
        if ((delimiter = strchr(req->uri, '/')) != NULL) {
            enc_uri = delimiter + 1;
            unenc_uri.data = req->uri;
            unenc_uri.len = enc_uri - req->uri;
        }
    }
    strncpy(uristr, unenc_uri.data, unenc_uri.len);
    res = cos_url_encode(uristr + unenc_uri.len, enc_uri, COS_MAX_URI_LEN);
    if (res != COSE_OK) {
        cos_error_log("failed to call cos_url_encode, res=%d", res);
        return res;
    }

    res = cos_url_encode(param, signstr.data, COS_MAX_QUERY_ARG_LEN);
    if (res != COSE_OK) {
        cos_error_log("failed to call cos_url_encode, res=%d", res);
        return res;
    }

    proto = req->proto != NULL && strlen(req->proto) != 0 ? req->proto : COS_HTTP_PREFIX;

    cos_str_set(&query_str, "?");
    if ((res = cos_query_params_to_string(options->pool, params, &query_str)) != COSE_OK) {
        return res;
    }
    url = apr_psprintf(options->pool, "%s%s/%s%.*s%ssign=%s",
                       proto,
                       req->host,
                       uristr,
                       query_str.len,
                       query_str.data,
                       query_str.len > 1 ? "&" : "",
                       param);
    cos_str_set(presigned_url, url);

    return COSE_OK;
}

// 云上数据处理 https://cloud.tencent.com/document/product/460/18147
cos_status_t *ci_image_process(const cos_request_options_t *options,
                                const cos_string_t *bucket,
                                const cos_string_t *object,
                                cos_table_t *headers,
                                cos_table_t **resp_headers,
                                ci_operation_result_t **results) {
    int res;
    cos_status_t *s = NULL;
    cos_http_request_t *req = NULL;
    cos_http_response_t *resp = NULL;
    cos_table_t *query_params = NULL;
    char *error_msg = NULL;

    query_params = cos_table_create_if_null(options, query_params, 1);
    apr_table_add(query_params, "image_process", "");

    headers = cos_table_create_if_null(options, headers, 0);

    if (!cos_init_object_request(options, bucket, object, HTTP_POST, &req,
            query_params, headers, NULL, 0, &resp, &error_msg)) {
        cos_invalid_param_status_set(options, s, error_msg);
        return s;
    }

    //add Content-Length
    if (NULL == apr_table_get(headers, COS_CONTENT_LENGTH)) {
        char* length;
        length = apr_psprintf(options->pool, "%" APR_INT64_T_FMT, req->body_len);
        apr_table_addn(headers, COS_CONTENT_LENGTH, length);
    }
    apr_table_addn(headers, COS_CONTENT_TYPE, "application/xml");

    s = cos_process_request(options, req, resp, 1);
    cos_fill_read_response_header(resp, resp_headers);
    if (!cos_status_is_ok(s)) return s;

    *results = ci_create_operation_result(options->pool);
    res = ci_get_operation_result_parse_from_body(options->pool, &resp->body, *results);
    if (res != COSE_OK) cos_xml_error_status_set(s, res);
    return s;
}

// 图片持久化处理-上传时处理 https://cloud.tencent.com/document/product/460/18147
// 二维码识别-上传时识别 https://cloud.tencent.com/document/product/460/37513
cos_status_t *ci_put_object_from_file(const cos_request_options_t *options,
                                       const cos_string_t *bucket,
                                       const cos_string_t *object,
                                       const cos_string_t *filename,
                                       cos_table_t *headers,
                                       cos_table_t **resp_headers,
                                       ci_operation_result_t **results) {
    int res;
    cos_status_t *s = NULL;
    cos_list_t resp_body;

    cos_list_init(&resp_body);
    s = cos_do_put_object_from_file(options, bucket, object, filename, headers, NULL, NULL, resp_headers, &resp_body);

    if (!cos_status_is_ok(s)) return s;
    *results = ci_create_operation_result(options->pool);
    res = ci_get_operation_result_parse_from_body(options->pool, &resp_body, *results);
    if (res != COSE_OK) cos_xml_error_status_set(s, res);
    return s;
}

// 二维码识别-下载时识别 https://cloud.tencent.com/document/product/436/54070
cos_status_t *ci_get_qrcode(const cos_request_options_t *options,
                                const cos_string_t *bucket,
                                const cos_string_t *object,
                                int cover,
                                cos_table_t *headers,
                                cos_table_t *query_params,
                                cos_table_t **resp_headers,
                                ci_qrcode_result_t **results) {
    int res;
    cos_status_t *s = NULL;
    cos_http_request_t *req = NULL;
    cos_http_response_t *resp = NULL;
    char cover_str[16] = {0};
    char *error_msg = NULL;

    snprintf(cover_str, 16, "%d", cover);
    query_params = cos_table_create_if_null(options, query_params, 2);
    apr_table_add(query_params, "ci-process", "QRcode");
    apr_table_add(query_params, "cover", cover_str);

    headers = cos_table_create_if_null(options, headers, 0);
    if (!cos_init_object_request(options, bucket, object, HTTP_GET, &req,
            query_params, headers, NULL, 0, &resp, &error_msg)) {
        cos_invalid_param_status_set(options, s, error_msg);
        return s;
    }

    s = cos_process_request(options, req, resp, 1);
    cos_fill_read_response_header(resp, resp_headers);
    if (!cos_status_is_ok(s)) return s;
    *results = ci_create_qrcode_result(options->pool);
    res = ci_get_qrcode_result_parse_from_body(options->pool, &resp->body, *results);
    if (res != COSE_OK) cos_xml_error_status_set(s, res);
    return s;
}
