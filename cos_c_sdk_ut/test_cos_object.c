#include "CuTest.h"
#include "cos_log.h"
#include "cos_sys_util.h"
#include "cos_string.h"
#include "cos_status.h"
#include "cos_auth.h"
#include "cos_utility.h"
#include "cos_xml.h"
#include "cos_api.h"
#include "cos_config.h"
#include "cos_test_util.h"

void test_object_setup(CuTest *tc) {
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_acl_e cos_acl = COS_ACL_PRIVATE;
    cos_string_t bucket;
    cos_table_t *resp_headers;
    cos_string_t object;
    cos_string_t file_path;

    /* create test bucket */
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    s = create_test_bucket(options, TEST_BUCKET_NAME, cos_acl);

    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test.mp4");
    cos_str_set(&file_path, "../../../cos_c_sdk_ut/test.mp4");
    s = cos_put_object_from_file(options, &bucket, &object, &file_path, NULL, &resp_headers);
    log_status(s);
    CuAssertIntEquals(tc, 200, s->code);
    cos_pool_destroy(p);
}

void test_object_cleanup(CuTest *tc) {
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_string_t bucket;
    cos_request_options_t *options = NULL;
    cos_table_t *resp_headers = NULL;
    cos_status_t *s = NULL;
    cos_string_t prefix;
    char *prefix_str = "";

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    
    /* delete test object */
    cos_str_set(&prefix, prefix_str);
    s = cos_delete_objects_by_prefix(options, &bucket, &prefix);
    printf("delete all objects, status code=%d\n", s->code);

    abort_all_test_multipart_upload(options, TEST_BUCKET_NAME);
    
    /* delete test bucket */
    cos_delete_bucket(options, &bucket, &resp_headers);
    apr_sleep(apr_time_from_sec(3));

    cos_pool_destroy(p);
}

void test_put_object_from_buffer(CuTest *tc) {
    fprintf(stderr, "==========test_put_object_from_buffer==========\n");
    cos_pool_t *p = NULL;
    char *object_name = "cos_test_put_object.ts";
    char *str = "test cos c sdk";
    cos_status_t *s = NULL;
    int is_cname = 0;
    cos_string_t bucket;
    cos_string_t object;
    cos_table_t *headers = NULL;
    cos_table_t *head_headers = NULL;
    cos_table_t *head_resp_headers = NULL;
    char *content_type = NULL;
    cos_request_options_t *options = NULL;

    /* test put object */
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 1);
    apr_table_set(headers, "x-cos-meta-author", "cos");
    s = create_test_object(options, TEST_BUCKET_NAME, object_name, str, headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, headers);

    cos_pool_destroy(p);

    /* head object */
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    init_test_request_options(options, is_cname);
    s = cos_head_object(options, &bucket, &object, 
                        head_headers, &head_resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, head_resp_headers);
    
    content_type = (char*)(apr_table_get(head_resp_headers, COS_CONTENT_TYPE));
    CuAssertStrEquals(tc, "video/MP2T", content_type);

    printf("test_put_object_from_buffer ok\n");
    fprintf(stderr, "==========test_put_object_from_buffer==========\n");
}

void test_put_object_from_buffer2(CuTest *tc) {
    fprintf(stderr, "==========test_put_object_from_buffer2==========\n");
    cos_pool_t *p = NULL;
    char *object_name = "cos_test_put_object.ts";
    char *str = "test cos c sdk";
    cos_status_t *s = NULL;
    int is_cname = 0;
    cos_string_t bucket;
    cos_string_t object;
    cos_table_t *headers = NULL;
    cos_table_t *head_headers = NULL;
    cos_table_t *head_resp_headers = NULL;
    char *content_type = NULL;
    cos_request_options_t *options = NULL;

    /* test put object */
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 1);
    apr_table_set(headers, "x-cos-meta-author", "cos");
    s = create_test_object(options, TEST_BUCKET_NAME, object_name, str, headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, headers);

    cos_pool_destroy(p);

    /* head object */
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    init_test_request_options(options, is_cname);
    options->config->access_key_secret.data = "\n";
    options->config->access_key_secret.len = 1;
    s = cos_head_object(options, &bucket, &object, 
                        head_headers, &head_resp_headers);
    CuAssertIntEquals(tc, COSE_INVALID_ARGUMENT, s->code);

    printf("test_put_object_from_buffer2 ok\n");
    fprintf(stderr, "==========test_put_object_from_buffer2==========\n");
}

void test_put_object_from_buffer_with_default_content_type(CuTest *tc) {
    cos_pool_t *p = NULL;
    char *object_name = "put_object_from_buffer_with_default_content_type";
    char *str = "test cos c sdk";
    cos_status_t *s = NULL;
    int is_cname = 0;
    cos_string_t bucket;
    cos_string_t object;
    cos_table_t *headers = NULL;
    cos_table_t *head_headers = NULL;
    cos_table_t *head_resp_headers = NULL;
    char *content_type = NULL;
    cos_request_options_t *options = NULL;

    /* test put object */
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 1);
    apr_table_set(headers, "x-cos-meta-author", "cos");
    s = create_test_object(options, TEST_BUCKET_NAME, object_name, str, headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, headers);

    cos_pool_destroy(p);

    /* head object */
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    init_test_request_options(options, is_cname);
    s = cos_head_object(options, &bucket, &object, 
                        head_headers, &head_resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, head_resp_headers);
    
    content_type = (char*)(apr_table_get(head_resp_headers, COS_CONTENT_TYPE));
    CuAssertStrEquals(tc, "application/octet-stream", content_type);

    printf("test_put_object_from_buffer_with_default_content_type ok\n");
}

void test_put_object_from_buffer_with_specified(CuTest *tc) {
    cos_pool_t *p = NULL;
    char *object_name = "xxx/ddd";
    char *str = "test cos c sdk";
    cos_status_t *s = NULL;
    int is_cname = 0;
    cos_string_t bucket;
    cos_string_t object;
    cos_table_t *headers = NULL;
    cos_table_t *head_headers = NULL;
    cos_table_t *head_resp_headers = NULL;
    cos_request_options_t *options = NULL;

    /* test put object */
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 1);
    apr_table_set(headers, "x-cos-meta-author", "cos");
    s = create_test_object(options, TEST_BUCKET_NAME, object_name, str, headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, headers);

    cos_pool_destroy(p);

    /* head object */
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    init_test_request_options(options, is_cname);
    s = cos_head_object(options, &bucket, &object, 
        head_headers, &head_resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, head_resp_headers);

    printf("test_put_object_from_buffer_with_specified ok\n");
}

void test_put_object_from_file(CuTest *tc) {
    cos_pool_t *p = NULL;
    char *object_name = "video_1.ts";
    char *filename = __FILE__;
    cos_string_t bucket;
    cos_string_t object;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    int is_cname = 0;
    cos_table_t *headers = NULL;
    cos_table_t *head_headers = NULL;
    cos_table_t *head_resp_headers = NULL;
    char *content_type = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 5);
    s = create_test_object_from_file(options, TEST_BUCKET_NAME, 
            object_name, filename, headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, headers);

    cos_pool_destroy(p);

    /* head object */
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    init_test_request_options(options, is_cname);
    s = cos_head_object(options, &bucket, &object, 
                        head_headers, &head_resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, head_resp_headers);
    
    content_type = (char*)(apr_table_get(head_resp_headers, COS_CONTENT_TYPE));
    CuAssertStrEquals(tc, "application/octet-stream", content_type);

    printf("test_put_object_from_file ok\n");
}

void test_put_object_with_large_length_header(CuTest *tc) {
    cos_pool_t *p = NULL;
    char *object_name = "video_2.ts";
    char *filename = __FILE__;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    int is_cname = 0;
    int i = 0;
    int header_length = 0;
    cos_table_t *headers = NULL;
    char *user_meta = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);

    header_length = 1024;
    user_meta = (char*)calloc(header_length, 1);
    for (; i < header_length - 1; i++) {
        user_meta[i] = 'a';
    }
    user_meta[header_length - 1] = '\0';
    headers = cos_table_make(p, 2);
    apr_table_set(headers, "x-cos-meta-user-meta", user_meta);
    s = create_test_object_from_file(options, TEST_BUCKET_NAME, 
            object_name, filename, headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, headers);

    free(user_meta);
    cos_pool_destroy(p);

    printf("test_put_object_with_large_length_header_back_bound ok\n");
}

void test_put_object_from_file_with_content_type(CuTest *tc) {
    cos_pool_t *p = NULL;
    char *object_name = "cos_test_put_object_from_file2.txt";
    char *filename = __FILE__;
    cos_string_t bucket;
    cos_string_t object;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    int is_cname = 0;
    cos_table_t *headers = NULL;
    cos_table_t *head_headers = NULL;
    cos_table_t *head_resp_headers = NULL;
    char *content_type = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(options->pool, 1);
    apr_table_set(headers, COS_CONTENT_TYPE, "image/jpeg");

    s = create_test_object_from_file(options, TEST_BUCKET_NAME, 
            object_name, filename, headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, headers);

    cos_pool_destroy(p);

    /* head object */
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    init_test_request_options(options, is_cname);
    s = cos_head_object(options, &bucket, &object, 
                        head_headers, &head_resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, head_resp_headers);
    
    content_type = (char*)(apr_table_get(head_resp_headers, COS_CONTENT_TYPE));
    CuAssertStrEquals(tc, "image/jpeg", content_type);

    printf("test_put_object_from_file ok\n");
}

void test_put_object_with_all_headers(CuTest *tc) {
    cos_pool_t *p = NULL;
    char *object_name = "test_put_object_with_all_headers";
    char *str = "test cos c sdk";
    cos_status_t *s = NULL;
    int is_cname = 0;
    cos_string_t bucket;
    cos_string_t object;
    cos_table_t *headers = NULL;
    cos_table_t *head_headers = NULL;
    cos_table_t *head_resp_headers = NULL;
    char *content_type = NULL;
    char *self_define_header = NULL;
    cos_request_options_t *options = NULL;
    cos_list_t buffer;
    cos_buf_t* content = NULL;

    /* test put object */
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 10);

    cos_list_init(&buffer);
    content = cos_buf_pack(options->pool, str, strlen(str));
    cos_list_add_tail(&content->node, &buffer);

    apr_table_set(headers, "x-cos-meta-author", "cos");
    apr_table_set(headers, COS_CONTENT_TYPE, "text/plain");
    char lengthStr[20];
    sprintf(lengthStr, "%d", strlen(str));
    apr_table_set(headers, COS_CONTENT_LENGTH, lengthStr);
    apr_table_set(headers, "cache-control", "no-cache");
    apr_table_set(headers, COS_EXPIRES, "900");
    apr_table_set(headers, COS_DATE, "Wed,29May201904:10:12GMT");
    apr_table_set(headers, COS_CANNONICALIZED_HEADER_ACL, "private");
    s = cos_put_object_from_buffer(options, &bucket, &object, &buffer, headers, &head_resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, headers);

    cos_pool_destroy(p);

    /* head object */
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    init_test_request_options(options, is_cname);
    s = cos_head_object(options, &bucket, &object,
                        head_headers, &head_resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, head_resp_headers);

    content_type = (char*)(apr_table_get(head_resp_headers, COS_CONTENT_TYPE));
    self_define_header = (char*)(apr_table_get(head_resp_headers, "x-cos-meta-author"));
    CuAssertStrEquals(tc, "text/plain", content_type);
    CuAssertStrEquals(tc, "cos", self_define_header);

    printf("test_put_object_with_all_headers ok\n");
}

void test_get_object_to_buffer(CuTest *tc) {
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    char *object_name = "cos_test_put_object.ts";
    cos_string_t object;
    int is_cname = 0;
    cos_request_options_t *options = NULL;
    cos_table_t *headers = NULL;
    cos_table_t *params = NULL;
    cos_table_t *resp_headers = NULL;
    cos_status_t *s = NULL;
    cos_list_t buffer;
    cos_buf_t *content = NULL;
    char *expect_content = "test cos c sdk";
    char *buf = NULL;
    int64_t len = 0;
    int64_t size = 0;
    int64_t pos = 0;
    char *content_type = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_list_init(&buffer);

    /* test get object to buffer */
    s = cos_get_object_to_buffer(options, &bucket, &object, headers, 
                                 params, &buffer, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, resp_headers);

    /* get buffer len */
    len = cos_buf_list_len(&buffer);

    buf = cos_pcalloc(p, (apr_size_t)(len + 1));
    buf[len] = '\0';

    /* copy buffer content to memory */
    cos_list_for_each_entry(cos_buf_t, content, &buffer, node) {
        size = cos_buf_size(content);
        memcpy(buf + pos, content->pos, (size_t)size);
        pos += size;
    }

    CuAssertStrEquals(tc, expect_content, buf);
    content_type = (char*)(apr_table_get(resp_headers, COS_CONTENT_TYPE));
    CuAssertStrEquals(tc, "video/MP2T", content_type);
    cos_pool_destroy(p);

    printf("test_get_object_to_buffer ok\n");
}

void test_get_object_to_buffer2(CuTest *tc) {
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    char *object_name = "cos_test_put_object.ts";
    cos_string_t object;
    int is_cname = 0;
    cos_request_options_t *options = NULL;
    cos_table_t *headers = NULL;
    cos_table_t *params = NULL;
    cos_table_t *resp_headers = NULL;
    cos_status_t *s = NULL;
    cos_list_t buffer;
    cos_buf_t *content = NULL;
    char *expect_content = "test cos c sdk";
    char *buf = NULL;
    int64_t len = 0;
    int64_t size = 0;
    int64_t pos = 0;
    char *content_type = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_list_init(&buffer);

    /* test get object to buffer */
    options->config->access_key_secret.data = "\n";
    options->config->access_key_secret.len = 1;
    s = cos_get_object_to_buffer(options, &bucket, &object, headers, 
                                 params, &buffer, &resp_headers);
    CuAssertIntEquals(tc, COSE_INVALID_ARGUMENT, s->code);
    cos_pool_destroy(p);

    printf("test_get_object_to_buffer2 ok\n");
}

void test_get_object_to_buffer_with_illega_getobject_key(CuTest *tc) {
    fprintf(stderr, "==========test_get_object_to_buffer_with_illega_getobject_key==========\n");
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    char *object_name = "/././///abc/.//def//../../";
    cos_string_t object;
    int is_cname = 0;
    cos_request_options_t *options = NULL;
    cos_table_t *headers = NULL;
    cos_table_t *params = NULL;
    cos_table_t *resp_headers = NULL;
    cos_status_t *s = NULL;
    cos_list_t buffer;
    cos_buf_t *content = NULL;
    char *expect_content = "test cos c sdk";
    char *buf = NULL;
    int64_t len = 0;
    int64_t size = 0;
    int64_t pos = 0;
    char *content_type = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_list_init(&buffer);

    /* test get object to buffer */
    s = cos_get_object_to_buffer(options, &bucket, &object, headers, 
                                 params, &buffer, &resp_headers);
    CuAssertStrEquals(tc, "ClientError", s->error_code);
    cos_pool_destroy(p);

    printf("test_get_object_to_buffer_with_illega_getobject_key ok\n");
}

void test_get_object_to_buffer_with_range(CuTest *tc) {
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    char *object_name = "cos_test_put_object.ts";
    cos_string_t object;
    int is_cname = 0;
    cos_request_options_t *options = NULL;
    cos_table_t *headers = NULL;
    cos_table_t *params = NULL;
    cos_table_t *resp_headers = NULL;
    cos_status_t *s = NULL;
    cos_list_t buffer;
    cos_buf_t *content = NULL;
    char *expect_content = "cos c sdk";
    char *buf = NULL;
    int64_t len = 0;
    int64_t size = 0;
    int64_t pos = 0;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    headers = cos_table_make(p, 1);
    apr_table_set(headers, "Range", "bytes=5-13");
    cos_list_init(&buffer);

    /* test get object to buffer */
    s = cos_get_object_to_buffer(options, &bucket, &object, headers, 
                                 params, &buffer, &resp_headers);
    CuAssertIntEquals(tc, 206, s->code);
    CuAssertPtrNotNull(tc, resp_headers);

    /* get buffer len */
    len = cos_buf_list_len(&buffer);

    buf = cos_pcalloc(p, (apr_size_t)(len + 1));
    buf[len] = '\0';

    /* copy buffer content to memory */
    cos_list_for_each_entry(cos_buf_t, content, &buffer, node) {
        size = cos_buf_size(content);
        memcpy(buf + pos, content->pos, (size_t)size);
        pos += size;
    }

    CuAssertStrEquals(tc, expect_content, buf);
    cos_pool_destroy(p);

    printf("test_get_object_to_buffer_with_range ok\n");
}

void test_get_object_to_file(CuTest *tc) {
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    char *object_name = "cos_test_put_object_from_file2.txt";
    cos_string_t object;
    char *filename = "cos_test_get_object_to_file";
    char *source_filename = __FILE__;
    cos_string_t file;
    cos_request_options_t *options = NULL; 
    int is_cname = 0;
    cos_table_t *headers = NULL;
    cos_table_t *params = NULL;
    cos_table_t *resp_headers = NULL;
    cos_status_t *s = NULL;
    char *content_type = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_str_set(&file, filename);

    /* test get object to file */
    set_object_key_simplify_check(COS_FALSE);
    s = cos_get_object_to_file(options, &bucket, &object, headers, 
                               params, &file, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertIntEquals(tc, get_file_size(source_filename), get_file_size(filename));
    content_type = (char*)(apr_table_get(resp_headers, COS_CONTENT_TYPE));
    CuAssertStrEquals(tc, "image/jpeg", content_type);
    CuAssertPtrNotNull(tc, resp_headers);

    remove(filename);
    cos_pool_destroy(p);

    printf("test_get_object_to_file ok\n");
}

void test_get_object_to_file2(CuTest *tc) {
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    char *object_name = "cos_test_put_object_from_file2.txt";
    cos_string_t object;
    char *filename = "cos_test_get_object_to_file";
    char *source_filename = __FILE__;
    cos_string_t file;
    cos_request_options_t *options = NULL; 
    int is_cname = 0;
    cos_table_t *headers = NULL;
    cos_table_t *params = NULL;
    cos_table_t *resp_headers = NULL;
    cos_status_t *s = NULL;
    char *content_type = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_str_set(&file, filename);

    /* test get object to file */
    set_object_key_simplify_check(COS_FALSE);
    options->config->access_key_secret.data = "\n";
    options->config->access_key_secret.len = 1;
    s = cos_get_object_to_file(options, &bucket, &object, headers, 
                               params, &file, &resp_headers);
    CuAssertIntEquals(tc, COSE_INVALID_ARGUMENT, s->code);
    cos_pool_destroy(p);

    printf("test_get_object_to_file2 ok\n");
}

void test_get_object_to_file_with_illega_getobject_key(CuTest *tc) {
    fprintf(stderr, "==========test_get_object_to_buffer_with_illega_getobject_key==========\n");
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    char *object_name = "/././///abc/.//def//../../";
    cos_string_t object;
    char *filename = "cos_test_get_object_to_file";
    char *source_filename = __FILE__;
    cos_string_t file;
    cos_request_options_t *options = NULL; 
    int is_cname = 0;
    cos_table_t *headers = NULL;
    cos_table_t *params = NULL;
    cos_table_t *resp_headers = NULL;
    cos_status_t *s = NULL;
    char *content_type = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_str_set(&file, filename);

    /* test get object to file */
    set_object_key_simplify_check(COS_TRUE);
    s = cos_get_object_to_file(options, &bucket, &object, headers, 
                               params, &file, &resp_headers);
    CuAssertStrEquals(tc, "ClientError", s->error_code);
    cos_pool_destroy(p);

    printf("test_get_object_to_file_with_illega_getobject_key ok\n");
}

void test_get_object_with_params(CuTest *tc) {
    cos_pool_t *p = NULL;
    char *object_name = "test_put_object_with_all_headers";
    char *str = "test cos c sdk";
    cos_status_t *s = NULL;
    int is_cname = 0;
    cos_string_t bucket;
    cos_string_t object;
    cos_table_t *headers = NULL;
    cos_table_t *params = NULL;
    cos_table_t *resp_headers = NULL;
    cos_request_options_t *options = NULL;
    char *content_type = NULL;
    cos_list_t buffer;
    char *buf = NULL;
    int64_t len = 0;
    int64_t size = 0;
    int64_t pos = 0;
    cos_buf_t *content = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    init_test_request_options(options, is_cname);
    cos_list_init(&buffer);
    params = cos_table_make(p, 10);
    apr_table_set(params, "response-content-type", "text/plain");

    /* test get object to buffer */
    s = cos_get_object_to_buffer(options, &bucket, &object, headers,
                                 params, &buffer, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, resp_headers);

    /* get buffer len */
    len = cos_buf_list_len(&buffer);

    buf = cos_pcalloc(p, (apr_size_t)(len + 1));
    buf[len] = '\0';

    /* copy buffer content to memory */
    cos_list_for_each_entry(cos_buf_t, content, &buffer, node) {
        size = cos_buf_size(content);
        memcpy(buf + pos, content->pos, (size_t)size);
        pos += size;
    }

    CuAssertStrEquals(tc, str, buf);
    content_type = (char*)(apr_table_get(resp_headers, COS_CONTENT_TYPE));
    CuAssertStrEquals(tc, "text/plain", content_type);

    //with versionid no exsit
    apr_table_set(params, "versionId", "test");
    s = cos_get_object_to_buffer(options, &bucket, &object, headers,
                                 params, &buffer, &resp_headers);
    CuAssertIntEquals(tc, 404, s->code);
    cos_pool_destroy(p);

    printf("test_get_object_with_params ok\n");
}

void test_head_object(CuTest *tc) {
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    cos_string_t object;
    char *object_name = "cos_test_put_object.ts";
    int is_cname = 0;
    cos_request_options_t *options = NULL;
    cos_table_t *headers = NULL;
    cos_table_t *resp_headers = NULL;
    cos_status_t *s = NULL;
    char *user_meta = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    headers = cos_table_make(p, 0);

    /* test head object */
    s = cos_head_object(options, &bucket, &object, headers, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, resp_headers);
    
    user_meta = (char*)(apr_table_get(resp_headers, "x-cos-meta-author"));
    CuAssertStrEquals(tc, "cos", user_meta);

    cos_pool_destroy(p);

    printf("test_head_object ok\n");
}

void test_head_object_with_not_exist(CuTest *tc) {
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    cos_string_t object;
    char *object_name = "not_exist.object";
    int is_cname = 0;
    cos_request_options_t *options = NULL;
    cos_table_t *headers = NULL;
    cos_table_t *resp_headers = NULL;
    cos_status_t *s = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    headers = cos_table_make(p, 0);

    /* test head object */
    s = cos_head_object(options, &bucket, &object, headers, &resp_headers);
    CuAssertIntEquals(tc, 404, s->code);
    CuAssertStrEquals(tc, "NosuchKey", s->error_code);
    CuAssertTrue(tc, NULL == s->error_msg);
    CuAssertTrue(tc, 0 != strlen(s->req_id));
    CuAssertPtrNotNull(tc, resp_headers);

    cos_pool_destroy(p);

    printf("test_head_object ok\n");
}

void test_delete_object(CuTest *tc) {
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    char *object_name = "cos_test_put_object";
    cos_string_t object;
    int is_cname = 0;
    cos_request_options_t *options = NULL;
    cos_table_t *resp_headers = NULL;
    cos_status_t *s = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
 
    /* test delete object */
    s = cos_delete_object(options, &bucket, &object, &resp_headers);
    CuAssertIntEquals(tc, 204, s->code);
    CuAssertPtrNotNull(tc, resp_headers);

    cos_pool_destroy(p);

    printf("test_delete_object ok\n");
}

void test_delete_object2(CuTest *tc) {
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    char *object_name = "cos_test_put_object";
    cos_string_t object;
    int is_cname = 0;
    cos_request_options_t *options = NULL;
    cos_table_t *resp_headers = NULL;
    cos_status_t *s = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
 
    /* test delete object */
    options->config->access_key_secret.data = "\n";
    options->config->access_key_secret.len = 1;
    s = cos_delete_object(options, &bucket, &object, &resp_headers);
    CuAssertIntEquals(tc, COSE_INVALID_ARGUMENT, s->code);

    cos_pool_destroy(p);

    printf("test_delete_object2 ok\n");
}

void test_append_object_from_buffer(CuTest *tc) {
    cos_pool_t *p = NULL;
    char *object_name = "cos_test_append_object";
    cos_string_t bucket;
    cos_string_t object;
    char *str = "test cos c sdk";
    cos_status_t *s = NULL;
    int is_cname = 0;
    int64_t position = 0;
    cos_table_t *headers = NULL;
    cos_table_t *headers1 = NULL;
    cos_table_t *resp_headers = NULL;
    cos_request_options_t *options = NULL;
    cos_list_t buffer;
    cos_buf_t *content = NULL;
    char *next_append_position = NULL;

    /* test append object */
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    s = cos_head_object(options, &bucket, &object, headers, &resp_headers);
    if(s->code == 200) {
        next_append_position = (char*)(apr_table_get(resp_headers, 
                        "Content-Length"));
        position = atoi(next_append_position);
    }
    CuAssertPtrNotNull(tc, resp_headers);

    /* append object */
    resp_headers = NULL;
    headers1 = cos_table_make(p, 0);
    cos_list_init(&buffer);
    content = cos_buf_pack(p, str, strlen(str));
    cos_list_add_tail(&content->node, &buffer);

    s = cos_append_object_from_buffer(options, &bucket, &object, 
            position, &buffer, headers1, &resp_headers);

    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, resp_headers);

    cos_pool_destroy(p);

    printf("test_append_object_from_buffer ok\n");
}

void test_append_object_from_buffer2(CuTest *tc) {
    cos_pool_t *p = NULL;
    char *object_name = "cos_test_append_object";
    cos_string_t bucket;
    cos_string_t object;
    char *str = "test cos c sdk";
    cos_status_t *s = NULL;
    int is_cname = 0;
    int64_t position = 0;
    cos_table_t *headers = NULL;
    cos_table_t *headers1 = NULL;
    cos_table_t *resp_headers = NULL;
    cos_request_options_t *options = NULL;
    cos_list_t buffer;
    cos_buf_t *content = NULL;
    char *next_append_position = NULL;

    /* test append object */
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    s = cos_head_object(options, &bucket, &object, headers, &resp_headers);
    if(s->code == 200) {
        next_append_position = (char*)(apr_table_get(resp_headers, 
                        "Content-Length"));
        position = atoi(next_append_position);
    }
    CuAssertPtrNotNull(tc, resp_headers);

    /* append object */
    resp_headers = NULL;
    headers1 = cos_table_make(p, 0);
    cos_list_init(&buffer);
    content = cos_buf_pack(p, str, strlen(str));
    cos_list_add_tail(&content->node, &buffer);
    options->config->access_key_secret.data = "\n";
    options->config->access_key_secret.len = 1;
    s = cos_append_object_from_buffer(options, &bucket, &object, 
            position, &buffer, headers1, &resp_headers);
    CuAssertIntEquals(tc, COSE_INVALID_ARGUMENT, s->code);

    cos_pool_destroy(p);

    printf("test_append_object_from_buffer2 ok\n");
}

void test_append_object_from_file(CuTest *tc) {
    cos_pool_t *p = NULL;
    char *object_name = "cos_test_append_object_from_file";
    cos_string_t bucket;
    cos_string_t object;
    char *filename = __FILE__;
    cos_string_t append_file;
    cos_status_t *s = NULL;
    int is_cname = 0;
    int64_t position = 0;
    cos_table_t *headers = NULL;
    cos_table_t *resp_headers = NULL;
    cos_request_options_t *options = NULL;

    /* test append object */
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_str_set(&append_file, filename);

    s = cos_append_object_from_file(options, &bucket, &object, position, 
                                    &append_file, headers, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, resp_headers);

    cos_pool_destroy(p);

    printf("test_append_object_from_file ok\n");
}

void test_append_object_from_file2(CuTest *tc) {
    cos_pool_t *p = NULL;
    char *object_name = "cos_test_append_object_from_file";
    cos_string_t bucket;
    cos_string_t object;
    char *filename = __FILE__;
    cos_string_t append_file;
    cos_status_t *s = NULL;
    int is_cname = 0;
    int64_t position = 0;
    cos_table_t *headers = NULL;
    cos_table_t *resp_headers = NULL;
    cos_request_options_t *options = NULL;

    /* test append object */
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_str_set(&append_file, filename);

    options->config->access_key_secret.data = "\n";
    options->config->access_key_secret.len = 1;
    s = cos_append_object_from_file(options, &bucket, &object, position, 
                                    &append_file, headers, &resp_headers);
    CuAssertIntEquals(tc, COSE_INVALID_ARGUMENT, s->code);

    cos_pool_destroy(p);

    printf("test_append_object_from_file2 ok\n");
}

void test_get_not_exist_object_to_file(CuTest *tc) {
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    char *object_name = "cos_test_put_object_from_file_not_exist_.txt";
    cos_string_t object;
    char *filename = "cos_test_get_object_to_file_not_exist";
    cos_string_t file;
    cos_request_options_t *options = NULL; 
    int is_cname = 0;
    cos_table_t *headers = NULL;
    cos_table_t *params = NULL;
    cos_table_t *resp_headers = NULL;
    cos_status_t *s = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_str_set(&file, filename);

    /* test get object to file */
    s = cos_get_object_to_file(options, &bucket, &object, headers, 
        params, &file, &resp_headers);
    CuAssertIntEquals(tc, 404, s->code);
    CuAssertIntEquals(tc, -1, get_file_size(filename));

    cos_pool_destroy(p);

    printf("test_get_not_exist_object_to_file ok\n");
}

void test_object_acl(CuTest *tc) {
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_acl_e cos_acl = COS_ACL_PRIVATE;
    cos_string_t bucket;
    cos_string_t object;
    cos_table_t *resp_headers = NULL;
   
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "cos_test_put_object.ts");

    //put acl
    cos_string_t read;
    cos_str_set(&read, "id=\"qcs::cam::uin/12345:uin/12345\", id=\"qcs::cam::uin/45678:uin/45678\"");
    s = cos_put_object_acl(options, &bucket, &object, cos_acl, &read, NULL, NULL, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);

    //get acl
    cos_acl_params_t *acl_params2 = NULL;
    acl_params2 = cos_create_acl_params(p);
    s = cos_get_object_acl(options, &bucket, &object, acl_params2, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    printf("acl owner id:%s, name:%s\n", acl_params2->owner_id.data, acl_params2->owner_name.data);
    cos_acl_grantee_content_t *acl_content = NULL;
    cos_list_for_each_entry(cos_acl_grantee_content_t, acl_content, &acl_params2->grantee_list, node) {
        printf("acl grantee id:%s, name:%s, permission:%s\n", acl_content->id.data, acl_content->name.data, acl_content->permission.data);
    }

    cos_pool_destroy(p);
}

void test_object_acl2(CuTest *tc) {
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_acl_e cos_acl = COS_ACL_PRIVATE;
    cos_string_t bucket;
    cos_string_t object;
    cos_table_t *resp_headers = NULL;
   
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "cos_test_put_object.ts");

    //put acl
    cos_string_t read;
    cos_str_set(&read, "id=\"qcs::cam::uin/12345:uin/12345\", id=\"qcs::cam::uin/45678:uin/45678\"");
    s = cos_put_object_acl(options, &bucket, &object, cos_acl, &read, NULL, NULL, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);

    //get acl
    cos_acl_params_t *acl_params2 = NULL;
    acl_params2 = cos_create_acl_params(p);
    options->config->access_key_secret.data = "\n";
    options->config->access_key_secret.len = 1;
    s = cos_get_object_acl(options, &bucket, &object, acl_params2, &resp_headers);
    CuAssertIntEquals(tc, COSE_INVALID_ARGUMENT, s->code);
    printf("test_object_acl2 ok\n");
    cos_pool_destroy(p);
}

void test_object_copy(CuTest *tc) {
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t src_bucket;
    cos_string_t src_object;
    cos_string_t src_endpoint;
    cos_table_t *resp_headers = NULL;
    
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test_copy.txt");
    cos_str_set(&src_bucket, TEST_BUCKET_NAME);
    cos_str_set(&src_object, "cos_test_put_object.ts");
    cos_str_set(&src_endpoint, options->config->endpoint.data);

    cos_copy_object_params_t *params = NULL;
    params = cos_create_copy_object_params(p);
    s = cos_copy_object(options, &src_bucket, &src_object, &src_endpoint, &bucket, &object, NULL, params, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertIntEquals(tc, 1, 0 != strcmp(params->etag.data, ""));
    cos_pool_destroy(p);
}


void test_object_copy2(CuTest *tc) {
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t src_bucket;
    cos_string_t src_object;
    cos_string_t src_endpoint;
    cos_table_t *resp_headers = NULL;
    
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test_copy.txt");
    cos_str_set(&src_bucket, TEST_BUCKET_NAME);
    cos_str_set(&src_object, "cos_test_put_object.ts");
    cos_str_set(&src_endpoint, options->config->endpoint.data);

    cos_copy_object_params_t *params = NULL;
    params = cos_create_copy_object_params(p);
    options->config->access_key_secret.data = "\n";
    options->config->access_key_secret.len = 1;
    s = cos_copy_object(options, &src_bucket, &src_object, &src_endpoint, &bucket, &object, NULL, params, &resp_headers);
    CuAssertIntEquals(tc, COSE_INVALID_ARGUMENT, s->code);
    printf("test_object_copy2 ok\n");
    cos_pool_destroy(p);
}

void test_object_bigcopy(CuTest *tc) {
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t src_bucket;
    cos_string_t src_object;
    cos_string_t src_endpoint;
    cos_table_t *resp_headers = NULL;
    cos_list_t buffer;
    cos_buf_t *content = NULL;
    char *str = NULL;
    
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test_copy_222.txt");
    cos_str_set(&src_bucket, TEST_BUCKET_NAME);
    cos_str_set(&src_object, "cos_test_put_object.ts");
    cos_str_set(&src_endpoint, options->config->endpoint.data);

    cos_list_init(&buffer);
    str = cos_palloc(p, 0x300000);
    content = cos_buf_pack(options->pool, str, 0x300000);
    cos_list_add_tail(&content->node, &buffer);
    s = cos_put_object_from_buffer(options, &bucket, &src_object, &buffer, NULL, &resp_headers);

    s = copy(options, &src_bucket, &src_object, &src_endpoint, &bucket, &object, 1);
    CuAssertIntEquals(tc, 200, s->code);
    options->config->access_key_secret.data = "\n";
    options->config->access_key_secret.len = 1;
    s = copy(options, &src_bucket, &src_object, &src_endpoint, &bucket, &object, 1);
    CuAssertIntEquals(tc, COSE_INVALID_ARGUMENT, s->code);
    cos_pool_destroy(p);
}

void test_presigned_url(CuTest *tc) {
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t presigned_url;
    int res;
    
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test.dat");

    res = cos_gen_presigned_url_safe(options, &bucket, &object, 300, HTTP_GET, NULL, NULL, 1, &presigned_url);
    CuAssertIntEquals(tc, 0, res);
    options->config->access_key_secret.data = "\n";
    options->config->access_key_secret.len = 1;
    res = cos_gen_presigned_url_safe(options, &bucket, &object, 300, HTTP_GET, NULL, NULL, 1, &presigned_url);
    CuAssertIntEquals(tc, COSE_INVALID_ARGUMENT, res);
    
    cos_pool_destroy(p);
    
}

void test_presigned_safe_url(CuTest *tc) {
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t presigned_url;
    int res;
    
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test.dat");

    res = cos_gen_presigned_url(options, &bucket, &object, 300, HTTP_GET, &presigned_url);
    CuAssertIntEquals(tc, 0, res);
    
    options->config->access_key_secret.data = "\n";
    options->config->access_key_secret.len = 1;
    res = cos_gen_presigned_url(options, &bucket, &object, 300, HTTP_GET, &presigned_url);
    CuAssertIntEquals(tc, COSE_INVALID_ARGUMENT, res);
    
    cos_pool_destroy(p);
    
}

void test_presigned_url_with_params_headers(CuTest *tc) {
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t presigned_url;
    int res;
    cos_table_t *params = NULL;
    cos_table_t *headers = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test.dat");
    headers = cos_table_make(p, 10);
    params = cos_table_make(p, 10);
    apr_table_set(params, "versionId", "test");
    apr_table_set(headers, "x-cos-meta-author", "cos");
    apr_table_set(headers, COS_EXPIRES, "900");
    apr_table_set(headers, COS_DATE, "Wed,29May201904:10:12GMT");
    apr_table_set(headers, "Range", "bytes=5-13");

    res = cos_gen_presigned_url_safe(options, &bucket, &object, 300, HTTP_GET, headers, params, 1, &presigned_url);
    CuAssertTrue(tc, strstr(presigned_url.data, "expires") != NULL);
    CuAssertTrue(tc, strstr(presigned_url.data, "host") != NULL);
    CuAssertTrue(tc, strstr(presigned_url.data, "range") != NULL);
    CuAssertTrue(tc, strstr(presigned_url.data, "x-cos-meta-author") != NULL);
    CuAssertTrue(tc, strstr(presigned_url.data, "versionid") != NULL);

    cos_pool_destroy(p);

    printf("test_presigned_url_with_params_headers ok\n");

}

void test_check_object_exist(CuTest *tc) {
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_table_t *resp_headers;
    cos_table_t *headers = NULL;
    cos_object_exist_status_e object_exist;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test.txt");

    // 检查对象是否存在
    s = cos_check_object_exist(options, &bucket, &object, headers, &object_exist, &resp_headers);
    CuAssertPtrNotNull(tc, s);
    if (object_exist == COS_OBJECT_NON_EXIST) {
        printf("object: %.*s non exist.\n", object.len, object.data);
    } else if (object_exist == COS_OBJECT_EXIST) {
        printf("object: %.*s exist.\n", object.len, object.data);
    } else {
        printf("object: %.*s unknown status.\n", object.len, object.data);
    }

    cos_pool_destroy(p);

    printf("test_check_object_exist ok\n");
}

void test_object_tagging(CuTest *tc) {
    cos_pool_t *pool = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_table_t *resp_headers = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t version_id = cos_string("");
    cos_tagging_params_t *params = NULL;
    cos_tagging_params_t *result = NULL;
    cos_tagging_tag_t *tag = NULL;
    cos_list_t buffer;

    //创建内存池
    cos_pool_create(&pool, NULL);

    //初始化请求选项
    options = cos_request_options_create(pool);
    options->config = cos_config_create(options->pool);

    init_test_request_options(options, is_cname);
    options->ctl = cos_http_controller_create(options->pool, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test.xxxxxx");

    cos_list_init(&buffer);
    cos_put_object_from_buffer(options, &bucket, &object, &buffer, NULL, resp_headers);

    // put object tagging
    params = cos_create_tagging_params(pool);
    tag = cos_create_tagging_tag(pool);
    cos_str_set(&tag->key, "age");
    cos_str_set(&tag->value, "18");
    cos_list_add_tail(&tag->node, &params->node);

    tag = cos_create_tagging_tag(pool);
    cos_str_set(&tag->key, "name");
    cos_str_set(&tag->value, "xiaoming");
    cos_list_add_tail(&tag->node, &params->node);

    s = cos_put_object_tagging(options, &bucket, &object, &version_id, NULL, params, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, resp_headers);

    // get object tagging
    result = cos_create_tagging_params(pool);
    s = cos_get_object_tagging(options, &bucket, &object, &version_id, NULL, result, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, resp_headers);

    tag = NULL;
    cos_list_for_each_entry(cos_tagging_tag_t, tag, &result->node, node) {
        printf("taging key: %s\n", tag->key.data);
        printf("taging value: %s\n", tag->value.data);

    } 

    // delete tagging
    s = cos_delete_object_tagging(options, &bucket, &object, &version_id, NULL, &resp_headers);
    CuAssertIntEquals(tc, 204, s->code);
    CuAssertPtrNotNull(tc, resp_headers);

    cos_pool_destroy(pool);

    printf("test_object_tagging ok\n");
}


void test_object_tagging2(CuTest *tc) {
    cos_pool_t *pool = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_table_t *resp_headers = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t version_id = cos_string("");
    cos_tagging_params_t *params = NULL;
    cos_tagging_params_t *result = NULL;
    cos_tagging_tag_t *tag = NULL;

    //创建内存池
    cos_pool_create(&pool, NULL);

    //初始化请求选项
    options = cos_request_options_create(pool);
    options->config = cos_config_create(options->pool);

    init_test_request_options(options, is_cname);
    options->ctl = cos_http_controller_create(options->pool, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test.xxxxxx");
    options->config->access_key_secret.data = "\n";
    options->config->access_key_secret.len = 1;

    // put object tagging
    params = cos_create_tagging_params(pool);
    tag = cos_create_tagging_tag(pool);
    cos_str_set(&tag->key, "age");
    cos_str_set(&tag->value, "18");
    cos_list_add_tail(&tag->node, &params->node);

    tag = cos_create_tagging_tag(pool);
    cos_str_set(&tag->key, "name");
    cos_str_set(&tag->value, "xiaoming");
    cos_list_add_tail(&tag->node, &params->node);

    s = cos_put_object_tagging(options, &bucket, &object, &version_id, NULL, params, &resp_headers);
    CuAssertIntEquals(tc, COSE_INVALID_ARGUMENT, s->code);

    // get object tagging
    result = cos_create_tagging_params(pool);
    s = cos_get_object_tagging(options, &bucket, &object, &version_id, NULL, result, &resp_headers);
    CuAssertIntEquals(tc, COSE_INVALID_ARGUMENT, s->code);

    // delete tagging
    s = cos_delete_object_tagging(options, &bucket, &object, &version_id, NULL, &resp_headers);
    CuAssertIntEquals(tc, COSE_INVALID_ARGUMENT, s->code);

    cos_pool_destroy(pool);

    printf("test_object_tagging2 ok\n");
}

void test_object_restore(CuTest *tc) {
    {

        cos_pool_t *p = NULL;
        char *object_name = "test_restore.dat";
        char *str = "test cos c sdk";
        cos_status_t *s = NULL;
        int is_cname = 0;
        cos_string_t bucket;
        cos_string_t object;
        cos_table_t *headers = NULL;
        cos_table_t *head_headers = NULL;
        cos_table_t *head_resp_headers = NULL;
        char *content_type = NULL;
        cos_request_options_t *options = NULL;

        /* test put object */
        cos_pool_create(&p, NULL);
        options = cos_request_options_create(p);
        init_test_request_options(options, is_cname);
        headers = cos_table_make(p, 1);
        apr_table_add(headers, "x-cos-storage-class", "ARCHIVE");
        s = create_test_object(options, TEST_BUCKET_NAME, object_name, str, headers);
        CuAssertIntEquals(tc, 200, s->code);
        CuAssertPtrNotNull(tc, headers);

        cos_pool_destroy(p);

        /* head object */
        cos_pool_create(&p, NULL);
        options = cos_request_options_create(p);
        cos_str_set(&bucket, TEST_BUCKET_NAME);
        cos_str_set(&object, object_name);
        init_test_request_options(options, is_cname);
        s = cos_head_object(options, &bucket, &object,
                            head_headers, &head_resp_headers);
        CuAssertIntEquals(tc, 200, s->code);
    }
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    cos_string_t object;
    int is_cname = 0;
    cos_table_t *resp_headers = NULL;
    cos_request_options_t *options = NULL;
    cos_status_t *s = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test_restore.dat");

    cos_object_restore_params_t *restore_params = cos_create_object_restore_params(p);
    restore_params->days = 30;
    cos_str_set(&restore_params->tier, "Standard");
    s = cos_post_object_restore(options, &bucket, &object, restore_params, NULL, NULL, &resp_headers);
    CuAssertIntEquals(tc, 202, s->code);
    CuAssertPtrNotNull(tc, resp_headers);
    options->config->access_key_secret.data = "\n";
    options->config->access_key_secret.len = 1;
    s = cos_post_object_restore(options, &bucket, &object, restore_params, NULL, NULL, &resp_headers); 
    CuAssertIntEquals(tc, COSE_INVALID_ARGUMENT, s->code);

    cos_pool_destroy(p);

    printf("test_object_restore ok\n");
}

void test_ci_image_process(CuTest *tc) {
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t file;
    cos_table_t *resp_headers;
    cos_table_t *headers = NULL;
    ci_operation_result_t *results = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test.jpg");

    // 云上数据处理
    cos_str_set(&file, "../../../cos_c_sdk_ut/test.jpg");
    cos_put_object_from_file(options, &bucket, &object, &file, headers, &resp_headers);

    headers = cos_table_make(p, 1);
    apr_table_addn(headers, "pic-operations", "{\"is_pic_info\":1,\"rules\":[{\"fileid\":\"test.jpg\",\"rule\":\"imageView2/format/png\"}]}");
    s = ci_image_process(options, &bucket, &object, headers, &resp_headers, &results);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, resp_headers);

    // 上传时处理
    headers = cos_table_make(p, 1);
    apr_table_addn(headers, "pic-operations", "{\"is_pic_info\":1,\"rules\":[{\"fileid\":\"test3.jpg\",\"rule\":\"imageView2/format/png\"}]}");
    cos_str_set(&object, "test2.jpg");
    s = ci_put_object_from_file(options, &bucket, &object, &file, headers, &resp_headers, &results);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, resp_headers);

    options->config->access_key_secret.data = "\n";
    options->config->access_key_secret.len = 1;
    s = ci_put_object_from_file(options, &bucket, &object, &file, headers, &resp_headers, &results);
    CuAssertIntEquals(tc, COSE_INVALID_ARGUMENT, s->code);

    cos_pool_destroy(p);
}

void test_ci_media_process_media_info(CuTest *tc) {
    cos_pool_t *p = NULL;
    int is_cname = 0; 
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_table_t *resp_headers;
    ci_media_info_result_t *media_info;
    cos_string_t object;

    // 基本配置
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test.mp4");

    // 替换为您的配置信息，可参见文档 https://cloud.tencent.com/document/product/436/55672
    s = ci_get_media_info(options, &bucket, &object, NULL, &resp_headers, &media_info);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, resp_headers);

    options->config->access_key_secret.data = "\n";
    options->config->access_key_secret.len = 1;
    s = ci_get_media_info(options, &bucket, &object, NULL, &resp_headers, &media_info);
    CuAssertIntEquals(tc, COSE_INVALID_ARGUMENT, s->code);
    // 销毁内存池
    cos_pool_destroy(p);
}

void test_ci_media_process_snapshot(CuTest *tc) {
    cos_pool_t *p = NULL;
    int is_cname = 0; 
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_table_t *resp_headers;
    cos_list_t download_buffer;
    cos_string_t object;
    ci_get_snapshot_request_t *snapshot_request;
    cos_buf_t *content = NULL;
    cos_string_t pic_file = cos_string("snapshot.jpg");

    // 基本配置
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test.mp4");

    // 替换为您的配置信息，可参见文档 https://cloud.tencent.com/document/product/436/55671
    snapshot_request = ci_snapshot_request_create(p);
    snapshot_request->time = 7.5;
    snapshot_request->width = 0;
    snapshot_request->height = 0;
    cos_str_set(&snapshot_request->format, "jpg");
    cos_str_set(&snapshot_request->rotate, "auto");
    cos_str_set(&snapshot_request->mode, "exactframe");
    cos_list_init(&download_buffer);

    s = ci_get_snapshot_to_buffer(options, &bucket, &object, snapshot_request, NULL, &download_buffer, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, resp_headers);

    int64_t len = 0;
    int64_t size = 0;
    int64_t pos = 0;
    cos_list_for_each_entry(cos_buf_t, content, &download_buffer, node) {
        len += cos_buf_size(content);
    }
    char *buf = cos_pcalloc(p, (apr_size_t)(len + 1));
    buf[len] = '\0';
    cos_list_for_each_entry(cos_buf_t, content, &download_buffer, node) {
        size = cos_buf_size(content);
        memcpy(buf + pos, content->pos, (size_t)size);
        pos += size;
    }
    cos_warn_log("Download len:%ld data=%s", len, buf);

    s = ci_get_snapshot_to_file(options, &bucket, &object, snapshot_request, NULL, &pic_file, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, resp_headers);

    // 销毁内存池
    cos_pool_destroy(p);
}

void test_ci_media_process_snapshot2(CuTest *tc) {
    cos_pool_t *p = NULL;
    int is_cname = 0; 
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_table_t *resp_headers;
    cos_list_t download_buffer;
    cos_string_t object;
    ci_get_snapshot_request_t *snapshot_request;
    cos_buf_t *content = NULL;
    cos_string_t pic_file = cos_string("snapshot.jpg");

    // 基本配置
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test.mp4");

    // 替换为您的配置信息，可参见文档 https://cloud.tencent.com/document/product/436/55671
    snapshot_request = ci_snapshot_request_create(p);
    snapshot_request->time = 7.5;
    snapshot_request->width = 0;
    snapshot_request->height = 0;
    cos_str_set(&snapshot_request->format, "jpg");
    cos_str_set(&snapshot_request->rotate, "auto");
    cos_str_set(&snapshot_request->mode, "exactframe");
    cos_list_init(&download_buffer);
    options->config->access_key_secret.data = "\n";
    options->config->access_key_secret.len = 1;

    s = ci_get_snapshot_to_buffer(options, &bucket, &object, snapshot_request, NULL, &download_buffer, &resp_headers);
    CuAssertIntEquals(tc, COSE_INVALID_ARGUMENT, s->code);


    s = ci_get_snapshot_to_file(options, &bucket, &object, snapshot_request, NULL, &pic_file, &resp_headers);
    CuAssertIntEquals(tc, COSE_INVALID_ARGUMENT, s->code);

    // 销毁内存池
    cos_pool_destroy(p);
}

void test_ci_media_process_media_bucket(CuTest *tc) {
    cos_pool_t *p = NULL;
    int is_cname = 0; 
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_table_t *resp_headers;
    ci_media_buckets_request_t *media_buckets_request;
    ci_media_buckets_result_t *media_buckets_result;

    // 基本配置
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    options->config = cos_config_create(options->pool);
    cos_str_set(&options->config->endpoint, TEST_CI_ENDPOINT);     // https://ci.<Region>.myqcloud.com
    cos_str_set(&options->config->access_key_id, TEST_ACCESS_KEY_ID);
    cos_str_set(&options->config->access_key_secret, TEST_ACCESS_KEY_SECRET);
    cos_str_set(&options->config->appid, TEST_APPID);
    options->config->is_cname = is_cname;
    options->ctl = cos_http_controller_create(options->pool, 0);

    // 替换为您的配置信息，可参见文档 https://cloud.tencent.com/document/product/436/48988
    media_buckets_request = ci_media_buckets_request_create(p);
    cos_str_set(&media_buckets_request->regions, "");
    cos_str_set(&media_buckets_request->bucket_names, "");
    cos_str_set(&media_buckets_request->bucket_name, "");
    cos_str_set(&media_buckets_request->page_number, "1");
    cos_str_set(&media_buckets_request->page_size, "10");
    s = ci_describe_media_buckets(options, media_buckets_request, NULL, &resp_headers, &media_buckets_result);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, resp_headers);

    options->config->access_key_secret.data = "\n";
    options->config->access_key_secret.len = 1;
    s = ci_describe_media_buckets(options, media_buckets_request, NULL, &resp_headers, &media_buckets_result);
    CuAssertIntEquals(tc, COSE_INVALID_ARGUMENT, s->code); 
    // 销毁内存池
    cos_pool_destroy(p);
}

void test_ci_video_auditing(CuTest *tc) {
    cos_pool_t *p = NULL;
    int is_cname = 0; 
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_table_t *resp_headers;
    ci_video_auditing_job_options_t *job_options;
    ci_video_auditing_job_result_t *job_result;
    ci_auditing_job_result_t *auditing_result;

    // 基本配置
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    options->config = cos_config_create(options->pool);
    cos_str_set(&options->config->endpoint, TEST_CI_ENDPOINT);     // https://ci.<Region>.myqcloud.com
    cos_str_set(&options->config->access_key_id, TEST_ACCESS_KEY_ID);
    cos_str_set(&options->config->access_key_secret, TEST_ACCESS_KEY_SECRET);
    cos_str_set(&options->config->appid, TEST_APPID);
    options->config->is_cname = is_cname;
    options->ctl = cos_http_controller_create(options->pool, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);

    // 替换为您的配置信息，可参见文档 https://cloud.tencent.com/document/product/436/47316
    job_options = ci_video_auditing_job_options_create(p);
    cos_str_set(&job_options->input_object, "test.mp4");
    cos_str_set(&job_options->job_conf.detect_type, "Porn,Terrorism,Politics,Ads");
    cos_str_set(&job_options->job_conf.callback_version, "Detail");
    job_options->job_conf.detect_content = 1;
    cos_str_set(&job_options->job_conf.snapshot.mode, "Interval");
    job_options->job_conf.snapshot.time_interval = 1.5;
    job_options->job_conf.snapshot.count = 10;

    // 提交一个视频审核任务
    s = ci_create_video_auditing_job(options, &bucket, job_options, NULL, &resp_headers, &job_result);
    if (job_result == NULL) {
        cos_pool_destroy(p);
        return;
    }
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, resp_headers);

    // 等待视频审核任务完成，此处可修改您的等待时间
    sleep(30);

    // 获取审核任务结果
    s = ci_get_auditing_job(options, &bucket, &job_result->jobs_detail.job_id, NULL, &resp_headers, &auditing_result);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, resp_headers);

    // 销毁内存池
    cos_pool_destroy(p);
}

void test_ci_video_auditing2(CuTest *tc) {
    cos_pool_t *p = NULL;
    int is_cname = 0; 
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_table_t *resp_headers;
    ci_video_auditing_job_options_t *job_options;
    ci_video_auditing_job_result_t *job_result;
    ci_auditing_job_result_t *auditing_result;

    // 基本配置
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    options->config = cos_config_create(options->pool);
    cos_str_set(&options->config->endpoint, TEST_CI_ENDPOINT);     // https://ci.<Region>.myqcloud.com
    cos_str_set(&options->config->access_key_id, TEST_ACCESS_KEY_ID);
    cos_str_set(&options->config->access_key_secret, TEST_ACCESS_KEY_SECRET);
    cos_str_set(&options->config->appid, TEST_APPID);
    options->config->is_cname = is_cname;
    options->ctl = cos_http_controller_create(options->pool, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);

    // 替换为您的配置信息，可参见文档 https://cloud.tencent.com/document/product/436/47316
    job_options = ci_video_auditing_job_options_create(p);
    cos_str_set(&job_options->input_object, "test.mp4");
    cos_str_set(&job_options->job_conf.detect_type, "Porn,Terrorism,Politics,Ads");
    cos_str_set(&job_options->job_conf.callback_version, "Detail");
    job_options->job_conf.detect_content = 1;
    cos_str_set(&job_options->job_conf.snapshot.mode, "Interval");
    job_options->job_conf.snapshot.time_interval = 1.5;
    job_options->job_conf.snapshot.count = 10;

    options->config->access_key_secret.data = "\n";
    options->config->access_key_secret.len = 1;
    // 提交一个视频审核任务
    
    s = ci_create_video_auditing_job(options, &bucket, job_options, NULL, &resp_headers, &job_result);
    CuAssertIntEquals(tc, COSE_INVALID_ARGUMENT, s->code);
    
    cos_string_t job_id;
    cos_str_set(&job_id, "test.mp4");
    // 获取审核任务结果
    s = ci_get_auditing_job(options, &bucket, &job_id, NULL, &resp_headers, &auditing_result);
     CuAssertIntEquals(tc, COSE_INVALID_ARGUMENT, s->code);
    // 销毁内存池
    cos_pool_destroy(p);
}

void test_ci_image_qrcode(CuTest *tc) {
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t file;
    cos_table_t *resp_headers;
    cos_table_t *headers = NULL;
    ci_operation_result_t *results = NULL;
    ci_qrcode_info_t *content = NULL;
    ci_qrcode_result_t *result2 = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test.jpg");
    
    headers = cos_table_make(p, 1);
    apr_table_addn(headers, "pic-operations", "{\"is_pic_info\":1,\"rules\":[{\"fileid\":\"test.png\",\"rule\":\"QRcode/cover/1\"}]}");
    // 上传时识别
    cos_str_set(&file, "../../../cos_c_sdk_ut/test.jpg");
    cos_str_set(&object, "test.jpg");
    s = ci_put_object_from_file(options, &bucket, &object, &file, headers, &resp_headers, &results);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, resp_headers);

    if (results == NULL) {
        cos_pool_destroy(p);
        return;
    }

    cos_list_for_each_entry(ci_qrcode_info_t, content, &results->object.qrcode_info, node) {
        printf("CodeUrl: %s\n", content->code_url.data);
        printf("Point: %s\n", content->point[0].data);
        printf("Point: %s\n", content->point[1].data);
        printf("Point: %s\n", content->point[2].data);
        printf("Point: %s\n", content->point[3].data);
    }

    // 下载时识别
    s = ci_get_qrcode(options, &bucket, &object, 1, NULL, NULL, &resp_headers, &result2);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, resp_headers);

    cos_list_for_each_entry(ci_qrcode_info_t, content, &result2->qrcode_info, node) {
        printf("CodeUrl: %s\n", content->code_url.data);
        printf("Point: %s\n", content->point[0].data);
        printf("Point: %s\n", content->point[1].data);
        printf("Point: %s\n", content->point[2].data);
        printf("Point: %s\n", content->point[3].data);
    }

    options->config->access_key_secret.data = "\n";
    options->config->access_key_secret.len = 1;
    s = ci_get_qrcode(options, &bucket, &object, 1, NULL, NULL, &resp_headers, &result2);
    CuAssertIntEquals(tc, COSE_INVALID_ARGUMENT, s->code);
    //销毁内存池
    cos_pool_destroy(p); 
}

CuSuite *test_cos_object() {
    CuSuite* suite = CuSuiteNew();   

    SUITE_ADD_TEST(suite, test_object_setup);
    SUITE_ADD_TEST(suite, test_ci_image_qrcode);
    SUITE_ADD_TEST(suite, test_ci_video_auditing);
    SUITE_ADD_TEST(suite, test_ci_media_process_media_info);
    SUITE_ADD_TEST(suite, test_ci_media_process_snapshot);
    SUITE_ADD_TEST(suite, test_ci_media_process_media_bucket);
    SUITE_ADD_TEST(suite, test_put_object_from_buffer);
    SUITE_ADD_TEST(suite, test_put_object_from_file);
    SUITE_ADD_TEST(suite, test_put_object_from_buffer_with_specified);
    SUITE_ADD_TEST(suite, test_get_object_to_buffer);
    SUITE_ADD_TEST(suite, test_get_object_to_buffer_with_range);
    SUITE_ADD_TEST(suite, test_put_object_from_file_with_content_type);
    SUITE_ADD_TEST(suite, test_put_object_from_buffer_with_default_content_type);
    SUITE_ADD_TEST(suite, test_put_object_with_large_length_header);
    SUITE_ADD_TEST(suite, test_get_object_to_file);
    SUITE_ADD_TEST(suite, test_head_object);
    SUITE_ADD_TEST(suite, test_head_object_with_not_exist);
    SUITE_ADD_TEST(suite, test_object_acl);
    SUITE_ADD_TEST(suite, test_object_copy);
    SUITE_ADD_TEST(suite, test_object_bigcopy);
    SUITE_ADD_TEST(suite, test_delete_object);
    SUITE_ADD_TEST(suite, test_append_object_from_buffer);
    SUITE_ADD_TEST(suite, test_append_object_from_file);
    SUITE_ADD_TEST(suite, test_presigned_url);
    SUITE_ADD_TEST(suite, test_presigned_safe_url);
    SUITE_ADD_TEST(suite, test_check_object_exist);
    SUITE_ADD_TEST(suite, test_object_tagging);
    SUITE_ADD_TEST(suite, test_object_restore);
    SUITE_ADD_TEST(suite, test_ci_image_process);
    SUITE_ADD_TEST(suite, test_get_object_to_file_with_illega_getobject_key); 
    SUITE_ADD_TEST(suite, test_get_object_to_buffer_with_illega_getobject_key); 
    SUITE_ADD_TEST(suite, test_get_object_to_file2); 
    SUITE_ADD_TEST(suite, test_get_object_to_buffer2); 
    SUITE_ADD_TEST(suite, test_put_object_from_buffer2); 
    SUITE_ADD_TEST(suite, test_ci_video_auditing2); 
    SUITE_ADD_TEST(suite, test_ci_media_process_snapshot2); 
    SUITE_ADD_TEST(suite, test_object_tagging2); 
    SUITE_ADD_TEST(suite, test_object_copy2); 
    SUITE_ADD_TEST(suite, test_object_acl2); 
    SUITE_ADD_TEST(suite, test_append_object_from_file2); 
    SUITE_ADD_TEST(suite, test_append_object_from_buffer2); 
    SUITE_ADD_TEST(suite, test_delete_object2);
    SUITE_ADD_TEST(suite, test_object_cleanup);

    return suite;
}
