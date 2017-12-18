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

void test_object_setup(CuTest *tc)
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_acl_e cos_acl = COS_ACL_PRIVATE;

    /* create test bucket */
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    s = create_test_bucket(options, TEST_BUCKET_NAME, cos_acl);

    CuAssertIntEquals(tc, 200, s->code);
    cos_pool_destroy(p);
}

void test_object_cleanup(CuTest *tc)
{
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
    
    /* delete test bucket */
    cos_delete_bucket(options, &bucket, &resp_headers);
    apr_sleep(apr_time_from_sec(3));

    cos_pool_destroy(p);
}

void test_put_object_from_buffer(CuTest *tc)
{
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
}

void test_put_object_from_buffer_with_default_content_type(CuTest *tc)
{
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

void test_put_object_from_buffer_with_specified(CuTest *tc)
{
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

void test_put_object_from_file(CuTest *tc)
{
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

void test_put_object_with_large_length_header(CuTest *tc)
{
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

void test_put_object_from_file_with_content_type(CuTest *tc)
{
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

void test_get_object_to_buffer(CuTest *tc)
{
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

void test_get_object_to_buffer_with_range(CuTest *tc)
{
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
    apr_table_set(headers, "Range", " bytes=5-13");
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

void test_get_object_to_file(CuTest *tc)
{
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

void test_head_object(CuTest *tc)
{
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

void test_head_object_with_not_exist(CuTest *tc)
{
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
    CuAssertStrEquals(tc, "UnknownError", s->error_code);
    CuAssertTrue(tc, NULL == s->error_msg);
    CuAssertTrue(tc, 0 != strlen(s->req_id));
    CuAssertPtrNotNull(tc, resp_headers);

    cos_pool_destroy(p);

    printf("test_head_object ok\n");
}

void test_delete_object(CuTest *tc)
{
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

void test_append_object_from_buffer(CuTest *tc)
{
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
                        "x-cos-next-append-position"));
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

    CuAssertIntEquals(tc, 400, s->code);
    CuAssertPtrNotNull(tc, resp_headers);

    cos_pool_destroy(p);

    printf("test_append_object_from_buffer ok\n");
}

void test_append_object_from_file(CuTest *tc)
{
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

void test_get_not_exist_object_to_file(CuTest *tc)
{
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

void test_object_acl(CuTest *tc)
{
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

void test_object_copy(CuTest *tc)
{
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


CuSuite *test_cos_object()
{
    CuSuite* suite = CuSuiteNew();   

    SUITE_ADD_TEST(suite, test_object_setup);
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
    SUITE_ADD_TEST(suite, test_delete_object);
    SUITE_ADD_TEST(suite, test_append_object_from_buffer);
    SUITE_ADD_TEST(suite, test_append_object_from_file);
    SUITE_ADD_TEST(suite, test_object_cleanup); 
    
    return suite;
}
