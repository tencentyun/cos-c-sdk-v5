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

void test_progress_setup(CuTest *tc)
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

void test_progress_cleanup(CuTest *tc)
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

void test_progress_put_and_get_from_buffer(CuTest *tc)
{
    cos_pool_t *p = NULL;
    char *object_name = "cos_test_progress_put_object.ts";
    char *str = NULL;
    cos_status_t *s = NULL;
    int is_cname = 0;
    cos_string_t bucket;
    cos_string_t object;
    cos_table_t *headers = NULL;
    cos_table_t *params = NULL;
    cos_request_options_t *options = NULL;
    cos_table_t *resp_headers = NULL;
    size_t length = 1024 * 16 * 10;
    cos_list_t resp_body;
    cos_list_t buffer;
    cos_buf_t *content;

    /* init test*/
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
   
    str = (char *)cos_palloc(p, length);
    memset(str, 'A', length - 1);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_list_init(&resp_body);

    cos_list_init(&buffer);
    content = cos_buf_pack(options->pool, str, length);
    cos_list_add_tail(&content->node, &buffer);

    headers = cos_table_make(p, 1);
    apr_table_set(headers, "x-cos-meta-author", "cos");
    
    /* test put object */
    s = cos_do_put_object_from_buffer(options, &bucket, &object, &buffer, 
        headers, params, percentage, &resp_headers, &resp_body);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, headers);
    cos_pool_destroy(p);

    /* test get object */
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);

    s = cos_do_get_object_to_buffer(options, &bucket, &object, NULL, NULL, 
        &buffer, percentage, NULL);
    CuAssertIntEquals(tc, 200, s->code);
    cos_pool_destroy(p);

    printf("test_progress_put_object_from_buffer ok\n");
}

void test_progress_put_and_get_from_file(CuTest *tc)
{
    cos_pool_t *p = NULL;
    char *object_name = "cos_test_progress_put_object.ts";
    cos_status_t *s = NULL;
    int is_cname = 0;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t filename;
    cos_request_options_t *options = NULL;
    cos_table_t *resp_headers = NULL;
    size_t length = 1024 * 16 * 10;
    cos_list_t resp_body;

    /* init test*/
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
   
    make_random_file(p, object_name, length);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_str_set(&filename, object_name);
    cos_list_init(&resp_body);

    /* test put object */
    s = cos_do_put_object_from_file(options, &bucket, &object, &filename, 
        NULL, NULL, percentage, &resp_headers, &resp_body);
    CuAssertIntEquals(tc, 200, s->code);
    
    cos_pool_destroy(p);

    /* test get object */
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);

    s = cos_do_get_object_to_file(options, &bucket, &object, NULL, NULL, 
        &filename, percentage, NULL);
    CuAssertIntEquals(tc, 200, s->code);

    apr_file_remove(object_name, p);
    cos_pool_destroy(p);

    printf("test_progress_put_and_get_from_file ok\n");
}

void test_progress_put_and_get_empty_body(CuTest *tc)
{
    cos_pool_t *p = NULL;
    char *object_name = "cos_test_progress_put_object.ts";
    char *str = "";
    cos_status_t *s = NULL;
    int is_cname = 0;
    cos_string_t bucket;
    cos_string_t object;
    cos_table_t *headers = NULL;
    cos_table_t *params = NULL;
    cos_request_options_t *options = NULL;
    cos_table_t *resp_headers = NULL;
    size_t length = 0;
    cos_list_t resp_body;
    cos_list_t buffer;
    cos_buf_t *content;

    /* init test*/
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);

    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_list_init(&resp_body);

    cos_list_init(&buffer);
    content = cos_buf_pack(options->pool, str, length);
    cos_list_add_tail(&content->node, &buffer);

    headers = cos_table_make(p, 1);
    apr_table_set(headers, "x-cos-meta-author", "cos");

    /* test put object */
    s = cos_do_put_object_from_buffer(options, &bucket, &object, &buffer, 
        headers, params, percentage, &resp_headers, &resp_body);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, headers);
    cos_pool_destroy(p);

    /* test get object */
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);

    s = cos_do_get_object_to_buffer(options, &bucket, &object, NULL, NULL, 
        &buffer, percentage, NULL);
    CuAssertIntEquals(tc, 200, s->code);
    cos_pool_destroy(p);

    printf("test_progress_put_and_get_empty_body ok\n");
}

void test_progress_append_object(CuTest *tc)
{
    cos_pool_t *p = NULL;
    char *object_name = "cos_test_progress_append_object.ts";
    char *str = NULL;
    cos_status_t *s = NULL;
    int is_cname = 0;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t filename;
    cos_table_t *headers = NULL;
    cos_table_t *params = NULL;
    cos_request_options_t *options = NULL;
    cos_table_t *resp_headers = NULL;
    size_t length = 1024 * 16 * 20;
    uint64_t initcrc = 0;
    cos_list_t resp_body;
    cos_list_t buffer;
    cos_buf_t *content;

    /* init test*/
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
   
    str = (char *)cos_palloc(p, length);
    memset(str, 'A', length - 1);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_list_init(&resp_body);

    cos_list_init(&buffer);
    content = cos_buf_pack(options->pool, str, length);
    cos_list_add_tail(&content->node, &buffer);

    headers = cos_table_make(p, 1);
    apr_table_set(headers, "x-cos-meta-author", "cos");
    
    /* test append object from buffer */
    s = cos_do_append_object_from_buffer(options, &bucket, &object, 0, initcrc, &buffer, 
        headers, params, percentage, &resp_headers, &resp_body);
    CuAssertIntEquals(tc, 200, s->code);

    cos_pool_destroy(p);

    /* test append object from file*/
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);

    cos_str_set(&filename, object_name);
    make_random_file(p, object_name, length);

    s = cos_do_append_object_from_file(options, &bucket, &object, length, initcrc, &filename, 
        NULL, NULL, percentage, &resp_headers, &resp_body);
    CuAssertIntEquals(tc, 200, s->code);

    apr_file_remove(object_name, p);
    cos_pool_destroy(p);

    printf("test_progress_append_object ok\n");
}

void test_progress_multipart_from_buffer(CuTest *tc)
{
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    char *object_name = "cos_test_progress_multipart_object.ts";
    cos_string_t object;
    int is_cname = 0;
    cos_request_options_t *options = NULL;
    cos_status_t *s = NULL;
    cos_list_t buffer;
    cos_list_upload_part_params_t *params = NULL;
    cos_string_t upload_id;
    cos_list_t complete_part_list;
    cos_list_part_content_t *part_content1 = NULL;
    cos_complete_part_content_t *complete_content1 = NULL;
    int part_num = 1;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);

    //init mulitipart
    s = init_test_multipart_upload(options, TEST_BUCKET_NAME, object_name, &upload_id);
    CuAssertIntEquals(tc, 200, s->code);

    //upload part
    cos_list_init(&buffer);
    make_random_body(p, 10, &buffer);

    s = cos_do_upload_part_from_buffer(options, &bucket, &object, &upload_id,
        part_num++, &buffer, percentage, NULL, NULL, NULL, NULL);
    CuAssertIntEquals(tc, 200, s->code);

    cos_list_init(&buffer);
    make_random_body(p, 10, &buffer);
    s = cos_do_upload_part_from_buffer(options, &bucket, &object, &upload_id,
        part_num++, &buffer, percentage, NULL, NULL, NULL, NULL);
    CuAssertIntEquals(tc, 200, s->code);

    //list part
    params = cos_create_list_upload_part_params(p);
    params->max_ret = 1;
    cos_list_init(&complete_part_list);

    s = cos_list_upload_part(options, &bucket, &object, &upload_id, 
                             params, NULL);
    CuAssertIntEquals(tc, 200, s->code);

    cos_list_for_each_entry(cos_list_part_content_t, part_content1, &params->part_list, node) {
        complete_content1 = cos_create_complete_part_content(p);
        cos_str_set(&complete_content1->part_number, part_content1->part_number.data);
        cos_str_set(&complete_content1->etag, part_content1->etag.data);
        cos_list_add_tail(&complete_content1->node, &complete_part_list);
    }

    //complete multipart
    s = cos_complete_multipart_upload(options, &bucket, &object, &upload_id,
            &complete_part_list, NULL, NULL);
    CuAssertIntEquals(tc, 200, s->code);

    cos_pool_destroy(p);

    printf("test_progress_multipart_from_buffer ok\n");
}

void test_progress_multipart_from_file(CuTest *tc)
{
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    char *object_name = "cos_test_progress_multipart_object.ts";
    cos_string_t object;
    int is_cname = 0;
    cos_request_options_t *options = NULL;
    cos_status_t *s = NULL;
    cos_list_upload_part_params_t *params = NULL;
    cos_string_t upload_id;
    cos_list_t complete_part_list;
    cos_upload_file_t *upload_file = NULL;
    cos_list_part_content_t *part_content1 = NULL;
    cos_complete_part_content_t *complete_content1 = NULL;
    size_t length = 1024 * 16 * 10;
    int part_num = 1;    

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);

    make_random_file(p, object_name, length);
    upload_file = cos_create_upload_file(p);
    cos_str_set(&upload_file->filename, object_name);

    //init mulitipart
    s = init_test_multipart_upload(options, TEST_BUCKET_NAME, object_name, &upload_id);
    CuAssertIntEquals(tc, 200, s->code);

    //upload part
    upload_file->file_pos = 0;
    upload_file->file_last = length/2;
    s = cos_do_upload_part_from_file(options, &bucket, &object, &upload_id,
        part_num++, upload_file, percentage, NULL, NULL, NULL, NULL);
    CuAssertIntEquals(tc, 200, s->code);

    upload_file->file_pos = length/2;
    upload_file->file_last = length;
    s = cos_do_upload_part_from_file(options, &bucket, &object, &upload_id,
        part_num++, upload_file, percentage, NULL, NULL, NULL, NULL);
    CuAssertIntEquals(tc, 200, s->code);

    //list part
    params = cos_create_list_upload_part_params(p);
    params->max_ret = 1;
    cos_list_init(&complete_part_list);

    s = cos_list_upload_part(options, &bucket, &object, &upload_id, 
                             params, NULL);
    CuAssertIntEquals(tc, 200, s->code);

    cos_list_for_each_entry(cos_list_part_content_t, part_content1, &params->part_list, node) {
        complete_content1 = cos_create_complete_part_content(p);
        cos_str_set(&complete_content1->part_number, part_content1->part_number.data);
        cos_str_set(&complete_content1->etag, part_content1->etag.data);
        cos_list_add_tail(&complete_content1->node, &complete_part_list);
    }

    //complete multipart
    s = cos_complete_multipart_upload(options, &bucket, &object, &upload_id,
            &complete_part_list, NULL, NULL);
    CuAssertIntEquals(tc, 200, s->code);

    apr_file_remove(object_name, p);
    cos_pool_destroy(p);

    printf("void test_progress_multipart_from_file ok\n");
}

CuSuite *test_cos_progress()
{
    CuSuite* suite = CuSuiteNew();

    SUITE_ADD_TEST(suite, test_progress_setup);
    SUITE_ADD_TEST(suite, test_progress_put_and_get_from_buffer);
    SUITE_ADD_TEST(suite, test_progress_put_and_get_from_file);
    SUITE_ADD_TEST(suite, test_progress_put_and_get_empty_body);
    SUITE_ADD_TEST(suite, test_progress_append_object);
    SUITE_ADD_TEST(suite, test_progress_multipart_from_buffer); 
    SUITE_ADD_TEST(suite, test_progress_multipart_from_file); 
    SUITE_ADD_TEST(suite, test_progress_cleanup);

    return suite;
}
