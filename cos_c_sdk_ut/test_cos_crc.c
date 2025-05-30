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
#include "cos_crc64.h"

void test_crc_setup(CuTest *tc) {
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

void test_crc_cleanup(CuTest *tc) {
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_string_t bucket;
    cos_request_options_t *options = NULL;
    char *object_name1 = "cos_test_crc_put_object.txt";
    char *object_name2 = "cos_test_crc_append_object.txt";
    char *object_name3 = "cos_test_crc_multipart_object.txt";

    cos_table_t *resp_headers = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);

    /* delete test object */
    delete_test_object(options, TEST_BUCKET_NAME, object_name1);
    delete_test_object(options, TEST_BUCKET_NAME, object_name2);
    delete_test_object(options, TEST_BUCKET_NAME, object_name3);
    abort_all_test_multipart_upload(options, TEST_BUCKET_NAME);

    /* delete test bucket */
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_delete_bucket(options, &bucket, &resp_headers);
    apr_sleep(apr_time_from_sec(3));

    cos_pool_destroy(p);
}

void test_crc_disable_crc(CuTest *tc) {
    cos_pool_t *p = NULL;
    char *object_name = "cos_test_crc_put_object.txt";
    char *str = "Sow nothing, reap nothing.";
    cos_status_t *s = NULL;
    int is_cname = 0;
    cos_string_t bucket;
    cos_string_t object;
    cos_request_options_t *options = NULL;
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
    content = cos_buf_pack(options->pool, str, strlen(str));
    cos_list_add_tail(&content->node, &buffer);

    options->ctl->options->enable_crc = COS_FALSE;
    
    /* test put object */
    s = cos_put_object_from_buffer(options, &bucket, &object, &buffer, NULL, NULL);
    CuAssertIntEquals(tc, 200, s->code);

    cos_pool_destroy(p);

    /* test get object */
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);

    options->ctl->options->enable_crc = COS_FALSE;

    s = cos_get_object_to_buffer(options, &bucket, &object, NULL, NULL, &buffer, NULL);
    CuAssertIntEquals(tc, 200, s->code);

    cos_pool_destroy(p);

    printf("test_crc_disable_crc ok\n");
}

/* Test crc64() on vector[0..len-1] which should have CRC-64 crc.  Also test
   crc64_combine() on vector[] split in two. */
static void crc64_combine_test(CuTest *tc, void *vector, size_t len, uint64_t crc) {
    uint64_t crc1, crc2;

    /* test crc64() */
    crc1 = cos_crc64(0, vector, len);
    CuAssertTrue(tc, crc1 == crc);

    /* test crc64_combine() */
    crc1 = cos_crc64(0, vector, (len + 1) >> 1);
    crc2 = cos_crc64(0, (char*)vector + ((len + 1) >> 1), len >> 1);
    crc1 = cos_crc64_combine(crc1, crc2, len >> 1);
    CuAssertTrue(tc, crc1 == crc);
}

void test_crc_combine(CuTest *tc) {
    {
        char *strb1 = "123456789";
        size_t lenb1 = 9;
        cos_crc64_big(0, strb1, lenb1);
    }
    char *str1 = "123456789";
    size_t len1 = 9;
    uint64_t crc1 = UINT64_C(0x995dc9bbdf1939fa);
    char *str2 = "This is a test of the emergency broadcast system.";
    size_t len2 = 49;
    uint64_t crc2 = UINT64_C(0x27db187fc15bbc72);

    crc64_combine_test(tc, str1, len1, crc1);
    crc64_combine_test(tc, str2, len2, crc2);

     printf("test_crc_combine ok\n");
}

void test_crc_negative(CuTest *tc) {
    cos_pool_t *p = NULL;
    char *object_name = "cos_test_crc_append_object_neg.txt";
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t filename;
    cos_status_t *s = NULL;
    int is_cname = 0;
    int64_t position = 0;
    cos_request_options_t *options = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);

    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);

    make_random_file(p, object_name, 1024);
    cos_str_set(&filename, object_name);

    cos_delete_object(options, &bucket, &object, NULL);

    /* append object */
    s = cos_do_append_object_from_file(options, &bucket, &object, position, 1, 
        &filename, NULL, NULL, NULL, NULL, NULL);
    CuAssertIntEquals(tc, 200, s->code);

    /* delete object */
    s = cos_delete_object(options, &bucket, &object, NULL);
    CuAssertIntEquals(tc, 204, s->code);

    apr_file_remove(object_name, p);
    cos_pool_destroy(p);

    printf("test_crc_negative ok\n");
}

CuSuite *test_cos_crc() {
    CuSuite* suite = CuSuiteNew();

    SUITE_ADD_TEST(suite, test_crc_setup);
    // SUITE_ADD_TEST(suite, test_crc_append_object_from_buffer);
    // SUITE_ADD_TEST(suite, test_crc_append_object_from_file);
    SUITE_ADD_TEST(suite, test_crc_disable_crc);
    SUITE_ADD_TEST(suite, test_crc_combine);
    SUITE_ADD_TEST(suite, test_crc_negative);
    SUITE_ADD_TEST(suite, test_crc_cleanup);

    return suite;
}
