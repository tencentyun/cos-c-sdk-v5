#include "CuTest.h"
#include "apr_portable.h"
#include "apr_file_info.h"
#include "cos_log.h"
#include "cos_sys_util.h"
#include "cos_string.h"
#include "cos_status.h"
#include "cos_auth.h"
#include "cos_xml.h"
#include "cos_utility.h"
#include "cos_transport.h"

extern int starts_with(const cos_string_t *str, const char *prefix);
extern int cos_curl_code_to_status(CURLcode code);

/*
 * cos_xml.c
 */
void test_get_xml_doc_with_empty_cos_list(CuTest *tc)
{
    int ret;
    mxml_node_t *xml_node;
    cos_list_t bc;
    cos_list_init(&bc);

    
    ret = get_xmldoc(&bc, &xml_node);
    CuAssertIntEquals(tc, COSE_XML_PARSE_ERROR, ret);

    printf("test_get_xml_doc_with_empty_cos_list ok\n");
}

/*
 * cos_list.h
 */

void test_cos_list_movelist_with_empty_list(CuTest *tc) {
    cos_list_t list;
    cos_list_t new_list;

    cos_list_init(&list);

    cos_list_movelist(&list, &new_list);
    CuAssertTrue(tc, new_list.prev == &new_list);
    CuAssertTrue(tc, new_list.next == &new_list);

    printf("test_cos_list_movelist_with_empty_list ok\n");
}

/*
 * cos_util.c
 */
void test_starts_with_failed(CuTest *tc) {
    int ret;
    cos_string_t str;
    cos_str_set(&str, "hangzhou.city");
    
    ret = starts_with(&str, "xixi");
    CuAssertIntEquals(tc, 0, ret);

    printf("test_starts_with_failed ok\n");
}

void test_is_valid_ip(CuTest *tc) {
    int ret;

    ret = is_valid_ip("140.205.63.8");
    CuAssertIntEquals(tc, 1, ret);

    printf("test_is_valid_ip ok\n");
}

void test_cos_request_options_create_with_null_pool(CuTest *tc) {
    cos_request_options_t *option;
    option = cos_request_options_create(NULL);
    CuAssertTrue(tc, NULL != option);

    cos_pool_destroy(option->pool);

    printf("test_cos_request_options_create_with_null_pool ok\n");
}

void test_cos_get_part_size(CuTest *tc) {
    int64_t file_size = 49999;
    int64_t part_size = 2;

    cos_get_part_size(file_size, &part_size);
    CuAssertIntEquals(tc, 1048576, (int)part_size);

    printf("test_cos_get_part_size ok\n");
}

void test_cos_get_object_uri_with_cname(CuTest *tc) {
    cos_pool_t *p;
    cos_request_options_t *options;
    cos_string_t bucket;
    cos_string_t object;
    cos_http_request_t req;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    options->config = cos_config_create(options->pool);
    options->config->is_cname = 1;
    cos_str_set(&options->config->endpoint, "img.abc.com");

    cos_str_set(&bucket, "bucket-1");
    cos_str_set(&object, "key-2");
    
    cos_get_object_uri(options, &bucket, &object, &req);
    CuAssertStrEquals(tc, "", req.proto);
    CuAssertStrEquals(tc, "key-2", req.uri);
    CuAssertStrEquals(tc, "img.abc.com", req.host);
    
    cos_pool_destroy(p);

    printf("test_cos_get_object_uri_with_cname ok\n");
}

void test_cos_get_object_uri_with_ip(CuTest *tc) {
    cos_pool_t *p;
    cos_request_options_t *options;
    cos_string_t bucket;
    cos_string_t object;
    cos_http_request_t req;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    options->config = cos_config_create(options->pool);
    options->config->is_cname = 0;
    cos_str_set(&options->config->endpoint, "http://140.205.63.8");

    cos_str_set(&bucket, "bucket-1");
    cos_str_set(&object, "key-2");
    
    cos_get_object_uri(options, &bucket, &object, &req);
    CuAssertStrEquals(tc, "http://", req.proto);
    CuAssertStrEquals(tc, "key-2", req.uri);
    CuAssertStrEquals(tc, "140.205.63.8", req.host);
    
    cos_pool_destroy(p);

    printf("test_cos_get_object_uri_with_ip ok\n");
}

void test_cos_get_bucket_uri_with_ip(CuTest *tc) {
    cos_pool_t *p;
    cos_request_options_t *options;
    cos_string_t bucket;
    cos_http_request_t req;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    options->config = cos_config_create(options->pool);
    options->config->is_cname = 0;
    cos_str_set(&options->config->endpoint, "140.205.63.8");

    cos_str_set(&bucket, "bucket-1");
    
    cos_get_bucket_uri(options, &bucket, &req);
    CuAssertStrEquals(tc, "", req.proto);
    CuAssertStrEquals(tc, "", req.uri);
    CuAssertStrEquals(tc, "140.205.63.8", req.host);
    CuAssertStrEquals(tc, "", req.resource);
    
    cos_pool_destroy(p);

    printf("test_cos_get_bucket_uri_with_ip ok\n");
}

void test_cos_get_bucket_uri_with_cname(CuTest *tc) {
    cos_pool_t *p;
    cos_request_options_t *options;
    cos_string_t bucket;
    cos_http_request_t req;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    options->config = cos_config_create(options->pool);
    options->config->is_cname = 1;
    cos_str_set(&options->config->endpoint, "https://img.abc.com");

    cos_str_set(&bucket, "bucket-1");
    
    cos_get_bucket_uri(options, &bucket, &req);
    CuAssertStrEquals(tc, "https://", req.proto);
    CuAssertStrEquals(tc, "", req.uri);
    CuAssertStrEquals(tc, "img.abc.com", req.host);
    CuAssertStrEquals(tc, "", req.resource);
    
    cos_pool_destroy(p);

    printf("test_cos_get_bucket_uri_with_cname ok\n");
}

void test_cos_log_format_default(CuTest *tc) {
    /*
     * check is coredump
     */
    cos_log_format_default(COS_LOG_INFO, "/tmp/a", 10, "fun1", "%d-%d", 1, 2);

    printf("test_cos_log_format_default ok\n");
}

void test_cos_log_print_default_with_null_file(CuTest *tc) {
    /*
     * check is coredump
     */
    cos_stderr_file = NULL;
    cos_log_print_default("abc", 3);

    printf("test_cos_log_print_default_with_null_file ok\n");
}

/*
 * cos_transport
 */
void test_cos_curl_code_to_status(CuTest *tc) {
    int code = cos_curl_code_to_status(CURLE_OUT_OF_MEMORY);
    CuAssertIntEquals(tc, COSE_OUT_MEMORY, code);

    code = cos_curl_code_to_status(CURLE_COULDNT_RESOLVE_PROXY);
    CuAssertIntEquals(tc, COSE_NAME_LOOKUP_ERROR, code);

    code = cos_curl_code_to_status(CURLE_COULDNT_RESOLVE_HOST);
    CuAssertIntEquals(tc, COSE_NAME_LOOKUP_ERROR, code);

    code = cos_curl_code_to_status(CURLE_COULDNT_CONNECT);
    CuAssertIntEquals(tc, COSE_FAILED_CONNECT, code);

    code = cos_curl_code_to_status(CURLE_WRITE_ERROR);
    CuAssertIntEquals(tc, COSE_CONNECTION_FAILED, code);

    code = cos_curl_code_to_status(CURLE_OPERATION_TIMEDOUT);
    CuAssertIntEquals(tc, COSE_CONNECTION_FAILED, code);

    code = cos_curl_code_to_status(CURLE_PARTIAL_FILE);
    CuAssertIntEquals(tc, COSE_OK, code);

    code = cos_curl_code_to_status(CURLE_SSL_CACERT);
    CuAssertIntEquals(tc, COSE_FAILED_VERIFICATION, code);

    code = cos_curl_code_to_status(CURLE_FTP_WEIRD_PASV_REPLY);
    CuAssertIntEquals(tc, COSE_INTERNAL_ERROR, code);

    printf("test_cos_curl_code_to_status ok\n");
}

/*
 * cos_string.h
 */
void test_cos_unquote_str(CuTest *tc) {
    cos_string_t str;
    cos_str_set(&str, "\"abc\"");
    cos_unquote_str(&str);

    CuAssertStrnEquals(tc, "abc", strlen("abc"), str.data);
    CuAssertIntEquals(tc, 3, str.len);

    printf("test_cos_unquote_str ok\n");
}

void test_cos_ends_with(CuTest *tc) {
    int ret;
    cos_string_t str;
    cos_string_t suffix;

    cos_str_set(&str, "abc.mn.qp");

    cos_str_set(&suffix, ".qp");
    ret = cos_ends_with(&str, &suffix);
    CuAssertIntEquals(tc, 1, ret);

    cos_str_set(&suffix, ".mn");
    ret = cos_ends_with(&str, &suffix);
    CuAssertIntEquals(tc, 0, ret);

    ret = cos_ends_with(&str, NULL);
    CuAssertIntEquals(tc, 0, ret);

    printf("test_cos_ends_with ok\n");
}

/*
 * cos_util.h
 */

void test_cos_url_encode_failed(CuTest *tc) {
    int ret;
    char *dest;
    dest = (char*)malloc(1024);
    
    ret = cos_url_encode(dest, "/mingdi-hz-3/./xxx/./ddd/", 1);
    CuAssertIntEquals(tc, COSE_INVALID_ARGUMENT, ret);

    free(dest);

    printf("test_cos_url_encode_failed ok\n");
}

void test_cos_url_encode_with_blank_char(CuTest *tc) {
    int ret;
    char *source;
    char *dest;
    source = "abc.xx.com/a b";
    dest = (char*)malloc(20);
    
    ret = cos_url_encode(dest, source, strlen(source));
    CuAssertIntEquals(tc, COSE_OK, ret);
    CuAssertStrEquals(tc, "abc.xx.com%2Fa%20b", dest);

    free(dest);

    printf("test_cos_url_encode_with_blank_char ok\n");
}

void test_cos_url_decode_with_percent(CuTest *tc) {
    int ret;
    char *in;
    char *out;

    in = "abc.xx.com/a%20b";
    out = (char*)malloc(20);
    
    ret = cos_url_decode(in, out);
    CuAssertIntEquals(tc, 0, ret);

    free(out);
    
    printf("test_cos_url_decode_with_percent ok\n");
}

void test_cos_url_decode_with_add(CuTest *tc) {
    int ret;
    char *in;
    char *out;

    in = "abc.xx.com/a+b";
    out = (char*)malloc(20);
    
    ret = cos_url_decode(in, out);
    CuAssertIntEquals(tc, 0, ret);

    free(out);

    printf("test_cos_url_decode_with_add ok\n");
}

void test_cos_url_decode_failed(CuTest *tc) {
    int ret;
    char *in;
    char *out;

    in = "abc.xx.com/a%xb";
    out = (char*)malloc(20);
    
    ret = cos_url_decode(in, out);
    CuAssertIntEquals(tc, -1, ret);

    free(out);
    
    printf("test_cos_url_decode_failed ok\n");
}

void test_cos_should_retry(CuTest *tc) {
    cos_status_t s;
    cos_status_set(&s, 500, "", "");
    CuAssertIntEquals(tc, 1, cos_should_retry(&s));

    cos_status_set(&s, 505, "", "");
    CuAssertIntEquals(tc, 1, cos_should_retry(&s));

    cos_status_set(&s, 400, "", "");
    CuAssertIntEquals(tc, 0, cos_should_retry(&s));

    cos_status_set(&s, 0, "-995", "");
    CuAssertIntEquals(tc, 1, cos_should_retry(&s));

    cos_status_set(&s, 0, "-993", "");
    CuAssertIntEquals(tc, 0, cos_should_retry(&s));

    cos_status_set(&s, 0, "0", "NULL");
    CuAssertIntEquals(tc, 0, cos_should_retry(&s));

    CuAssertIntEquals(tc, 0, cos_should_retry(NULL));

    cos_status_set(&s, 200, "", "");
    CuAssertIntEquals(tc, 0, cos_should_retry(&s));

    cos_status_set(&s, 200, NULL, NULL);
    CuAssertIntEquals(tc, 0, cos_should_retry(&s));

    printf("test_cos_should_retry ok\n");
}

void test_cos_strtoll(CuTest *tc)
{
    int64_t val = 0;
    char *endptr = NULL;

    val = cos_strtoll("0", NULL, 10);
    CuAssertTrue(tc, val == 0);

    val = cos_strtoll("9223372036854775807", NULL, 10);
    CuAssertTrue(tc, val == 9223372036854775807);

    val = cos_strtoll("-9223372036854775808", NULL, 10);
    CuAssertTrue(tc, val == INT64_MIN);

    val = cos_strtoll("2147483648ABC", &endptr, 10);
    CuAssertTrue(tc, val == 2147483648);
    CuAssertStrEquals(tc, endptr, "ABC");

    val = cos_atoi64("0");
    CuAssertTrue(tc, val == 0);

    val = cos_atoi64("9223372036854775807");
    CuAssertTrue(tc, val == 9223372036854775807);

    val = cos_atoi64("-9223372036854775808");
    CuAssertTrue(tc, val == INT64_MIN);
}

void test_cos_strtoull(CuTest *tc)
{
    uint64_t val = 0;
    char *endptr = NULL;

    val = cos_strtoull("0", NULL, 10);
    CuAssertTrue(tc, val == 0);

    val = cos_strtoull("9223372036854775807", NULL, 10);
    CuAssertTrue(tc, val == 9223372036854775807);

    val = cos_strtoull("18446744073709551615", NULL, 10);
    CuAssertTrue(tc, val == UINT64_MAX);

    val = cos_strtoll("2147483648ABC", &endptr, 10);
    CuAssertTrue(tc, val == 2147483648);
    CuAssertStrEquals(tc, endptr, "ABC");

    val = cos_atoui64("0");
    CuAssertTrue(tc, val == 0);

    val = cos_atoui64("9223372036854775807");
    CuAssertTrue(tc, val == 9223372036854775807);

    val = cos_atoui64("18446744073709551615");
    CuAssertTrue(tc, val == UINT64_MAX);
}

CuSuite *test_cos_sys()
{
    CuSuite* suite = CuSuiteNew();   

    SUITE_ADD_TEST(suite, test_get_xml_doc_with_empty_cos_list);
    SUITE_ADD_TEST(suite, test_cos_list_movelist_with_empty_list);
    SUITE_ADD_TEST(suite, test_starts_with_failed);
    SUITE_ADD_TEST(suite, test_is_valid_ip);
    SUITE_ADD_TEST(suite, test_cos_request_options_create_with_null_pool);
    SUITE_ADD_TEST(suite, test_cos_get_part_size);
    SUITE_ADD_TEST(suite, test_cos_get_object_uri_with_cname);
    SUITE_ADD_TEST(suite, test_cos_get_object_uri_with_ip);
    SUITE_ADD_TEST(suite, test_cos_get_bucket_uri_with_cname);
    SUITE_ADD_TEST(suite, test_cos_get_bucket_uri_with_ip);
    SUITE_ADD_TEST(suite, test_cos_log_format_default);
    SUITE_ADD_TEST(suite, test_cos_log_print_default_with_null_file);
    SUITE_ADD_TEST(suite, test_cos_curl_code_to_status);
    SUITE_ADD_TEST(suite, test_cos_unquote_str);
    SUITE_ADD_TEST(suite, test_cos_ends_with);
    SUITE_ADD_TEST(suite, test_cos_url_encode_failed);
    SUITE_ADD_TEST(suite, test_cos_url_encode_with_blank_char);
    SUITE_ADD_TEST(suite, test_cos_url_decode_with_percent);
    SUITE_ADD_TEST(suite, test_cos_url_decode_with_add);
    SUITE_ADD_TEST(suite, test_cos_url_decode_failed);
    SUITE_ADD_TEST(suite, test_cos_should_retry);
    SUITE_ADD_TEST(suite, test_cos_strtoll);
    SUITE_ADD_TEST(suite, test_cos_strtoull);

    return suite;
}
