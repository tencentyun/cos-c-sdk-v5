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
 * cos_status.h
 */
void test_cos_status_parse_from_body(CuTest *tc) {
    cos_pool_t *pool;
    apr_pool_create(&pool, NULL);

    // 调用要测试的函数
    {
        cos_status_t s;
        int res = cos_status_parse_from_body(pool, NULL, 200, &s);
        printf("test_cos_status_parse_from_body 200 ok\n");
    }
    {
        cos_list_t body;
        cos_list_init(&body);
        const char *buffer = "<root><Status>active</Status><Name>test</Name><Type>test</Type><ForcedReplacement>test</ForcedReplacement></DomainRule></root>";

        cos_buf_t *b;
        int len = strlen(buffer);
        b = cos_create_buf(pool, len);
        memcpy(b->pos, buffer, len);
        b->last += len;
        cos_list_add_tail(&b->node, &body);
        cos_status_t s;
        int res = cos_status_parse_from_body(pool, &body, 400, &s);
        CuAssertIntEquals(tc, s.error_code, COS_UNKNOWN_ERROR_CODE);
        printf("test_cos_status_parse_from_body 400 1ok\n");
    }
    {
        cos_list_t body;
        cos_list_init(&body);
        const char *buffer = "<root><Status>active</Status><Name>test</Name><ETag>test</ETag><ForcedReplacement>test</ForcedReplacement></DomainRule></root>";

        cos_buf_t *b;
        int len = strlen(buffer);
        b = cos_create_buf(pool, len);
        memcpy(b->pos, buffer, len);
        b->last += len;
        cos_list_add_tail(&b->node, &body);
        cos_status_t s;
        int res = check_status_with_resp_body(&body, strlen(buffer), "ETag");
        CuAssertIntEquals(tc, res, COS_TRUE);
        printf("test_cos_status_parse_from_body 400 1ok\n");
    }
    {
        cos_list_t body;
        cos_list_init(&body);
        const char *buffer = "<root><Status>active</Status><Name>test</Name><ForcedReplacement>test</ForcedReplacement></DomainRule></root>";

        cos_buf_t *b;
        int len = strlen(buffer);
        b = cos_create_buf(pool, len);
        memcpy(b->pos, buffer, len);
        b->last += len;
        cos_list_add_tail(&b->node, &body);
        cos_status_t s;
        int res = check_status_with_resp_body(&body, strlen(buffer), "ETag");
        CuAssertIntEquals(tc, res, COS_FALSE);
        printf("test_cos_status_parse_from_body 400 1ok\n");
    }
    {
        cos_list_t body;
        cos_list_init(&body);
        const char *buffer = "<root><Status>active</Status></root>";

        cos_buf_t *b;
        int len = strlen(buffer);
        b = cos_create_buf(pool, len);
        memcpy(b->pos, buffer, len);
        b->last += len;
        cos_list_add_tail(&b->node, &body);
        cos_status_t s;
        int res = cos_status_parse_from_body(pool, &body, 400, &s);
        CuAssertIntEquals(tc, s.error_code, COS_UNKNOWN_ERROR_CODE);
        printf("test_cos_status_parse_from_body 400 2ok\n");
    }
    printf("test_cos_status_parse_from_body ok\n");
}

/*
 * cos_xml.c
 */
void test_get_xml_doc_with_empty_cos_list(CuTest *tc) {
    set_retry_change_domin(0);
    cos_log_set_print(cos_log_print_default);
    cos_log_set_format(cos_log_format_default);
    int ret;
    mxml_node_t *xml_node;
    cos_list_t bc;
    cos_list_init(&bc);

    ret = get_xmldoc(&bc, &xml_node);
    CuAssertIntEquals(tc, COSE_XML_PARSE_ERROR, ret);

    printf("test_get_xml_doc_with_empty_cos_list ok\n");
}

void test_build_lifecycle_xml(CuTest *tc) {
    cos_pool_t *pool = NULL;
    cos_pool_create(&pool, NULL);

    cos_lifecycle_rule_content_t rule1;
    cos_str_set(&rule1.id, "rule1");
    cos_str_set(&rule1.prefix, "prefix1");
    cos_str_set(&rule1.status, "Enabled");
    rule1.expire.days = 1;
    rule1.transition.days = INT_MAX;
    rule1.abort.days = INT_MAX;

    cos_lifecycle_rule_content_t rule2;
    cos_str_set(&rule2.id, "rule2");
    cos_str_set(&rule2.prefix, "prefix2");
    cos_str_set(&rule2.status, "Disabled");
    rule2.expire.days = INT_MAX;
    cos_str_set(&rule2.expire.date, "2023-01-01T00:00:00.000Z");
    rule2.transition.days = 7;
    cos_str_set(&rule2.transition.date, "2023-01-01T00:00:00.000Z");
    cos_str_set(&rule2.transition.storage_class, "Standard_IA");
    rule2.abort.days = 1111111;

    cos_list_t lifecycle_rule_list;
    cos_list_init(&lifecycle_rule_list);
    cos_list_add_tail(&rule1.node, &lifecycle_rule_list);
    cos_list_add_tail(&rule2.node, &lifecycle_rule_list);

    char *lifecycle_xml = build_lifecycle_xml(pool, &lifecycle_rule_list);
    cos_pool_destroy(pool);
    printf("test_build_lifecycle_xml ok\n");
}


void test_cos_serveral_parse_from_xml_node(CuTest *tc) {
    apr_initialize();

    // 创建内存池
    cos_pool_t *pool;
    apr_pool_create(&pool, NULL);

    // 准备测试数据
    const char *test_xml = "<root><test>hello</test></root>\n";
    mxml_node_t *root = mxmlLoadString(NULL, test_xml, MXML_OPAQUE_CALLBACK);
    mxml_node_t *pnode = mxmlFindElement(root, root, "root", NULL, NULL, MXML_DESCEND);
    cos_string_t param;

    // 调用要测试的函数
    mxml_node_t *node = cos_serveral_parse_from_xml_node(pool, pnode, root, "test", &param);
    // 清理
    mxmlDelete(root);
    cos_pool_destroy(pool);
    apr_terminate();
    printf("test_cos_serveral_parse_from_xml_node ok\n");
}

void print_node_values(mxml_node_t *node) {
    mxml_type_t type = mxmlGetType(node);

    switch (type) {
        case MXML_ELEMENT:
            printf("ELEMENT: %s\n", mxmlGetElement(node));
            break;
        case MXML_TEXT:
            printf("TEXT: '%s'\n", mxmlGetText(node, NULL));
            break;
        default:
            printf("UNKNOWN TYPE: %d\n", type);
    }

    mxml_node_t *child = mxmlGetFirstChild(node);
    while (child) {
        print_node_values(child);
        child = mxmlGetNextSibling(child);
    }
}

void test_cos_get_domain_parse_from_body(CuTest *tc) {
    cos_pool_t *pool;
    apr_pool_create(&pool, NULL);

    // 创建 cos_list_t 对象并加载测试数据
    cos_list_t body;
    cos_list_init(&body);
    const char *buffer = "<root><DomainRule><Status>active</Status><Name>test</Name><Type>test</Type><ForcedReplacement>test</ForcedReplacement></DomainRule></root>";

    cos_buf_t *b;
    int len = strlen(buffer);
    b = cos_create_buf(pool, len);
    memcpy(b->pos, buffer, len);
    b->last += len;
    cos_list_add_tail(&b->node, &body);

    // 创建 cos_domain_params_t 对象
    cos_domain_params_t *domain = cos_create_domain_params(pool);

    // 调用要测试的函数
    int res = cos_get_domain_parse_from_body(pool, &body, domain);

    mxml_node_t *root = mxmlLoadString(NULL, buffer, MXML_OPAQUE_CALLBACK);
    print_node_values(root);
    mxmlDelete(root);

    // 检查结果
    CuAssertIntEquals(tc, COSE_OK, res);
    CuAssertStrEquals(tc, "active", domain->status.data);
    CuAssertStrEquals(tc, "test", domain->name.data);
    CuAssertStrEquals(tc, "test", domain->type.data);
    CuAssertStrEquals(tc, "test", domain->forced_replacement.data);
    cos_pool_destroy(pool);
    printf("test_cos_get_domain_parse_from_body ok\n");
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

    cos_list_t list2;
    cos_list_init(&list2);
    cos_pool_t *pool;
    apr_pool_create(&pool, NULL);

    cos_object_key_t *object_key = cos_create_cos_object_key(pool);
    char *key = apr_psprintf(pool, "%.*s", 2,
                               "22");
    cos_str_set(&object_key->key, key);
    cos_list_add_tail(&object_key->node, &list2);
    cos_list_del(&object_key->node);
}

/*
 * cos_util.c
 */
void test_change_host_suffix(CuTest *tc) {
    char *endpoint = "example.cos.myqcloud.com";
    change_host_suffix(&endpoint);
    CuAssertStrEquals(tc, "example.cos.tencentcos.cn", endpoint);
    printf("test_change_host_suffix ok\n");
}
void test_change_endpoint_suffix(CuTest *tc) {
    cos_string_t endpoint;
    endpoint.data = strdup("example.cos.myqcloud.com");
    endpoint.len = strlen(endpoint.data);
    change_endpoint_suffix(&endpoint);
    CuAssertStrEquals(tc, "example.cos.tencentcos.cn", endpoint.data);
    clear_change_endpoint_suffix(&endpoint, "test");
    CuAssertStrEquals(tc, "test", endpoint.data);
    printf("test_change_endpoint_suffix ok\n");
}
void test_cos_set_request_route(CuTest *tc) {
    cos_pool_t *pool;
    cos_request_options_t *options;
    cos_pool_create(&pool, NULL);
    options = cos_request_options_create(pool);
    options->config = cos_config_create(options->pool);
    cos_str_set(&options->config->endpoint, "<用户的Endpoint>");
    cos_str_set(&options->config->access_key_id, "<用户的SecretId>");
    cos_str_set(&options->config->access_key_secret, "<用户的SecretKey>");
    cos_str_set(&options->config->appid, "<用户的AppId>");
    options->config->is_cname = 0;
    options->ctl = cos_http_controller_create(options->pool, 0);
    cos_set_content_md5_enable(options->ctl, COS_FALSE);
    cos_set_request_route(options->ctl, "1.2.3.4", 80);
    cos_pool_destroy(pool);
    printf("test_cos_set_request_route ok\n");
}
void test_cos_gen_object_url(CuTest *tc) {
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, "TEST_BUCKET_NAME");
    cos_str_set(&object, "TEST_OBJECT_NAME1");

    printf("url:%s\n", cos_gen_object_url(options, &bucket, &object));

    cos_pool_destroy(p);
    printf("test_cos_gen_object_url ok\n");
}
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
    char error_msg[256] = {0};

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    options->config = cos_config_create(options->pool);
    options->config->is_cname = 1;
    cos_str_set(&options->config->endpoint, "img.abc.com");

    cos_str_set(&bucket, "bucket-1");
    cos_str_set(&object, "key-2");

    cos_get_object_uri(options, &bucket, &object, &req, &error_msg);
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
    char error_msg[256] = {0};

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    options->config = cos_config_create(options->pool);
    options->config->is_cname = 0;
    cos_str_set(&options->config->endpoint, "http://140.205.63.8");

    cos_str_set(&bucket, "bucket-1");
    cos_str_set(&object, "key-2");

    cos_get_object_uri(options, &bucket, &object, &req, &error_msg);
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
    char error_msg[256] = {0};

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    options->config = cos_config_create(options->pool);
    options->config->is_cname = 0;
    cos_str_set(&options->config->endpoint, "140.205.63.8");

    cos_str_set(&bucket, "bucket-1");

    cos_get_bucket_uri(options, &bucket, &req, &error_msg);
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
    char error_msg[256] = {0};

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    options->config = cos_config_create(options->pool);
    options->config->is_cname = 1;
    cos_str_set(&options->config->endpoint, "https://img.abc.com");

    cos_str_set(&bucket, "bucket-1");

    cos_get_bucket_uri(options, &bucket, &req, &error_msg);
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
void test_is_default_domain(CuTest *tc) {
    int code = is_default_domain("xxxxxx-123.cos.ap-guangzhou.myqcloud.com");
    CuAssertIntEquals(tc, 1, code);
    printf("test_is_default_domain ok\n");
}
void test_is_config_params_vaild(CuTest *tc) {
    {
        cos_pool_t *p = NULL;
        int is_cname = 0;
        cos_request_options_t *options = NULL;
        char *error_msg = "xxxxxx";
        options = cos_request_options_create(p);
        init_test_request_options(options, is_cname);
        options->config->endpoint.data = "";
        options->config->endpoint.len = 0;
        cos_string_t bucket;
        cos_str_set(&bucket, "qp");

        int code = cos_get_object_uri(options, &bucket, NULL, NULL, &error_msg);
        CuAssertIntEquals(tc, 0, code);
        printf("test_is_config_params_vaild endpoint invaild ok\n");
    }
    {
        cos_pool_t *p = NULL;
        int is_cname = 0;
        cos_request_options_t *options = NULL;
        char *error_msg = "xxxxxx";
        options = cos_request_options_create(p);
        init_test_request_options(options, is_cname);

        int code = cos_get_object_uri(options, NULL, NULL, NULL, &error_msg);
        CuAssertIntEquals(tc, 0, code);
        printf("test_is_config_params_vaild bucket invaild ok\n");
    }

    {
        cos_pool_t *p = NULL;
        int is_cname = 0;
        cos_request_options_t *options = NULL;
        char *error_msg = "xxxxxx";
        options = cos_request_options_create(p);
        init_test_request_options(options, is_cname);

        cos_string_t bucket;
        cos_str_set(&bucket, "qp");
        options->config->access_key_id.data = "\n";
        options->config->access_key_id.len = 1;
        int code = cos_get_object_uri(options, &bucket, NULL, NULL, &error_msg);
        CuAssertIntEquals(tc, 0, code);
        printf("test_is_config_params_vaild ak invaild ok\n");
    }

    {
        cos_pool_t *p = NULL;
        int is_cname = 0;
        cos_request_options_t *options = NULL;
        char *error_msg = "xxxxxx";
        options = cos_request_options_create(p);
        init_test_request_options(options, is_cname);

        cos_string_t bucket;
        cos_str_set(&bucket, "qp");
        options->config->access_key_secret.data = "\n";
        options->config->access_key_secret.len = 1;
        int code = cos_get_object_uri(options, &bucket, NULL, NULL, &error_msg);
        printf("test_is_config_params_vaild sk invaild 1ok\n");
        CuAssertIntEquals(tc, 0, code);
        code = cos_get_service_uri(options, 1, NULL, &error_msg);
        CuAssertIntEquals(tc, 0, code);
        printf("test_is_config_params_vaild sk invaild 2ok\n");
    }
    {
        cos_pool_t *p = NULL;
        cos_request_options_t *options = NULL;
        cos_table_t *resp_headers = NULL;
        int is_cname = 0;
        cos_status_t *s = NULL;

        options = cos_request_options_create(p);
        init_test_request_options(options, is_cname);
        cos_http_request_t *req = cos_http_request_create(options->pool);;
        char *error_msg = "xxxxxx";
        int code = cos_get_service_uri(options, 2, req, &error_msg);
        CuAssertIntEquals(tc, 1, code);
        printf("test_cos_get_service_uri sk invaild 2ok\n");
    }

    {
        cos_string_t test;
        cos_str_set(&test, "xxxxx");
        int code = starts_with(&test, "a");
        CuAssertIntEquals(tc, 0, code);
        printf("test_is_config_params_vaild starts_with invaild ok\n");
    }

}

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

void test_cos_strtoll(CuTest *tc) {
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

void test_cos_strtoull(CuTest *tc) {
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

CuSuite *test_cos_sys() {
    CuSuite* suite = CuSuiteNew();

    SUITE_ADD_TEST(suite, test_is_default_domain);
    SUITE_ADD_TEST(suite, test_is_config_params_vaild);
    SUITE_ADD_TEST(suite, test_cos_status_parse_from_body);
    SUITE_ADD_TEST(suite, test_get_xml_doc_with_empty_cos_list);
    SUITE_ADD_TEST(suite, test_build_lifecycle_xml);
    SUITE_ADD_TEST(suite, test_cos_serveral_parse_from_xml_node);
    SUITE_ADD_TEST(suite, test_cos_get_domain_parse_from_body);
    SUITE_ADD_TEST(suite, test_cos_list_movelist_with_empty_list);
    SUITE_ADD_TEST(suite, test_change_endpoint_suffix);
    SUITE_ADD_TEST(suite, test_change_host_suffix);
    SUITE_ADD_TEST(suite, test_cos_set_request_route);
    SUITE_ADD_TEST(suite, test_cos_gen_object_url);
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
