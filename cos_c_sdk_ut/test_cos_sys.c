#include "CuTest.h"
#include "apr_file_io.h"
#include "cos_log.h"
#include "cos_sys_util.h"
#include "cos_string.h"
#include "cos_status.h"
#include "cos_auth.h"
#include "cos_xml.h"
#include "cos_utility.h"
#include "cos_transport.h"
#include "cos_buf.h"
#include "cos_http_io.h"
#include "cos_define.h"
#include "mxml.h"
#include <unistd.h>

extern int starts_with(const cos_string_t *str, const char *prefix);
extern int cos_curl_code_to_status(CURLcode code);

static void make_body_from_string(cos_pool_t *pool, cos_list_t *body, const char *buffer) {
    cos_buf_t *b;
    int len = strlen(buffer);

    cos_list_init(body);
    b = cos_create_buf(pool, len);
    memcpy(b->pos, buffer, len);
    b->last += len;
    cos_list_add_tail(&b->node, body);
}

/*
 * cos_status.h
 */
void test_cos_status_parse_from_body(CuTest *tc) {
    cos_pool_t *pool;
    apr_pool_create(&pool, NULL);

    {
        cos_status_t s;
        memset(&s, 0, sizeof(cos_status_t));
        cos_status_parse_from_body(pool, NULL, 200, COS_FALSE, &s);
        CuAssertIntEquals(tc, 200, s.code);
        CuAssertPtrEquals(tc, NULL, s.error_code);
    }
    {
        cos_list_t body;
        const char *buffer = "<Error><Code>InternalError</Code><Message>error message</Message></Error>";
        cos_status_t s;

        memset(&s, 0, sizeof(cos_status_t));
        make_body_from_string(pool, &body, buffer);
        cos_status_parse_from_body(pool, &body, 200, COS_FALSE, &s);
        CuAssertIntEquals(tc, 200, s.code);
        CuAssertPtrEquals(tc, NULL, s.error_code);
    }
    {
        cos_list_t body;
        const char *buffer = "<Error><Code>InternalError</Code><Message>error message</Message></Error>";
        cos_status_t s;

        memset(&s, 0, sizeof(cos_status_t));
        make_body_from_string(pool, &body, buffer);
        cos_status_parse_from_body(pool, &body, 200, COS_TRUE, &s);
        CuAssertIntEquals(tc, COSE_SERVICE_ERROR, s.code);
        CuAssertStrEquals(tc, COS_INTERNAL_ERROR_CODE, s.error_code);
        CuAssertStrEquals(tc, "error message", s.error_msg);
    }
    {
        cos_list_t body;
        const char *buffer = "<?xml version='1.0' encoding='utf-8' ?><Error><Code>InternalError</Code><Message>error message</Message></Error>";
        cos_status_t s;

        memset(&s, 0, sizeof(cos_status_t));
        make_body_from_string(pool, &body, buffer);
        cos_status_parse_from_body(pool, &body, 200, COS_TRUE, &s);
        CuAssertIntEquals(tc, COSE_SERVICE_ERROR, s.code);
        CuAssertStrEquals(tc, COS_INTERNAL_ERROR_CODE, s.error_code);
        CuAssertStrEquals(tc, "error message", s.error_msg);
    }
    {
        cos_list_t body;
        const char *buffer = "<CopyObjectResult><ETag>test</ETag></CopyObjectResult>";
        cos_status_t s;

        memset(&s, 0, sizeof(cos_status_t));
        make_body_from_string(pool, &body, buffer);
        cos_status_parse_from_body(pool, &body, 200, COS_TRUE, &s);
        CuAssertIntEquals(tc, 200, s.code);
        CuAssertPtrEquals(tc, NULL, s.error_code);
    }
    {
        cos_list_t body;
        const char *buffer = "<Response><Wrapper><Error><Code>SlowDown</Code><Message>retry later</Message></Error></Wrapper></Response>";
        cos_status_t s;

        memset(&s, 0, sizeof(cos_status_t));
        make_body_from_string(pool, &body, buffer);
        cos_status_parse_from_body(pool, &body, 200, COS_TRUE, &s);
        CuAssertIntEquals(tc, COSE_SERVICE_ERROR, s.code);
        CuAssertStrEquals(tc, COS_SLOW_DOWN_ERROR_CODE, s.error_code);
        CuAssertStrEquals(tc, "retry later", s.error_msg);
    }
    {
        cos_list_t body;
        const char *buffer = "<Error><Code>InternalError</Code><Message>error message</Message></Error>";
        cos_status_t s;

        memset(&s, 0, sizeof(cos_status_t));
        make_body_from_string(pool, &body, buffer);
        cos_status_parse_from_body(pool, &body, 500, COS_FALSE, &s);
        CuAssertIntEquals(tc, 500, s.code);
        CuAssertStrEquals(tc, COS_INTERNAL_ERROR_CODE, s.error_code);
        CuAssertStrEquals(tc, "error message", s.error_msg);
    }
    {
        cos_list_t body;
        const char *buffer = "<root><Status>active</Status><Name>test</Name><Type>test</Type><ForcedReplacement>test</ForcedReplacement></DomainRule></root>";
        cos_status_t s;

        memset(&s, 0, sizeof(cos_status_t));
        make_body_from_string(pool, &body, buffer);
        cos_status_parse_from_body(pool, &body, 400, COS_FALSE, &s);
        CuAssertIntEquals(tc, 400, s.code);
        CuAssertStrEquals(tc, COS_UNKNOWN_ERROR_CODE, s.error_code);
    }
    {
        cos_list_t body;
        const char *buffer = "<root><Status>active</Status><Name>test</Name><ETag>test</ETag><ForcedReplacement>test</ForcedReplacement></DomainRule></root>";
        int res;

        make_body_from_string(pool, &body, buffer);
        res = check_status_with_resp_body(&body, strlen(buffer), "ETag");
        CuAssertIntEquals(tc, COS_TRUE, res);
    }
    {
        cos_list_t body;
        const char *buffer = "<root><Status>active</Status><Name>test</Name><ForcedReplacement>test</ForcedReplacement></DomainRule></root>";
        int res;

        make_body_from_string(pool, &body, buffer);
        res = check_status_with_resp_body(&body, strlen(buffer), "ETag");
        CuAssertIntEquals(tc, COS_FALSE, res);
    }
    {
        cos_list_t body;
        const char *buffer = "<root><Status>active</Status></root>";
        cos_status_t s;

        memset(&s, 0, sizeof(cos_status_t));
        make_body_from_string(pool, &body, buffer);
        cos_status_parse_from_body(pool, &body, 400, COS_FALSE, &s);
        CuAssertIntEquals(tc, 400, s.code);
        CuAssertStrEquals(tc, COS_UNKNOWN_ERROR_CODE, s.error_code);
    }

    apr_pool_destroy(pool);
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
    CuAssertIntEquals(tc, COSE_CONNECTION_FAILED, code);

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


/* fix/body_error_retry 补强 UT：
 * - CopySource 改写通过上层 do_switch_domain 覆盖，底层 helper 保持 static。
 * - Error 节点查找通过 cos_status_parse_from_body 覆盖，底层 helper 保持 static。
 * - cos_retry_file_state_t 定义在 cos_define.h，避免 UT 复制内部结构体布局。
 */
extern int do_switch_domain(const cos_request_options_t *options,
                            cos_http_request_t *req);
extern void cos_retry_file_state_init(cos_retry_file_state_t *state,
                                      const cos_http_request_t *req,
                                      const cos_http_response_t *resp);
extern int cos_retry_reset_state(cos_pool_t *pool,
                                 cos_http_controller_t *ctl,
                                 cos_http_request_t *req,
                                 cos_http_response_t *resp,
                                 const cos_retry_file_state_t *state);

/* ---------- UT-2: do_switch_domain 覆盖 Host + CopySource 一致切换 ---------- */
void test_do_switch_domain(CuTest *tc) {
    cos_pool_t *p = NULL;
    cos_pool_create(&p, NULL);

    cos_request_options_t *options = cos_request_options_create(p);

    /* Host 与 x-cos-copy-source 都应从 myqcloud.com 切到 tencentcos.cn */
    {
        cos_http_request_t *req = cos_http_request_create(p);
        req->host = apr_pstrdup(p, "bucket-1250000000.cos.ap-guangzhou.myqcloud.com");
        apr_table_set(req->headers, COS_COPY_SOURCE,
                      "srcbucket-1250000000.cos.ap-guangzhou.myqcloud.com/dir/key.txt");

        int res = do_switch_domain(options, req);
        CuAssertIntEquals(tc, COSE_OK, res);
        CuAssertStrEquals(tc,
            "bucket-1250000000.cos.ap-guangzhou.tencentcos.cn", req->host);
        CuAssertStrEquals(tc,
            "srcbucket-1250000000.cos.ap-guangzhou.tencentcos.cn/dir/key.txt",
            apr_table_get(req->headers, COS_COPY_SOURCE));
    }

    /* 没有 x-cos-copy-source 时只切 Host，不新增 header */
    {
        cos_http_request_t *req = cos_http_request_create(p);
        req->host = apr_pstrdup(p, "bucket-1250000000.cos.ap-guangzhou.myqcloud.com");

        int res = do_switch_domain(options, req);
        CuAssertIntEquals(tc, COSE_OK, res);
        CuAssertStrEquals(tc,
            "bucket-1250000000.cos.ap-guangzhou.tencentcos.cn", req->host);
        CuAssertPtrEquals(tc, NULL,
            (void *)apr_table_get(req->headers, COS_COPY_SOURCE));
    }

    /* CopySource 是自定义域名时不应误改，Host 仍正常切换 */
    {
        cos_http_request_t *req = cos_http_request_create(p);
        const char *copy_source = "cdn.example.com/path/myqcloud.com/key";
        req->host = apr_pstrdup(p, "bucket-1250000000.cos.ap-guangzhou.myqcloud.com");
        apr_table_set(req->headers, COS_COPY_SOURCE, copy_source);

        int res = do_switch_domain(options, req);
        CuAssertIntEquals(tc, COSE_OK, res);
        CuAssertStrEquals(tc,
            "bucket-1250000000.cos.ap-guangzhou.tencentcos.cn", req->host);
        CuAssertStrEquals(tc, copy_source,
            apr_table_get(req->headers, COS_COPY_SOURCE));
    }

    /* CopySource 已是 tencentcos.cn 时，按当前实现保持不变 */
    {
        cos_http_request_t *req = cos_http_request_create(p);
        const char *copy_source = "srcbucket-1250000000.cos.ap-guangzhou.tencentcos.cn/key";
        req->host = apr_pstrdup(p, "bucket-1250000000.cos.ap-guangzhou.myqcloud.com");
        apr_table_set(req->headers, COS_COPY_SOURCE, copy_source);

        int res = do_switch_domain(options, req);
        CuAssertIntEquals(tc, COSE_OK, res);
        CuAssertStrEquals(tc,
            "bucket-1250000000.cos.ap-guangzhou.tencentcos.cn", req->host);
        CuAssertStrEquals(tc, copy_source,
            apr_table_get(req->headers, COS_COPY_SOURCE));
    }

    cos_pool_destroy(p);
    printf("test_do_switch_domain ok\n");
}

/* ---------- UT-3: cos_resign_request 头清理与重签 ---------- */
/* 当前实现仅 unset Host + Authorization 后重签；本用例锁死该行为，
 * 以便后续若有变更（如同时清 x-cos-security-token）reviewer 能立即看到。 */
void test_cos_resign_request(CuTest *tc) {
    cos_pool_t *p = NULL;
    cos_pool_create(&p, NULL);

    cos_config_t *config = cos_config_create(p);
    cos_str_set(&config->endpoint, "cos.ap-guangzhou.myqcloud.com");
    cos_str_set(&config->access_key_id, "AKID-test");
    cos_str_set(&config->access_key_secret, "SK-test");
    cos_str_set(&config->appid, "1250000000");
    cos_str_set(&config->sts_token, "STS-token-value");
    config->is_cname = 0;

    cos_http_request_t *req = cos_http_request_create(p);
    req->method = HTTP_GET;
    req->host = apr_pstrdup(p, "bucket-1250000000.cos.ap-guangzhou.myqcloud.com");
    req->uri = apr_pstrdup(p, "/key.txt");
    req->resource = apr_pstrdup(p, "key.txt");

    /* 模拟首次签名后的状态：headers 中已有旧 Authorization 与旧 Host */
    apr_table_set(req->headers, COS_HOST, "stale-host.example.com");
    apr_table_set(req->headers, COS_AUTHORIZATION, "STALE-AUTH-VALUE");
    apr_table_set(req->headers, COS_SECURITY_TOKEN, "STS-token-value");
    apr_table_set(req->headers, "x-cos-meta-keep", "must-keep");

    int res = cos_resign_request(req, config);
    CuAssertIntEquals(tc, COSE_OK, res);

    /* Host 应被刷新为 req->host，旧 Authorization 必须被替换 */
    CuAssertStrEquals(tc, req->host, apr_table_get(req->headers, COS_HOST));
    const char *new_auth = apr_table_get(req->headers, COS_AUTHORIZATION);
    CuAssertPtrNotNull(tc, new_auth);
    CuAssertTrue(tc, strcmp(new_auth, "STALE-AUTH-VALUE") != 0);

    /* 业务自定义头不应被误删 */
    CuAssertStrEquals(tc, "must-keep",
        apr_table_get(req->headers, "x-cos-meta-keep"));

    /* 当前实现不清理 x-cos-security-token，锁死现状（如未来策略变更，此断言需同步更新） */
    CuAssertStrEquals(tc, "STS-token-value",
        apr_table_get(req->headers, COS_SECURITY_TOKEN));

    cos_pool_destroy(p);
    printf("test_cos_resign_request ok\n");
}

/* ---------- UT-4: cos_http_request_options_copy / cos_config_copy 深拷贝隔离 ---------- */
void test_cos_http_request_options_copy_isolated(CuTest *tc) {
    cos_pool_t *p = NULL;
    cos_pool_create(&p, NULL);

    cos_http_request_options_t *src = cos_http_request_options_create(p);
    src->connect_timeout = 17;
    src->speed_limit = 1234;
    src->speed_time = 56;
    src->enable_crc = COS_FALSE;
    src->host_port = 8080;
    src->proxy_host = apr_pstrdup(p, "proxy.example.com");
    src->host_ip = apr_pstrdup(p, "1.2.3.4");

    cos_http_request_options_t *dup = cos_http_request_options_copy(p, src);

    /* 标量字段应等值 */
    CuAssertIntEquals(tc, 17, dup->connect_timeout);
    CuAssertIntEquals(tc, 1234, dup->speed_limit);
    CuAssertIntEquals(tc, 56, dup->speed_time);
    CuAssertIntEquals(tc, COS_FALSE, dup->enable_crc);
    CuAssertIntEquals(tc, 8080, dup->host_port);

    /* 指针字段应不同（深拷贝），但内容相同 */
    CuAssertTrue(tc, dup->proxy_host != src->proxy_host);
    CuAssertStrEquals(tc, "proxy.example.com", dup->proxy_host);
    CuAssertTrue(tc, dup->host_ip != src->host_ip);
    CuAssertStrEquals(tc, "1.2.3.4", dup->host_ip);

    /* 修改 dup 不应污染 src */
    dup->connect_timeout = 99;
    dup->host_port = 9999;
    CuAssertIntEquals(tc, 17, src->connect_timeout);
    CuAssertIntEquals(tc, 8080, src->host_port);

    /* src == NULL 时应得到默认 options 而不崩溃 */
    cos_http_request_options_t *fallback = cos_http_request_options_copy(p, NULL);
    CuAssertPtrNotNull(tc, fallback);

    cos_pool_destroy(p);
    printf("test_cos_http_request_options_copy_isolated ok\n");
}

void test_cos_http_controller_create_options_isolated(CuTest *tc) {
    cos_pool_t *p = NULL;
    cos_pool_create(&p, NULL);

    cos_http_controller_t *ctl1 = cos_http_controller_create(p, 0);
    cos_http_controller_t *ctl2 = cos_http_controller_create(p, 0);

    CuAssertPtrNotNull(tc, ctl1);
    CuAssertPtrNotNull(tc, ctl2);
    CuAssertPtrNotNull(tc, ctl1->options);
    CuAssertPtrNotNull(tc, ctl2->options);
    CuAssertTrue(tc, ctl1->options != ctl2->options);

    ctl1->options->connect_timeout = 1;
    ctl1->options->enable_crc = COS_FALSE;
    CuAssertTrue(tc, ctl2->options->connect_timeout != 1);
    CuAssertTrue(tc, ctl2->options->enable_crc != COS_FALSE);

    cos_pool_destroy(p);
    printf("test_cos_http_controller_create_options_isolated ok\n");
}

void test_cos_config_copy_isolated(CuTest *tc) {
    cos_pool_t *p = NULL;
    cos_pool_create(&p, NULL);

    cos_config_t *src = cos_config_create(p);
    cos_str_set(&src->endpoint, "cos.ap-guangzhou.myqcloud.com");
    cos_str_set(&src->access_key_id, "AKID-A");
    cos_str_set(&src->access_key_secret, "SK-A");
    cos_str_set(&src->appid, "1250000000");
    cos_str_set(&src->sts_token, "TOKEN-A");
    cos_str_set(&src->proxy_host, "proxy.example.com");
    cos_str_set(&src->proxy_user, "user-A");
    cos_str_set(&src->proxy_passwd, "passwd-A");
    src->is_cname = 1;
    src->proxy_port = 8080;
    src->retry_change_domain = 1;
    src->retry_times = 5;
    src->retry_interval_us = 100;
    src->omit_cos_sdk_retry_header = COS_TRUE;

    cos_config_t *dup = cos_config_copy(p, src);

    /* 字符串字段应深拷贝（data 指针不同、内容相同） */
    CuAssertTrue(tc, dup->endpoint.data != src->endpoint.data);
    CuAssertIntEquals(tc, src->endpoint.len, dup->endpoint.len);
    CuAssertTrue(tc, strncmp(dup->endpoint.data, src->endpoint.data,
                             src->endpoint.len) == 0);

    CuAssertTrue(tc, dup->access_key_secret.data != src->access_key_secret.data);
    CuAssertTrue(tc, dup->sts_token.data != src->sts_token.data);
    CuAssertTrue(tc, dup->proxy_host.data != src->proxy_host.data);
    CuAssertTrue(tc, dup->proxy_user.data != src->proxy_user.data);
    CuAssertTrue(tc, dup->proxy_passwd.data != src->proxy_passwd.data);

    /* 标量字段应等值 */
    CuAssertIntEquals(tc, 1, dup->is_cname);
    CuAssertIntEquals(tc, 8080, dup->proxy_port);
    CuAssertIntEquals(tc, 1, dup->retry_change_domain);
    CuAssertIntEquals(tc, 5, dup->retry_times);
    CuAssertIntEquals(tc, 100, dup->retry_interval_us);
    CuAssertIntEquals(tc, COS_TRUE, dup->omit_cos_sdk_retry_header);

    /* 修改 dup 不应污染 src */
    dup->retry_times = 99;
    dup->retry_change_domain = 0;
    CuAssertIntEquals(tc, 5, src->retry_times);
    CuAssertIntEquals(tc, 1, src->retry_change_domain);

    /* src == NULL 时返回空 config 不崩溃 */
    cos_config_t *fallback = cos_config_copy(p, NULL);
    CuAssertPtrNotNull(tc, fallback);

    cos_pool_destroy(p);
    printf("test_cos_config_copy_isolated ok\n");
}

/* ---------- UT-1: cos_retry_file_state_t 保存 / cos_retry_reset_state 恢复 ---------- */
/* 这是 B2 的命门：PUT/UploadPart 流式 body 的重试如果没把 file_buf 偏移归位，
 * 第二次发送的就只是"剩余字节"，导致服务端文件被截断或 CRC 不一致。 */
static void write_temp_file(CuTest *tc, const char *path, const char *content, int len) {
    FILE *f = fopen(path, "wb");
    CuAssertPtrNotNull(tc, f);
    CuAssertIntEquals(tc, len, (int)fwrite(content, 1, len, f));
    CuAssertIntEquals(tc, 0, fclose(f));
}

static void assert_file_cur_offset(CuTest *tc, apr_file_t *file, apr_off_t expected) {
    apr_off_t cur = 0;
    apr_file_seek(file, APR_CUR, &cur);
    CuAssertTrue(tc, cur == expected);
}

void test_cos_retry_file_state_save_and_reset(CuTest *tc) {
    cos_pool_t *p = NULL;
    cos_pool_create(&p, NULL);

    const char upload_data[16] = {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P'};
    const char download_data[16] = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p'};
    char upload_path[128];
    char download_path[128];
    char full_download_path[128];
    snprintf(upload_path, sizeof(upload_path), "/tmp/cos_ut_retry_upload_%ld.dat", (long)getpid());
    snprintf(download_path, sizeof(download_path), "/tmp/cos_ut_retry_download_%ld.dat", (long)getpid());
    snprintf(full_download_path, sizeof(full_download_path), "/tmp/cos_ut_retry_full_download_%ld.dat", (long)getpid());
    write_temp_file(tc, upload_path, upload_data, 16);
    write_temp_file(tc, download_path, download_data, 16);
    write_temp_file(tc, full_download_path, download_data, 16);

    cos_http_request_t *req = cos_http_request_create(p);
    cos_http_response_t *resp = cos_http_response_create(p);
    cos_http_controller_t *ctl = cos_http_controller_create(p, 0);

    req->file_path = apr_pstrdup(p, upload_path);
    req->file_buf = cos_create_file_buf(p);
    int res = cos_open_file_for_range_read(p, upload_path, 0, 16, req->file_buf);
    CuAssertIntEquals(tc, COSE_OK, res);

    resp->file_path = apr_pstrdup(p, download_path);
    resp->file_buf = cos_create_file_buf(p);
    resp->write_body = cos_write_http_body_file_part;
    res = cos_open_file_for_range_write(p, download_path, 0, 16, resp->file_buf);
    CuAssertIntEquals(tc, COSE_OK, res);

    cos_buf_t *buf = cos_create_buf(p, 4);
    memcpy(buf->pos, "DATA", 4);
    buf->last += 4;
    cos_list_add_tail(&buf->node, &req->body);

    /* 模拟 append object 等接口在 cos_init_object_request 中设置的非零 init_crc：
     * 进 retry loop 前 req->crc64 是 init_crc，body 还没流过、累加未发生。
     * cos_retry_file_state_init 必须把这个值 snapshot 下来，
     * 之后 cos_retry_reset_state 必须恢复到这个值（而不是硬清成 0）。
     */
    req->crc64 = 0xDEADBEEFULL;

    cos_retry_file_state_t state;
    cos_retry_file_state_init(&state, req, resp);
    CuAssertIntEquals(tc, COS_TRUE, state.has_req_file);
    CuAssertTrue(tc, state.req_file_pos == 0);
    CuAssertTrue(tc, state.req_file_last == 16);
    CuAssertIntEquals(tc, COS_TRUE, state.has_resp_file);
    CuAssertTrue(tc, state.resp_file_pos == 0);
    CuAssertTrue(tc, state.resp_file_last == 16);
    CuAssertTrue(tc, state.req_init_crc == 0xDEADBEEFULL);

    apr_off_t off = 10;
    apr_file_seek(req->file_buf->file, APR_SET, &off);
    req->file_buf->file_pos = 10;
    off = 8;
    apr_file_seek(resp->file_buf->file, APR_SET, &off);
    resp->file_buf->file_pos = 8;
    buf->pos += 2;

    /* 模拟第一次请求 body 已经流过一部分、CRC 被累加污染的脏状态 */
    req->crc64 = 0x1234567812345678ULL;
    req->consumed_bytes = 10;
    resp->status = 503;
    resp->body_len = 100;
    resp->content_length = 100;
    resp->crc64 = 0xCAFEBABEULL;

    res = cos_retry_reset_state(p, ctl, req, resp, &state);
    CuAssertIntEquals(tc, COSE_OK, res);
    CuAssertTrue(tc, req->file_buf->file_pos == 0);
    CuAssertTrue(tc, req->file_buf->file_last == 16);
    assert_file_cur_offset(tc, req->file_buf->file, 0);
    CuAssertTrue(tc, resp->file_buf->file_pos == 0);
    CuAssertTrue(tc, resp->file_buf->file_last == 16);
    assert_file_cur_offset(tc, resp->file_buf->file, 0);
    CuAssertPtrEquals(tc, buf->start, buf->pos);
    /* 关键：req->crc64 必须回到 init_crc baseline，而不是 0；
     * 否则 append object 等 init_crc != 0 的接口在 retry 后会出现
     * 本端 CRC 与服务端 CRC 不一致（COSE_CRC_INCONSISTENT_ERROR）。
     */
    CuAssertTrue(tc, req->crc64 == 0xDEADBEEFULL);
    CuAssertTrue(tc, req->consumed_bytes == 0);
    CuAssertIntEquals(tc, -1, resp->status);
    CuAssertTrue(tc, resp->body_len == 0);
    CuAssertTrue(tc, resp->content_length == 0);
    CuAssertTrue(tc, resp->crc64 == 0);

    /* 普通下载文件重试时，应截断并回到初始写入位置，避免 partial 内容残留 */
    cos_http_request_t *req_full = cos_http_request_create(p);
    cos_http_response_t *resp_full = cos_http_response_create(p);
    resp_full->file_path = apr_pstrdup(p, full_download_path);
    resp_full->file_buf = cos_create_file_buf(p);
    resp_full->write_body = cos_write_http_body_file;
    res = cos_open_file_for_write(p, full_download_path, resp_full->file_buf);
    CuAssertIntEquals(tc, COSE_OK, res);
    cos_retry_file_state_t full_state;
    cos_retry_file_state_init(&full_state, req_full, resp_full);
    CuAssertIntEquals(tc, COS_TRUE, full_state.has_resp_file);
    CuAssertIntEquals(tc, 7, cos_write_http_body_file(resp_full, "PARTIAL", 7));
    res = cos_retry_reset_state(p, ctl, req_full, resp_full, &full_state);
    CuAssertIntEquals(tc, COSE_OK, res);
    CuAssertTrue(tc, resp_full->file_buf->file_pos == 0);
    CuAssertTrue(tc, resp_full->file_buf->file_last == 0);
    assert_file_cur_offset(tc, resp_full->file_buf->file, 0);
    apr_finfo_t finfo;
    CuAssertIntEquals(tc, APR_SUCCESS, apr_file_info_get(&finfo, APR_FINFO_SIZE, resp_full->file_buf->file));
    CuAssertTrue(tc, finfo.size == 0);

    /* file_buf 存在但 file == NULL 时，应按 state 重新打开文件 */
    req->file_buf = cos_create_file_buf(p);
    resp->file_buf = cos_create_file_buf(p);
    resp->write_body = cos_write_http_body_file_part;
    req->crc64 = 0x9999999999999999ULL;  /* 再次被污染 */
    res = cos_retry_reset_state(p, ctl, req, resp, &state);
    CuAssertIntEquals(tc, COSE_OK, res);
    CuAssertPtrNotNull(tc, req->file_buf->file);
    CuAssertTrue(tc, req->file_buf->file_pos == 0);
    CuAssertTrue(tc, req->file_buf->file_last == 16);
    CuAssertPtrNotNull(tc, resp->file_buf->file);
    CuAssertTrue(tc, resp->file_buf->file_pos == 0);
    CuAssertTrue(tc, resp->file_buf->file_last == 16);
    /* 文件重新打开路径下，init_crc 同样应当被恢复 */
    CuAssertTrue(tc, req->crc64 == 0xDEADBEEFULL);

    cos_http_request_t *req2 = cos_http_request_create(p);
    cos_http_response_t *resp2 = cos_http_response_create(p);
    cos_retry_file_state_t state2;
    cos_retry_file_state_init(&state2, req2, resp2);
    CuAssertIntEquals(tc, COS_FALSE, state2.has_req_file);
    CuAssertIntEquals(tc, COS_FALSE, state2.has_resp_file);
    /* 空 req/resp 场景下，未设置过 crc64，baseline 应当为 0；
     * 这覆盖了 PUT/multipart 等 init_crc==0 的常规接口在 retry 后仍然得到 0。
     */
    CuAssertTrue(tc, state2.req_init_crc == 0);
    req2->crc64 = 0xAAAABBBBCCCCDDDDULL;  /* 模拟第一次请求 body 流过后的累计值 */
    res = cos_retry_reset_state(p, ctl, req2, resp2, &state2);
    CuAssertIntEquals(tc, COSE_OK, res);
    CuAssertTrue(tc, req2->crc64 == 0);

    remove(upload_path);
    remove(download_path);
    remove(full_download_path);
    cos_pool_destroy(p);
    printf("test_cos_retry_file_state_save_and_reset ok\n");
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
    SUITE_ADD_TEST(suite, test_do_switch_domain);
    SUITE_ADD_TEST(suite, test_cos_resign_request);
    SUITE_ADD_TEST(suite, test_cos_http_request_options_copy_isolated);
    SUITE_ADD_TEST(suite, test_cos_http_controller_create_options_isolated);
    SUITE_ADD_TEST(suite, test_cos_config_copy_isolated);
    SUITE_ADD_TEST(suite, test_cos_retry_file_state_save_and_reset);

    return suite;
}
