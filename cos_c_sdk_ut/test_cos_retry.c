#include "CuTest.h"
#include "cos_log.h"
#include "cos_sys_define.h"
#include "cos_sys_util.h"
#include "cos_string.h"
#include "cos_status.h"
#include "cos_auth.h"
#include "cos_utility.h"
#include "cos_xml.h"
#include "cos_api.h"
#include "cos_config.h"
#include "cos_test_util.h"

static char *ERR_TEST_ENDPOINT_NORMAL;  //*.myqcloud.com
static char *ERR_TEST_ENDPOINT_OTHER; //*.tencentcos.cn
static char *ERR_TEST_ACCESS_KEY_ID;
static char *ERR_TEST_ACCESS_KEY_SECRET;
static char *ERR_TEST_APPID;
static char *ERR_TEST_BUCKET;


void init_retry_test_config(cos_config_t *config, int is_cname, int normal_domain) {
    if (normal_domain) {
        cos_str_set(&config->endpoint, ERR_TEST_ENDPOINT_NORMAL);
    } else {
        cos_str_set(&config->endpoint, ERR_TEST_ENDPOINT_OTHER);
    }
    // cos_str_set(&config->access_key_id, ERR_TEST_ACCESS_KEY_ID);
    // cos_str_set(&config->access_key_secret, ERR_TEST_ACCESS_KEY_SECRET);
    cos_str_set(&config->appid, ERR_TEST_APPID);
    config->is_cname = is_cname;
    config->retry_interval_us = 0;
    config->omit_cos_sdk_retry_header = COS_TRUE;
}

void init_retry_test_request_options(cos_request_options_t *options, int is_cname, int normal_domain) {
    options->config = cos_config_create(options->pool);
    init_retry_test_config(options->config, is_cname, normal_domain);
    options->ctl = cos_http_controller_create(options->pool, 0);
    options->ctl->options->connect_timeout = 2;
    options->ctl->options->speed_time = 2;
    options->ctl->options->enable_crc = 0;
}

// switch_flag 0 不开启转换域名开关，1 开启转换域名开关
void do_get_retry_test(CuTest *tc, char *object_name, int code, int retry_times, int switch_flag, int normal_domain) {
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    cos_string_t object;
    int is_cname = 0;
    cos_request_options_t *options = NULL;
    cos_table_t *headers = NULL;
    cos_table_t *params = NULL;
    cos_table_t *resp_headers = NULL;
    cos_status_t *s = NULL;
    cos_list_t buffer;
    char msg[256];

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_retry_test_request_options(options, is_cname, normal_domain);

    options->config->retry_change_domain = switch_flag;

    cos_str_set(&bucket, ERR_TEST_BUCKET);
    cos_str_set(&object, object_name);
    cos_list_init(&buffer);

    s = cos_get_object_to_buffer(options, &bucket, &object, headers,
                                 params, &buffer, &resp_headers);
    
    snprintf(msg, sizeof(msg), "GET object=%s, switch=%d, normal_domain=%d, expected code == %d but was %d",
             object_name, switch_flag, normal_domain, code, s->code);
    CuAssert(tc, msg, s->code == code);

    snprintf(msg, sizeof(msg), "GET object=%s, switch=%d, normal_domain=%d, expected retry_count == %d but was %d",
             object_name, switch_flag, normal_domain, retry_times, options->ctl->retry_count);
    CuAssert(tc, msg, options->ctl->retry_count == retry_times);

    cos_pool_destroy(p);
}

void do_get_retry_test_no_switch_normal_domain(CuTest *tc, char *object_name, int code, int retry_times) {
    do_get_retry_test(tc, object_name, code, retry_times, 0, 1);
}

void do_get_retry_test_switch_normal_domain(CuTest *tc, char *object_name, int code, int retry_times) {
    do_get_retry_test(tc, object_name, code, retry_times, 1, 1);
}

void do_get_retry_test_no_switch_other_domain(CuTest *tc, char *object_name, int code, int retry_times) {
    do_get_retry_test(tc, object_name, code, retry_times, 0, 0);
}

void do_get_retry_test_switch_other_domain(CuTest *tc, char *object_name, int code, int retry_times) {
    do_get_retry_test(tc, object_name, code, retry_times, 1, 0);
}

// 不开启转换域名开关，myqcloud.com域名
void test_get_retry_no_switch_normal_domain(CuTest *tc) {
    //2xx 成功，不重试
    do_get_retry_test_no_switch_normal_domain(tc, "200", 200, 0);
    do_get_retry_test_no_switch_normal_domain(tc, "200r", 200, 0);
    do_get_retry_test_no_switch_normal_domain(tc, "204", 204, 0);
    do_get_retry_test_no_switch_normal_domain(tc, "204r", 204, 0);
    do_get_retry_test_no_switch_normal_domain(tc, "206", 206, 0);
    do_get_retry_test_no_switch_normal_domain(tc, "206r", 206, 0);
    do_get_retry_test_no_switch_normal_domain(tc, "207", 207, 0);
    do_get_retry_test_no_switch_normal_domain(tc, "207r", 207, 0);

    //3xx 301/302/307且符合域名转换条件，重试，其余不重试
    do_get_retry_test_no_switch_normal_domain(tc, "301", 301, 0);
    do_get_retry_test_no_switch_normal_domain(tc, "301r", 301, 0);
    do_get_retry_test_no_switch_normal_domain(tc, "302", 302, 0);
    do_get_retry_test_no_switch_normal_domain(tc, "302r", 302, 0);
    do_get_retry_test_no_switch_normal_domain(tc, "307", 307, 0);
    do_get_retry_test_no_switch_normal_domain(tc, "307r", 307, 0);

    // //4xx 不重试
    do_get_retry_test_no_switch_normal_domain(tc, "400", 400, 0);
    do_get_retry_test_no_switch_normal_domain(tc, "400r", 400, 0);
    do_get_retry_test_no_switch_normal_domain(tc, "403", 403, 0);
    do_get_retry_test_no_switch_normal_domain(tc, "403r", 403, 0);
    do_get_retry_test_no_switch_normal_domain(tc, "404", 404, 0);
    do_get_retry_test_no_switch_normal_domain(tc, "404r", 404, 0);

    //5xx 重试
    do_get_retry_test_no_switch_normal_domain(tc, "500", 500, 3);
    do_get_retry_test_no_switch_normal_domain(tc, "500r", 500, 3);
    do_get_retry_test_no_switch_normal_domain(tc, "503", 503, 3);
    do_get_retry_test_no_switch_normal_domain(tc, "503r", 503, 3);
    do_get_retry_test_no_switch_normal_domain(tc, "504", 504, 3);
    do_get_retry_test_no_switch_normal_domain(tc, "504r", 504, 3);

    // timeout和shutdown
    do_get_retry_test_no_switch_normal_domain(tc, "timeout", COSE_CONNECTION_FAILED, 3);
    do_get_retry_test_no_switch_normal_domain(tc, "shutdown", COSE_INTERNAL_ERROR, 3);
}

// 不开启转换域名开关，tencentcos.cn域名
void test_get_retry_no_switch_other_domain(CuTest *tc) {
    //2xx 成功，不重试
    do_get_retry_test_no_switch_other_domain(tc, "200", 200, 0);
    do_get_retry_test_no_switch_other_domain(tc, "200r", 200, 0);
    do_get_retry_test_no_switch_other_domain(tc, "204", 204, 0);
    do_get_retry_test_no_switch_other_domain(tc, "204r", 204, 0);
    do_get_retry_test_no_switch_other_domain(tc, "206", 206, 0);
    do_get_retry_test_no_switch_other_domain(tc, "206r", 206, 0);
    do_get_retry_test_no_switch_other_domain(tc, "207", 207, 0);
    do_get_retry_test_no_switch_other_domain(tc, "207r", 207, 0);

    //3xx 301/302/307且符合域名转换条件，重试，其余不重试
    do_get_retry_test_no_switch_other_domain(tc, "301", 301, 0);
    do_get_retry_test_no_switch_other_domain(tc, "301r", 301, 0);
    do_get_retry_test_no_switch_other_domain(tc, "302", 302, 0);
    do_get_retry_test_no_switch_other_domain(tc, "302r", 302, 0);
    do_get_retry_test_no_switch_other_domain(tc, "307", 307, 0);
    do_get_retry_test_no_switch_other_domain(tc, "307r", 307, 0);

    // //4xx 不重试
    do_get_retry_test_no_switch_other_domain(tc, "400", 400, 0);
    do_get_retry_test_no_switch_other_domain(tc, "400r", 400, 0);
    do_get_retry_test_no_switch_other_domain(tc, "403", 403, 0);
    do_get_retry_test_no_switch_other_domain(tc, "403r", 403, 0);
    do_get_retry_test_no_switch_other_domain(tc, "404", 404, 0);
    do_get_retry_test_no_switch_other_domain(tc, "404r", 404, 0);

    //5xx 重试
    do_get_retry_test_no_switch_other_domain(tc, "500", 500, 3);
    do_get_retry_test_no_switch_other_domain(tc, "500r", 500, 3);
    do_get_retry_test_no_switch_other_domain(tc, "503", 503, 3);
    do_get_retry_test_no_switch_other_domain(tc, "503r", 503, 3);
    do_get_retry_test_no_switch_other_domain(tc, "504", 504, 3);
    do_get_retry_test_no_switch_other_domain(tc, "504r", 504, 3);

    // timeout和shutdown
    do_get_retry_test_no_switch_other_domain(tc, "timeout", COSE_CONNECTION_FAILED, 3);
    do_get_retry_test_no_switch_other_domain(tc, "shutdown", COSE_INTERNAL_ERROR, 3);
}

// 开启转换域名开关, myqcloud.com域名
void test_get_retry_switch_normal_domain(CuTest *tc) {
    //2xx 成功，不重试
    do_get_retry_test_switch_normal_domain(tc, "200", 200, 0);
    do_get_retry_test_switch_normal_domain(tc, "200r", 200, 0);
    do_get_retry_test_switch_normal_domain(tc, "204", 204, 0);
    do_get_retry_test_switch_normal_domain(tc, "204r", 204, 0);
    do_get_retry_test_switch_normal_domain(tc, "206", 206, 0);
    do_get_retry_test_switch_normal_domain(tc, "206r", 206, 0);
    do_get_retry_test_switch_normal_domain(tc, "207", 207, 0);
    do_get_retry_test_switch_normal_domain(tc, "207r", 207, 0);

    //3xx 301/302/307且符合域名转换条件，重试，其余不重试
    do_get_retry_test_switch_normal_domain(tc, "301", 301, 1);
    do_get_retry_test_switch_normal_domain(tc, "301r", 301, 0);
    do_get_retry_test_switch_normal_domain(tc, "302", 302, 1);
    do_get_retry_test_switch_normal_domain(tc, "302r", 302, 0);
    do_get_retry_test_switch_normal_domain(tc, "307", 307, 1);
    do_get_retry_test_switch_normal_domain(tc, "307r", 307, 0);

    //4xx 不重试
    do_get_retry_test_switch_normal_domain(tc, "400", 400, 0);
    do_get_retry_test_switch_normal_domain(tc, "400r", 400, 0);
    do_get_retry_test_switch_normal_domain(tc, "403", 403, 0);
    do_get_retry_test_switch_normal_domain(tc, "403r", 403, 0);
    do_get_retry_test_switch_normal_domain(tc, "404", 404, 0);
    do_get_retry_test_switch_normal_domain(tc, "404r", 404, 0);

    //5xx 重试
    do_get_retry_test_switch_normal_domain(tc, "500", 500, 3);
    do_get_retry_test_switch_normal_domain(tc, "500r", 500, 3);
    do_get_retry_test_switch_normal_domain(tc, "503", 503, 3);
    do_get_retry_test_switch_normal_domain(tc, "503r", 503, 3);
    do_get_retry_test_switch_normal_domain(tc, "504", 504, 3);
    do_get_retry_test_switch_normal_domain(tc, "504r", 504, 3);

    // timeout和shutdown
    do_get_retry_test_switch_normal_domain(tc, "timeout", COSE_CONNECTION_FAILED, 3);
    do_get_retry_test_switch_normal_domain(tc, "shutdown", COSE_INTERNAL_ERROR, 3);
}

// 开启转换域名开关, tencentcos.cn域名
void test_get_retry_switch_other_domain(CuTest *tc) {
    //2xx 成功，不重试
    do_get_retry_test_switch_other_domain(tc, "200", 200, 0);
    do_get_retry_test_switch_other_domain(tc, "200r", 200, 0);
    do_get_retry_test_switch_other_domain(tc, "204", 204, 0);
    do_get_retry_test_switch_other_domain(tc, "204r", 204, 0);
    do_get_retry_test_switch_other_domain(tc, "206", 206, 0);
    do_get_retry_test_switch_other_domain(tc, "206r", 206, 0);
    do_get_retry_test_switch_other_domain(tc, "207", 207, 0);
    do_get_retry_test_switch_other_domain(tc, "207r", 207, 0);

    //3xx 301/302/307且符合域名转换条件，重试，其余不重试
    do_get_retry_test_switch_other_domain(tc, "301", 301, 0);
    do_get_retry_test_switch_other_domain(tc, "301r", 301, 0);
    do_get_retry_test_switch_other_domain(tc, "302", 302, 0);
    do_get_retry_test_switch_other_domain(tc, "302r", 302, 0);
    do_get_retry_test_switch_other_domain(tc, "307", 307, 0);
    do_get_retry_test_switch_other_domain(tc, "307r", 307, 0);

    // //4xx 不重试
    do_get_retry_test_switch_other_domain(tc, "400", 400, 0);
    do_get_retry_test_switch_other_domain(tc, "400r", 400, 0);
    do_get_retry_test_switch_other_domain(tc, "403", 403, 0);
    do_get_retry_test_switch_other_domain(tc, "403r", 403, 0);
    do_get_retry_test_switch_other_domain(tc, "404", 404, 0);
    do_get_retry_test_switch_other_domain(tc, "404r", 404, 0);

    //5xx 重试
    do_get_retry_test_switch_other_domain(tc, "500", 500, 3);
    do_get_retry_test_switch_other_domain(tc, "500r", 500, 3);
    do_get_retry_test_switch_other_domain(tc, "503", 503, 3);
    do_get_retry_test_switch_other_domain(tc, "503r", 503, 3);
    do_get_retry_test_switch_other_domain(tc, "504", 504, 3);
    do_get_retry_test_switch_other_domain(tc, "504r", 504, 3);

    // timeout和shutdown
    do_get_retry_test_switch_other_domain(tc, "timeout", COSE_CONNECTION_FAILED, 3);
    do_get_retry_test_switch_other_domain(tc, "shutdown", COSE_INTERNAL_ERROR, 3);
}

void do_copy_retry_test(CuTest *tc, char *object_name, int code, int retry_times, int switch_flag, int normal_domain) {

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
    char msg[256];

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_retry_test_request_options(options, is_cname, normal_domain);
    options->config->retry_change_domain = switch_flag;
    cos_str_set(&bucket, ERR_TEST_BUCKET);
    cos_str_set(&object, object_name);
    cos_str_set(&src_bucket, ERR_TEST_BUCKET);
    cos_str_set(&src_object, object_name);
    cos_str_set(&src_endpoint, options->config->endpoint.data);

    cos_copy_object_params_t *params = NULL;
    params = cos_create_copy_object_params(p);
    s = cos_copy_object(options, &src_bucket, &src_object, &src_endpoint, &bucket, &object, NULL, params, &resp_headers);
    
    snprintf(msg, sizeof(msg), "COPY object=%s, switch=%d, normal_domain=%d, expected code == %d but was %d",
             object_name, switch_flag, normal_domain, code, s->code);
    CuAssert(tc, msg, s->code == code);

    snprintf(msg, sizeof(msg), "COPY object=%s, switch=%d, normal_domain=%d, expected retry_count == %d but was %d",
             object_name, switch_flag, normal_domain, retry_times, options->ctl->retry_count);
    CuAssert(tc, msg, options->ctl->retry_count == retry_times);

    cos_pool_destroy(p);
}

void do_copy_retry_test_no_switch_normal_domain(CuTest *tc, char *object_name, int code, int retry_times) {
    do_copy_retry_test(tc, object_name, code, retry_times, 0, 1);
}

void do_copy_retry_test_no_switch_other_domain(CuTest *tc, char *object_name, int code, int retry_times) {
    do_copy_retry_test(tc, object_name, code, retry_times, 0, 0);
}

void do_copy_retry_test_switch_normal_domain(CuTest *tc, char *object_name, int code, int retry_times) {
    do_copy_retry_test(tc, object_name, code, retry_times, 1, 1);
}

void do_copy_retry_test_switch_other_domain(CuTest *tc, char *object_name, int code, int retry_times) {
    do_copy_retry_test(tc, object_name, code, retry_times, 1, 0);
}

// 不切换域名，myqcloud.com域名
void test_copy_retry_no_switch_normal_domain(CuTest *tc) {
    
    //2xx copy mock server返回空body，不能正常解析
    do_copy_retry_test_no_switch_normal_domain(tc, "200", COSE_XML_PARSE_ERROR, 0);
    do_copy_retry_test_no_switch_normal_domain(tc, "200r", COSE_XML_PARSE_ERROR, 0);
    do_copy_retry_test_no_switch_normal_domain(tc, "204", COSE_XML_PARSE_ERROR, 0);
    do_copy_retry_test_no_switch_normal_domain(tc, "204r", COSE_XML_PARSE_ERROR, 0);
    do_copy_retry_test_no_switch_normal_domain(tc, "206", COSE_XML_PARSE_ERROR, 0);
    do_copy_retry_test_no_switch_normal_domain(tc, "206r", COSE_XML_PARSE_ERROR, 0);
    do_copy_retry_test_no_switch_normal_domain(tc, "207", COSE_SERVICE_ERROR, 3);
    do_copy_retry_test_no_switch_normal_domain(tc, "207r", COSE_SERVICE_ERROR, 3);

    //3xx 301/302/307且符合域名转换条件，重试，其余不重试
    do_copy_retry_test_no_switch_normal_domain(tc, "301", 301, 0);
    do_copy_retry_test_no_switch_normal_domain(tc, "301r", 301, 0);
    do_copy_retry_test_no_switch_normal_domain(tc, "302", 302, 0);
    do_copy_retry_test_no_switch_normal_domain(tc, "302r", 302, 0);
    do_copy_retry_test_no_switch_normal_domain(tc, "307", 307, 0);
    do_copy_retry_test_no_switch_normal_domain(tc, "307r", 307, 0);

    //4xx 不重试
    do_copy_retry_test_no_switch_normal_domain(tc, "400", 400, 0);
    do_copy_retry_test_no_switch_normal_domain(tc, "400r", 400, 0);
    do_copy_retry_test_no_switch_normal_domain(tc, "403", 403, 0);
    do_copy_retry_test_no_switch_normal_domain(tc, "403r", 403, 0);
    do_copy_retry_test_no_switch_normal_domain(tc, "404", 404, 0);
    do_copy_retry_test_no_switch_normal_domain(tc, "404r", 404, 0);

    //5xx 重试
    do_copy_retry_test_no_switch_normal_domain(tc, "500", 500, 3);
    do_copy_retry_test_no_switch_normal_domain(tc, "500r", 500, 3);
    do_copy_retry_test_no_switch_normal_domain(tc, "503", 503, 3);
    do_copy_retry_test_no_switch_normal_domain(tc, "503r", 503, 3);
    do_copy_retry_test_no_switch_normal_domain(tc, "504", 504, 3);
    do_copy_retry_test_no_switch_normal_domain(tc, "504r", 504, 3);

    // timeout和shutdown
    // 对于测试环境（mock server）,当前c sdk timeout时，不会触发io error，所以无法重试，正常会触发io error并重试
    do_copy_retry_test_no_switch_normal_domain(tc, "timeout", COSE_CONNECTION_FAILED, 3);
    do_copy_retry_test_no_switch_normal_domain(tc, "shutdown", COSE_INTERNAL_ERROR, 3);

}

// 不切换域名，tencentcos.cn域名
void test_copy_retry_no_switch_other_domain(CuTest *tc) {
    
    //2xx copy mock server返回空body，不能正常解析
    do_copy_retry_test_no_switch_other_domain(tc, "200", COSE_XML_PARSE_ERROR, 0);
    do_copy_retry_test_no_switch_other_domain(tc, "200r", COSE_XML_PARSE_ERROR, 0);
    do_copy_retry_test_no_switch_other_domain(tc, "204", COSE_XML_PARSE_ERROR, 0);
    do_copy_retry_test_no_switch_other_domain(tc, "204r", COSE_XML_PARSE_ERROR, 0);
    do_copy_retry_test_no_switch_other_domain(tc, "206", COSE_XML_PARSE_ERROR, 0);
    do_copy_retry_test_no_switch_other_domain(tc, "206r", COSE_XML_PARSE_ERROR, 0);
    do_copy_retry_test_no_switch_other_domain(tc, "207", COSE_SERVICE_ERROR, 3);
    do_copy_retry_test_no_switch_other_domain(tc, "207r", COSE_SERVICE_ERROR, 3);

    //3xx 301/302/307且符合域名转换条件，重试，其余不重试
    do_copy_retry_test_no_switch_other_domain(tc, "301", 301, 0);
    do_copy_retry_test_no_switch_other_domain(tc, "301r", 301, 0);
    do_copy_retry_test_no_switch_other_domain(tc, "302", 302, 0);
    do_copy_retry_test_no_switch_other_domain(tc, "302r", 302, 0);
    do_copy_retry_test_no_switch_other_domain(tc, "307", 307, 0);
    do_copy_retry_test_no_switch_other_domain(tc, "307r", 307, 0);

    //4xx 不重试
    do_copy_retry_test_no_switch_other_domain(tc, "400", 400, 0);
    do_copy_retry_test_no_switch_other_domain(tc, "400r", 400, 0);
    do_copy_retry_test_no_switch_other_domain(tc, "403", 403, 0);
    do_copy_retry_test_no_switch_other_domain(tc, "403r", 403, 0);
    do_copy_retry_test_no_switch_other_domain(tc, "404", 404, 0);
    do_copy_retry_test_no_switch_other_domain(tc, "404r", 404, 0);

    //5xx 重试
    do_copy_retry_test_no_switch_other_domain(tc, "500", 500, 3);
    do_copy_retry_test_no_switch_other_domain(tc, "500r", 500, 3);
    do_copy_retry_test_no_switch_other_domain(tc, "503", 503, 3);
    do_copy_retry_test_no_switch_other_domain(tc, "503r", 503, 3);
    do_copy_retry_test_no_switch_other_domain(tc, "504",504, 3);
    do_copy_retry_test_no_switch_other_domain(tc, "504r", 504, 3);

    // timeout和shutdown
    // 对于测试环境（mock server）,当前c sdk timeout时，不会触发io error，所以无法重试，正常会触发io error并重试
    do_copy_retry_test_no_switch_other_domain(tc, "timeout", COSE_CONNECTION_FAILED, 3);
    do_copy_retry_test_no_switch_other_domain(tc, "shutdown", COSE_INTERNAL_ERROR, 3);

}

// 切换域名，myqcloud.com域名
void test_copy_retry_switch_normal_domain(CuTest *tc) {
    
    //2xx copy mock server大部分返回空body，不能正常解析
    do_copy_retry_test_switch_normal_domain(tc, "200", COSE_XML_PARSE_ERROR, 0);
    do_copy_retry_test_switch_normal_domain(tc, "200r", COSE_XML_PARSE_ERROR, 0);
    do_copy_retry_test_switch_normal_domain(tc, "204", COSE_XML_PARSE_ERROR, 0);
    do_copy_retry_test_switch_normal_domain(tc, "204r", COSE_XML_PARSE_ERROR, 0);
    do_copy_retry_test_switch_normal_domain(tc, "206", COSE_XML_PARSE_ERROR, 0);
    do_copy_retry_test_switch_normal_domain(tc, "206r", COSE_XML_PARSE_ERROR, 0);
    do_copy_retry_test_switch_normal_domain(tc, "207", COSE_SERVICE_ERROR, 3);
    do_copy_retry_test_switch_normal_domain(tc, "207r", COSE_SERVICE_ERROR, 3);

    //3xx 301/302/307且符合域名转换条件，重试，其余不重试
    do_copy_retry_test_switch_normal_domain(tc, "301", 301, 1);
    do_copy_retry_test_switch_normal_domain(tc, "301r", 301, 0);
    do_copy_retry_test_switch_normal_domain(tc, "302", 302, 1);
    do_copy_retry_test_switch_normal_domain(tc, "302r", 302, 0);

    // 4xx 不重试
    do_copy_retry_test_switch_normal_domain(tc, "400", 400, 0);
    do_copy_retry_test_switch_normal_domain(tc, "400r", 400, 0);
    do_copy_retry_test_switch_normal_domain(tc, "403", 403, 0);
    do_copy_retry_test_switch_normal_domain(tc, "403r", 403, 0);
    do_copy_retry_test_switch_normal_domain(tc, "404", 404, 0);
    do_copy_retry_test_switch_normal_domain(tc, "404r", 404, 0);

    //5xx 重试
    do_copy_retry_test_switch_normal_domain(tc, "500", 500, 3);
    do_copy_retry_test_switch_normal_domain(tc, "500r", 500, 3);
    do_copy_retry_test_switch_normal_domain(tc, "503", 503, 3);
    do_copy_retry_test_switch_normal_domain(tc, "503r", 503, 3);
    do_copy_retry_test_switch_normal_domain(tc, "504", 504, 3);
    do_copy_retry_test_switch_normal_domain(tc, "504r", 504, 3);

    //timeout和shutdown
    // 对于测试环境（mock server）,当前c sdk timeout时，不会触发io error，所以无法重试，正常会触发io error并重试
    do_copy_retry_test_switch_normal_domain(tc, "timeout", COSE_CONNECTION_FAILED, 3);
    do_copy_retry_test_switch_normal_domain(tc, "shutdown", COSE_INTERNAL_ERROR, 3);

}

// 切换域名，tencentcos.cn域名
void test_copy_retry_switch_other_domain(CuTest *tc) {
    
    //2xx copy mock server大部分返回空body，不能正常解析
    do_copy_retry_test_switch_other_domain(tc, "200", COSE_XML_PARSE_ERROR, 0);
    do_copy_retry_test_switch_other_domain(tc, "200r", COSE_XML_PARSE_ERROR, 0);
    do_copy_retry_test_switch_other_domain(tc, "204", COSE_XML_PARSE_ERROR, 0);
    do_copy_retry_test_switch_other_domain(tc, "204r", COSE_XML_PARSE_ERROR, 0);
    do_copy_retry_test_switch_other_domain(tc, "206", COSE_XML_PARSE_ERROR, 0);
    do_copy_retry_test_switch_other_domain(tc, "206r", COSE_XML_PARSE_ERROR, 0);
    do_copy_retry_test_switch_other_domain(tc, "207", COSE_SERVICE_ERROR, 3);
    do_copy_retry_test_switch_other_domain(tc, "207r", COSE_SERVICE_ERROR, 3);

    //3xx 301/302/307且符合域名转换条件，重试，其余不重试
    do_copy_retry_test_switch_other_domain(tc, "301", 301, 0);
    do_copy_retry_test_switch_other_domain(tc, "301r", 301, 0);
    do_copy_retry_test_switch_other_domain(tc, "302", 302, 0);
    do_copy_retry_test_switch_other_domain(tc, "302r", 302, 0);

    //4xx 不重试
    do_copy_retry_test_switch_other_domain(tc, "400", 400, 0);
    do_copy_retry_test_switch_other_domain(tc, "400r", 400, 0);
    do_copy_retry_test_switch_other_domain(tc, "403", 403, 0);
    do_copy_retry_test_switch_other_domain(tc, "403r", 403, 0);
    do_copy_retry_test_switch_other_domain(tc, "404", 404, 0);
    do_copy_retry_test_switch_other_domain(tc, "404r", 404, 0);

    //5xx 重试
    do_copy_retry_test_switch_other_domain(tc, "500", 500, 3);
    do_copy_retry_test_switch_other_domain(tc, "500r", 500, 3);
    do_copy_retry_test_switch_other_domain(tc, "503", 503, 3);
    do_copy_retry_test_switch_other_domain(tc, "503r", 503, 3);
    do_copy_retry_test_switch_other_domain(tc, "504", 504, 3);
    do_copy_retry_test_switch_other_domain(tc, "504r", 504, 3);

    //timeout和shutdown
    // 对于测试环境（mock server）,当前c sdk timeout时，不会触发io error，所以无法重试，正常会触发io error并重试
    do_copy_retry_test_switch_other_domain(tc, "timeout", COSE_CONNECTION_FAILED, 3);
    do_copy_retry_test_switch_other_domain(tc, "shutdown", COSE_INTERNAL_ERROR, 3);

}

CuSuite *test_cos_retry() {
    CuSuite* suite = CuSuiteNew();

    ERR_TEST_ENDPOINT_NORMAL = getenv("COS_ERR_TEST_ENDPOINT_NORMAL");
    ERR_TEST_ENDPOINT_OTHER = getenv("COS_ERR_TEST_ENDPOINT_OTHER");
    ERR_TEST_ACCESS_KEY_ID = getenv("COS_ERR_TEST_ACCESS_KEY_ID");
    ERR_TEST_ACCESS_KEY_SECRET = getenv("COS_ERR_TEST_ACCESS_KEY_SECRET");
    ERR_TEST_APPID = getenv("COS_ERR_TEST_APPID");
    ERR_TEST_BUCKET = getenv("COS_ERR_TEST_BUCKET");

    SUITE_ADD_TEST(suite, test_get_retry_no_switch_normal_domain);
    SUITE_ADD_TEST(suite, test_get_retry_no_switch_other_domain);
    SUITE_ADD_TEST(suite, test_get_retry_switch_normal_domain);
    SUITE_ADD_TEST(suite, test_get_retry_switch_other_domain);
    
    SUITE_ADD_TEST(suite, test_copy_retry_no_switch_normal_domain);
    SUITE_ADD_TEST(suite, test_copy_retry_no_switch_other_domain);
    SUITE_ADD_TEST(suite, test_copy_retry_switch_normal_domain);
    SUITE_ADD_TEST(suite, test_copy_retry_switch_other_domain);

    return suite;
}
