#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "cos_api.h"
#include "cos_http_io.h"
#include "cos_log.h"

/**
 * 本样例演示了如何使用 COS C SDK 获取对象 URL 和预签名链接
 * 包括：预签名链接、对象访问 URL
 */

// COS 的 bucket 名称, [bucket]-[appid], 如: mybucket-1253666666，可在 https://console.cloud.tencent.com/cos5/bucket 查看
char bucket_name[] = "examplebucket-12500000000";
// 开发者访问 COS 服务时拥有的用户维度唯一资源标识，用以标识资源，可在 https://console.cloud.tencent.com/cam/capi 页面获取
char appid[] = "12500000000";
// 开发者拥有的项目身份ID/密钥，可在 https://console.cloud.tencent.com/cam/capi 页面获取
char secret_id[] = "AKIDXXXXXXXX";
char secret_key[] = "1A2Z3YYYYYYYYYY";
//endpoint 是 COS 访问域名信息（不设置存储桶前缀，访问 COS 时会自动在前面拼接上[bucket]-[appid]）， 详情请参见 https://cloud.tencent.com/document/product/436/6224 文档
char endpoint[] = "cos.ap-guangzhou.myqcloud.com";
// 是否使用自定域名。如果设置为 COS_TRUE ，则访问 COS 时需要将 endpoint 的值修改为自定义域名
int is_cname = COS_FALSE;

void init_test_config(cos_config_t* config, int is_cname) {
    cos_str_set(&config->endpoint, endpoint);
    cos_str_set(&config->access_key_id, secret_id);
    cos_str_set(&config->access_key_secret, secret_key);
    cos_str_set(&config->appid, appid);
    // cos_str_set(&config->sts_token, token);  // 使用临时密钥时的 token
    config->is_cname = is_cname;  // 是否使用自定义域名
}

void init_test_request_options(cos_request_options_t* options, int is_cname) {
    options->config = cos_config_create(options->pool);
    init_test_config(options->config, is_cname);
    options->ctl = cos_http_controller_create(options->pool, 0);
}

void log_status(cos_status_t* s) {
    cos_warn_log("status->code: %d", s->code);
    if (s->error_code)
        cos_warn_log("status->error_code: %s", s->error_code);
    if (s->error_msg)
        cos_warn_log("status->error_msg: %s", s->error_msg);
    if (s->req_id)
        cos_warn_log("status->req_id: %s", s->req_id);
}
void get_object_url_demo()
{
    char object_name[] = "test.txt";  // 对象名称
    cos_pool_t *p = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
        
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, bucket_name);
    cos_str_set(&object, object_name);

    printf("url:%s\n", cos_gen_object_url(options, &bucket, &object));

    cos_pool_destroy(p);
}

void get_presigned_url_demo()
{
    char object_name[] = "test.txt";  // 对象名称
    cos_pool_t *p = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t presigned_url;
    cos_table_t *params = NULL;
    cos_table_t *headers = NULL;
    int sign_host = 1;
    
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, bucket_name);
    cos_str_set(&object, object_name);

    cos_gen_presigned_url(options, &bucket, &object, 300, HTTP_GET, &presigned_url);
    printf("presigned_url: %s\n", presigned_url.data);


    // 添加您自己的params和headers
    params = cos_table_make(options->pool, 0);
    //cos_table_add(params, "param1", "value");
    headers = cos_table_make(options->pool, 0);
    //cos_table_add(headers, "header1", "value");

    // 强烈建议sign_host为1，这样强制把host头域加入签名列表，防止越权访问问题
    cos_gen_presigned_url_safe(options, &bucket, &object, 300, HTTP_GET, headers, params, sign_host, &presigned_url);
    printf("presigned_url_safe: %s\n", presigned_url.data);

    cos_pool_destroy(p);
    
}
int main() {
    if (cos_http_io_initialize(NULL, 0) != COSE_OK) {
        exit(1);
    }
    // set log level, default COS_LOG_WARN
    cos_log_set_level(COS_LOG_WARN);
    get_object_url_demo();
    get_presigned_url_demo();
    // cos_http_io_deinitialize last
    cos_http_io_deinitialize();
    return 0;
}
