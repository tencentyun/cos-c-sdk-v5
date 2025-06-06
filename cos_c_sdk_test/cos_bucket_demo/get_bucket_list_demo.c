#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "cos_api.h"
#include "cos_http_io.h"
#include "cos_log.h"

/**
 * 本样例演示了如何使用 COS C SDK 获取存储桶列表
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
void get_bucket_list_demo() {
    cos_pool_t *pool = NULL;
    cos_status_t *status = NULL;
    cos_request_options_t *options = NULL;
    cos_get_service_params_t *list_params = NULL;
    cos_table_t *resp_headers = NULL;

    //创建内存池
    cos_pool_create(&pool, NULL);

    //初始化请求选项
    options = cos_request_options_create(pool);
    options->config = cos_config_create(options->pool);

    init_test_request_options(options, is_cname);
    options->ctl = cos_http_controller_create(options->pool, 0);

    //创建get service参数, 默认获取全部bucket
    list_params = cos_create_get_service_params(options->pool);
    //若将all_region设置为0，则只根据options->config->endpoint的区域进行查询
    //list_params->all_region = 0;

    status = cos_get_service(options, list_params, &resp_headers);
    log_status(status);
    if (!cos_status_is_ok(status)) {
        cos_pool_destroy(pool);
        return;
    }

    //查看结果
    cos_get_service_content_t *content = NULL;
    char *line = NULL;
    cos_list_for_each_entry(cos_get_service_content_t, content, &list_params->bucket_list, node) {
        line = apr_psprintf(options->pool, "%.*s\t%.*s\t%.*s\n", content->bucket_name.len, content->bucket_name.data, content->location.len, content->location.data, content->creation_date.len, content->creation_date.data);
        printf("%s", line);
    }

    cos_pool_destroy(pool);
}

int main() {
    if (cos_http_io_initialize(NULL, 0) != COSE_OK) {
        exit(1);
    }
    // set log level, default COS_LOG_WARN
    cos_log_set_level(COS_LOG_ERROR);
    get_bucket_list_demo();
    // cos_http_io_deinitialize last
    cos_http_io_deinitialize();
    return 0;
}