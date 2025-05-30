#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "cos_api.h"
#include "cos_http_io.h"
#include "cos_log.h"

/**
 * 本样例演示了如何使用 COS C SDK 进行对象下载
 * 包括：复合下载、简单下载
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

void get_object_to_file_demo() {
    char object_name[] = "test.txt";  // 对象名称
    char file_path[] = "test.txt";    // 本地文件路径

    cos_pool_t *p = NULL;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_table_t *resp_headers;
    cos_string_t file;
    cos_table_t *headers = NULL;
    cos_table_t *params = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, bucket_name);
    cos_str_set(&file, file_path);
    cos_str_set(&object, object_name);

    //限速值设置范围为819200 - 838860800，即100KB/s - 100MB/s，如果超出该范围将返回400错误
    // headers = cos_table_make(p, 1);
    // cos_table_add_int(headers, "x-cos-traffic-limit", 819200);
    s = cos_get_object_to_file(options, &bucket, &object, headers, params, &file, &resp_headers);
    log_status(s);

    {
        int i = 0;
        apr_array_header_t * pp = (apr_array_header_t *) apr_table_elts(resp_headers);
        for ( ; i < pp->nelts; i++)
        {
            apr_table_entry_t *ele = (apr_table_entry_t *)pp->elts+i;
            printf("%s: %s\n",ele->key, ele->val);
        }
    }

    cos_pool_destroy(p);
}

void resumable_get_object_demo() {
    char object_name[] = "big_file.txt";  // 对象名称
    char file_path[] = "big_file.txt";    // 本地文件路径
    int enable_checkpoint = COS_FALSE; // 是否开启断点续传

    cos_pool_t *p = NULL;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t filepath;
    cos_resumable_clt_params_t *clt_params;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, bucket_name);
    cos_str_set(&object, object_name);
    cos_str_set(&filepath, file_path);

    clt_params = cos_create_resumable_clt_params_content(p, 5*1024*1024, 3, enable_checkpoint, NULL);
    s = cos_resumable_download_file(options, &bucket, &object, &filepath, NULL, NULL, clt_params, NULL);
    log_status(s);
    if (cos_status_is_ok(s)) {
        printf("upload succeeded\n");
    } else {
        printf("upload failed\n");
    }

    cos_pool_destroy(p);
}

int main() {
    if (cos_http_io_initialize(NULL, 0) != COSE_OK) {
        exit(1);
    }
    // set log level, default COS_LOG_WARN
    cos_log_set_level(COS_LOG_WARN);
    get_object_to_file_demo();
    resumable_get_object_demo();
    // cos_http_io_deinitialize last
    cos_http_io_deinitialize();
    return 0;
}
