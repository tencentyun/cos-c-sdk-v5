#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "cos_api.h"
#include "cos_http_io.h"
#include "cos_log.h"

/**
 * 本样例演示了如何使用 COS C SDK 进行对象删除
 * 包括：删除对象、批量删除对象
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

void delete_object_demo()
{
    char object_name[] = "test.txt";  // 对象名称
    cos_pool_t *p = NULL;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t src_object;
    cos_string_t src_endpoint;
    cos_table_t *resp_headers = NULL;

    //创建内存池
    cos_pool_create(&p, NULL);
    
    //初始化请求选项
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, bucket_name);
    
    //设置对象
    cos_str_set(&object, object_name);
    
    s = cos_delete_object(options, &bucket, &object, &resp_headers);
    log_status(s);
    if (cos_status_is_ok(s)) {
        printf("delete object succeeded\n");
    } else {
        printf("delete object failed\n");
    }

    //销毁内存池
    cos_pool_destroy(p);
}
void delete_objects_demo()
{
    char object_name1[] = "test1.txt";  // 对象名称
    char object_name2[] = "test2.txt";  // 对象名称

    cos_pool_t *p = NULL;
    cos_string_t bucket;
    cos_status_t *s = NULL;
    cos_table_t *resp_headers = NULL;
    cos_request_options_t *options = NULL;
    cos_object_key_t *content1 = NULL;
    cos_object_key_t *content2 = NULL;
    cos_list_t object_list;
    cos_list_t deleted_object_list;
    int is_quiet = COS_TRUE;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, bucket_name);

    cos_list_init(&object_list);
    cos_list_init(&deleted_object_list);
    content1 = cos_create_cos_object_key(p);
    cos_str_set(&content1->key, object_name1);
    cos_list_add_tail(&content1->node, &object_list);
    content2 = cos_create_cos_object_key(p);
    cos_str_set(&content2->key, object_name2);
    cos_list_add_tail(&content2->node, &object_list);

    s = cos_delete_objects(options, &bucket, &object_list, is_quiet,
        &resp_headers, &deleted_object_list);
    log_status(s);
    
    cos_pool_destroy(p);

    if (cos_status_is_ok(s)) {
        printf("delete objects succeeded\n");
    } else {
        printf("delete objects failed\n");
    }
}

int main() {
    if (cos_http_io_initialize(NULL, 0) != COSE_OK) {
        exit(1);
    }
    // set log level, default COS_LOG_WARN
    cos_log_set_level(COS_LOG_WARN);
    delete_object_demo();
    delete_objects_demo();
    // cos_http_io_deinitialize last
    cos_http_io_deinitialize();
    return 0;
}
