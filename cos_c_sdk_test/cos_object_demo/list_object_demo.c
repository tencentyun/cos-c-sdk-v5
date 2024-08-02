#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "cos_api.h"
#include "cos_http_io.h"
#include "cos_log.h"

/**
 * 本样例演示了如何使用 COS C SDK 进行对象列出
 * 包括：列出第一页、列出目录下的对象、列出桶中的所有对象
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

void list_objects_first_page_demo() {
    cos_pool_t* p = NULL;
    cos_status_t* s = NULL;
    cos_request_options_t* options = NULL;
    cos_string_t bucket;
    cos_table_t* resp_headers = NULL;

    // 创建内存池
    cos_pool_create(&p, NULL);

    // 初始化请求选项
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, bucket_name);

    // 获取对象列表
    cos_list_object_params_t* list_params = NULL;
    cos_list_object_content_t* content = NULL;
    list_params = cos_create_list_object_params(p);
    s = cos_list_object(options, &bucket, list_params, &resp_headers);
    if (cos_status_is_ok(s)) {
        printf("list object succeeded\n");
        cos_list_for_each_entry(cos_list_object_content_t, content, &list_params->object_list, node) {
            printf("object: %.*s\n", content->key.len, content->key.data);
        }
    } else {
        printf("list object failed\n");
    }
    log_status(s);

    // 销毁内存池
    cos_pool_destroy(p);
}

void list_directory_demo() {
    char* prefix = "test/";  // prefix表示列出的object的key以prefix开始
    char* delimiter = "/";     // delimiter表示分隔符, 设置为/表示列出当前目录下的object, 设置为空表示列出所有的object
    int max_ret = 1000;        // 设置最大遍历出多少个对象, 一次listobject最大支持1000

    cos_pool_t* p = NULL;
    cos_status_t* s = NULL;
    cos_request_options_t* options = NULL;
    cos_string_t bucket;
    cos_table_t* resp_headers;
    int is_truncated = 1;
    cos_string_t marker;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, bucket_name);

    // list object (get bucket)
    cos_list_object_params_t* list_params = NULL;
    list_params = cos_create_list_object_params(p);
    cos_str_set(&list_params->prefix, prefix);
    cos_str_set(&list_params->delimiter, delimiter);
    list_params->max_ret = max_ret;
    cos_str_set(&marker, "");
    while (is_truncated) {
        list_params->marker = marker;
        s = cos_list_object(options, &bucket, list_params, &resp_headers);
        if (!cos_status_is_ok(s)) {
            printf("list object failed, req_id:%s\n", s->req_id);
            break;
        }
        // list_params->object_list 返回列出的object对象。
        cos_list_object_content_t* content = NULL;
        cos_list_for_each_entry(cos_list_object_content_t, content, &list_params->object_list, node) {
            printf("object: %s\n", content->key.data);
        }
        // list_params->common_prefix_list 表示被delimiter截断的路径, 如delimter设置为/, common prefix则表示所有子目录的路径
        cos_list_object_common_prefix_t* common_prefix = NULL;
        cos_list_for_each_entry(cos_list_object_common_prefix_t, common_prefix, &list_params->common_prefix_list, node) {
            printf("common prefix: %s\n", common_prefix->prefix.data);
        }

        is_truncated = list_params->truncated;
        marker = list_params->next_marker;
    }
    cos_pool_destroy(p);
}

void list_all_objects_demo() {
    cos_pool_t* p = NULL;
    cos_status_t* s = NULL;
    cos_request_options_t* options = NULL;
    cos_string_t bucket;
    cos_table_t* resp_headers;
    int is_truncated = 1;
    cos_string_t marker;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, bucket_name);

    // list object (get bucket)
    cos_list_object_params_t* list_params = NULL;
    list_params = cos_create_list_object_params(p);
    // 设置最大遍历出多少个对象, 一次listobject最大支持1000
    list_params->max_ret = 1000;
    cos_str_set(&marker, "");
    while (is_truncated) {
        list_params->marker = marker;
        cos_list_init(&list_params->object_list);
        s = cos_list_object(options, &bucket, list_params, &resp_headers);
        if (!cos_status_is_ok(s)) {
            printf("list object failed, req_id:%s\n", s->req_id);
            break;
        }
        // list_params->object_list 返回列出的object对象。
        cos_list_object_content_t* content = NULL;
        cos_list_for_each_entry(cos_list_object_content_t, content, &list_params->object_list, node) {
            printf("object: %s\n", content->key.data);
        }

        is_truncated = list_params->truncated;
        marker = list_params->next_marker;
    }
    cos_pool_destroy(p);
}

int main() {
    if (cos_http_io_initialize(NULL, 0) != COSE_OK) {
        exit(1);
    }
    // set log level, default COS_LOG_WARN
    cos_log_set_level(COS_LOG_WARN);
    list_objects_first_page_demo();
    list_directory_demo();
    list_all_objects_demo();
    // cos_http_io_deinitialize last
    cos_http_io_deinitialize();
    return 0;
}
