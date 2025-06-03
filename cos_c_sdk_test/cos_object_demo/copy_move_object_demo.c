#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "cos_api.h"
#include "cos_http_io.h"
#include "cos_log.h"

/**
 * 本样例演示了如何使用 COS C SDK 进行对象复制和移动
 * 包括：高级复制、普通复制、分块复制
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

void copy_demo() {
    char object_name[] = "test_dst.txt";      // 目标对象名称
    char* src_bucket_name = bucket_name;     // 复制源 bucket 名称
    char src_object_name[] = "test_src.txt";  // 复制源对象名称
    char* src_endpoint_str = endpoint;       // 复制源endpoint
    int thread_nums = 2; // 复制线程数

    cos_pool_t* p = NULL;
    cos_status_t* s = NULL;
    cos_request_options_t* options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t src_bucket;
    cos_string_t src_object;
    cos_string_t src_endpoint;
    cos_table_t* resp_headers = NULL;

    // 创建内存池
    cos_pool_create(&p, NULL);

    // 初始化请求选项
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, bucket_name);

    // 设置对象复制
    cos_str_set(&object, object_name);
    cos_str_set(&src_bucket, src_bucket_name);
    cos_str_set(&src_endpoint, src_endpoint_str);
    cos_str_set(&src_object, src_object_name);


    s = copy(options, &src_bucket, &src_object, &src_endpoint, &bucket, &object, thread_nums);
    log_status(s);
    if (cos_status_is_ok(s)) {
        printf("put object copy succeeded\n");
    } else {
        printf("put object copy failed\n");
    }

    // 销毁内存池
    cos_pool_destroy(p);
}

void copy_object_demo() {
    char object_name[] = "test_dst.txt";      // 目标对象名称
    char* src_bucket_name = bucket_name;     // 复制源 bucket 名称
    char src_object_name[] = "test_src.txt";  // 复制源对象名称
    char* src_endpoint_str = endpoint;       // 复制源endpoint

    cos_pool_t* p = NULL;
    cos_status_t* s = NULL;
    cos_request_options_t* options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t src_bucket;
    cos_string_t src_object;
    cos_string_t src_endpoint;
    cos_table_t* resp_headers = NULL;

    // 创建内存池
    cos_pool_create(&p, NULL);

    // 初始化请求选项
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, bucket_name);

    // 设置对象复制
    cos_str_set(&object, object_name);
    cos_str_set(&src_bucket, src_bucket_name);
    cos_str_set(&src_endpoint, src_endpoint_str);
    cos_str_set(&src_object, src_object_name);

    cos_copy_object_params_t* params = NULL;
    params = cos_create_copy_object_params(p);
    s = cos_copy_object(options, &src_bucket, &src_object, &src_endpoint, &bucket, &object, NULL, params, &resp_headers);
    log_status(s);
    if (cos_status_is_ok(s)) {
        printf("put object copy succeeded\n");
    } else {
        printf("put object copy failed\n");
    }

    // 销毁内存池
    cos_pool_destroy(p);
}

void part_copy_demo() {
    char object_name[] = "test_dst.txt";      // 目标对象名称
    char *src_object_path = "examplebucket-12500000000.cos.ap-guangzhou.myqcloud.com/big_file.txt";  // 复制源对象

    cos_pool_t *p = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t file;
    int is_cname = 0;
    cos_string_t upload_id;
    cos_list_upload_part_params_t *list_upload_part_params = NULL;
    cos_upload_part_copy_params_t *upload_part_copy_params1 = NULL;
    cos_upload_part_copy_params_t *upload_part_copy_params2 = NULL;
    cos_table_t *headers = NULL;
    cos_table_t *query_params = NULL;
    cos_table_t *resp_headers = NULL;
    cos_table_t *list_part_resp_headers = NULL;
    cos_list_t complete_part_list;
    cos_list_part_content_t *part_content = NULL;
    cos_complete_part_content_t *complete_content = NULL;
    cos_table_t *complete_resp_headers = NULL;
    cos_status_t *s = NULL;
    int part1 = 1;
    int part2 = 2;
    FILE *fd = NULL;
    cos_string_t download_file;
    // 一下 range 请根据实际文件大小进行修改
    int64_t range_start1 = 0;
    int64_t range_end1 = 6000000;
    int64_t range_start2 = 6000001;
    int64_t range_end2 = 12000000;
    cos_string_t data;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);

    init_test_request_options(options, is_cname);

    //init mulitipart
    cos_str_set(&object, object_name);
    cos_str_set(&bucket, bucket_name);
    s = cos_init_multipart_upload(options, &bucket, &object,
                                  &upload_id, NULL, &resp_headers);
    log_status(s);
    if (cos_status_is_ok(s)) {
        printf("multi object copy succeeded\n");
    } else {
        printf("multi object copy failed\n");
    }


    //upload part copy 1
    upload_part_copy_params1 = cos_create_upload_part_copy_params(p);
    cos_str_set(&upload_part_copy_params1->copy_source, src_object_path);
    cos_str_set(&upload_part_copy_params1->dest_bucket, bucket_name);
    cos_str_set(&upload_part_copy_params1->dest_object, object_name);
    cos_str_set(&upload_part_copy_params1->upload_id, upload_id.data);
    upload_part_copy_params1->part_num = part1;
    upload_part_copy_params1->range_start = range_start1;
    upload_part_copy_params1->range_end = range_end1;
    headers = cos_table_make(p, 0);
    s = cos_upload_part_copy(options, upload_part_copy_params1, headers, &resp_headers);
    log_status(s);
    if (cos_status_is_ok(s)) {
        printf("multi object copy succeeded\n");
    } else {
        printf("multi object copy failed\n");
    }
    printf("last modified:%s, etag:%s\n", upload_part_copy_params1->rsp_content->last_modify.data, upload_part_copy_params1->rsp_content->etag.data);
    cos_list_init(&complete_part_list);
    // 响应加入列表
    {
        complete_content = cos_create_complete_part_content(p);
        cos_str_set(&complete_content->part_number, "1");
        cos_str_set(&complete_content->etag, upload_part_copy_params1->rsp_content->etag.data);
        cos_list_add_tail(&complete_content->node, &complete_part_list);
    }

    //upload part copy 2
    resp_headers = NULL;
    upload_part_copy_params2 = cos_create_upload_part_copy_params(p);
    cos_str_set(&upload_part_copy_params2->copy_source, src_object_path);
    cos_str_set(&upload_part_copy_params2->dest_bucket, bucket_name);
    cos_str_set(&upload_part_copy_params2->dest_object, object_name);
    cos_str_set(&upload_part_copy_params2->upload_id, upload_id.data);
    upload_part_copy_params2->part_num = part2;
    upload_part_copy_params2->range_start = range_start2;
    upload_part_copy_params2->range_end = range_end2;
    headers = cos_table_make(p, 0);
    s = cos_upload_part_copy(options, upload_part_copy_params2, headers, &resp_headers);
    log_status(s);
    if (cos_status_is_ok(s)) {
        printf("multi object copy succeeded\n");
    } else {
        printf("multi object copy failed\n");
    }
    printf("last modified:%s, etag:%s\n", upload_part_copy_params2->rsp_content->last_modify.data, upload_part_copy_params2->rsp_content->etag.data);
    // 响应加入列表
    {
        complete_content = cos_create_complete_part_content(p);
        cos_str_set(&complete_content->part_number, "2");
        cos_str_set(&complete_content->etag, upload_part_copy_params2->rsp_content->etag.data);
        cos_list_add_tail(&complete_content->node, &complete_part_list);
    }

    //complete multipart
    headers = cos_table_make(p, 0);
    s = cos_complete_multipart_upload(options, &bucket, &object,
            &upload_id, &complete_part_list, headers, &complete_resp_headers);
    log_status(s);

    cos_pool_destroy(p);
    if (cos_status_is_ok(s)) {
        printf("multi object copy succeeded\n");
    } else {
        printf("multi object copy failed\n");
    }
}


int main() {
    if (cos_http_io_initialize(NULL, 0) != COSE_OK) {
        exit(1);
    }
    // set log level, default COS_LOG_WARN
    cos_log_set_level(COS_LOG_WARN);
    copy_demo();
    copy_object_demo();
    part_copy_demo();
    // cos_http_io_deinitialize last
    cos_http_io_deinitialize();
    return 0;
}
