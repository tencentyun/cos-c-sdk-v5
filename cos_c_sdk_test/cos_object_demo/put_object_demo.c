#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "cos_api.h"
#include "cos_http_io.h"
#include "cos_log.h"

/**
 * 本样例演示了如何使用 COS C SDK 进行对象上传
 * 包括：上传本地文件、上传 buffer 中数据、上传目录类型、高级上传、分块上传和取消分块上传
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

void put_object_from_file_demo() {
    char object_name[] = "test.txt";  // 对象名称
    char file_path[] = "test.txt";    // 本地文件路径

    cos_pool_t* p = NULL;
    cos_status_t* s = NULL;
    cos_request_options_t* options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t file;
    cos_table_t* resp_headers = NULL;
    cos_table_t* headers = NULL;

    // 创建内存池
    cos_pool_create(&p, NULL);

    // 初始化请求选项
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, bucket_name);

    // 限速值设置范围为819200 - 838860800，即100KB/s - 100MB/s，如果超出该范围将返回400错误
    // headers = cos_table_make(p, 1);
    // cos_table_add_int(headers, "x-cos-traffic-limit", 819200);

    // 上传对象
    cos_str_set(&file, file_path);
    cos_str_set(&object, object_name);
    s = cos_put_object_from_file(options, &bucket, &object, &file, headers, &resp_headers);
    if (cos_status_is_ok(s)) {
        printf("put object succeeded\n");
    } else {
        printf("put object failed\n");
    }
    log_status(s);

    // 销毁内存池
    cos_pool_destroy(p);
}

void put_object_from_buffer_demo() {
    char object_name[] = "test.txt";  // 对象名称

    cos_pool_t* p = NULL;
    cos_status_t* s = NULL;
    cos_request_options_t* options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_table_t* resp_headers;
    cos_table_t* headers = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, bucket_name);
    cos_str_set(&object, object_name);

    // buffer 数据
    cos_list_t buffer;
    cos_buf_t* content = NULL;
    char* str = "This is my test data.";
    cos_list_init(&buffer);
    content = cos_buf_pack(options->pool, str, strlen(str));
    cos_list_add_tail(&content->node, &buffer);

    s = cos_put_object_from_buffer(options, &bucket, &object,
                                   &buffer, headers, &resp_headers);
    if (cos_status_is_ok(s)) {
        printf("put object succeeded\n");
    } else {
        printf("put object failed\n");
    }
    log_status(s);
    cos_pool_destroy(p);
}

void put_object_dir_demo() {
    // COS 上可以将以 / 分隔的对象路径看做一个虚拟文件夹，根据此特性，可以上传一个空的流，并且命名以 / 结尾，可实现在 COS 上创建一个空文件夹。
    char dir_name[] = "test/";  // 目录名称，末尾需要加/

    cos_pool_t* p = NULL;
    cos_status_t* s = NULL;
    cos_request_options_t* options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_table_t* resp_headers;
    cos_table_t* headers = NULL;
    cos_list_t buffer;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, bucket_name);
    cos_str_set(&object, dir_name);

    // 上传文件夹
    cos_list_init(&buffer);
    s = cos_put_object_from_buffer(options, &bucket, &object,
                                   &buffer, headers, &resp_headers);
    if (cos_status_is_ok(s)) {
        printf("put dir succeeded\n");
    } else {
        printf("put dir failed\n");
    }
    log_status(s);
    cos_pool_destroy(p);
}

void resumable_put_object_demo() {
    char object_name[] = "big_file2.txt";  // 对象名称
    char file_path[] = "big_file.txt";    // 本地文件路径
    int enable_checkpoint = COS_FALSE; // 是否开启断点续传

    cos_pool_t* p = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t filename;
    cos_status_t* s = NULL;
    cos_table_t* headers = NULL;
    cos_table_t* resp_headers = NULL;
    cos_request_options_t* options = NULL;
    cos_resumable_clt_params_t* clt_params;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 0);
    cos_str_set(&bucket, bucket_name);
    cos_str_set(&object, object_name);
    cos_str_set(&filename, file_path);

    // upload
    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 1024 * 5, 8, enable_checkpoint, NULL);
    s = cos_resumable_upload_file(options, &bucket, &object, &filename, headers, NULL,
                                  clt_params, NULL, &resp_headers, NULL);
    log_status(s);
    if (cos_status_is_ok(s)) {
        printf("upload succeeded\n");
    } else {
        printf("upload failed\n");
    }

    cos_pool_destroy(p);
}

void multipart_upload_file_demo() {
    char object_name[] = "big_file2.txt";  // 对象名称
    char file_path[] = "big_file.txt";    // 本地文件路径

    cos_pool_t *p = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_table_t *headers = NULL;
    cos_table_t *complete_headers = NULL;
    cos_table_t *resp_headers = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t upload_id;
    cos_upload_file_t *upload_file = NULL;
    cos_status_t *s = NULL;
    cos_list_upload_part_params_t *params = NULL;
    cos_list_t complete_part_list;
    cos_list_part_content_t *part_content = NULL;
    cos_complete_part_content_t *complete_part_content = NULL;
    int part_num = 1;
    int64_t pos = 0;
    int64_t file_length = 0;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 1);
    complete_headers = cos_table_make(p, 1);
    cos_str_set(&bucket, bucket_name);
    cos_str_set(&object, object_name);

    //init mulitipart
    s = cos_init_multipart_upload(options, &bucket, &object,
                                  &upload_id, headers, &resp_headers);
    log_status(s);
    if (cos_status_is_ok(s)) {
        printf("Init multipart upload succeeded, upload_id:%.*s\n",
               upload_id.len, upload_id.data);
    } else {
        printf("Init multipart upload failed\n");
        cos_pool_destroy(p);
        return;
    }

    //upload part from file
    int res = COSE_OK;
    cos_file_buf_t *fb = cos_create_file_buf(p);
    res = cos_open_file_for_all_read(p, file_path, fb);
    if (res != COSE_OK) {
        cos_error_log("Open read file fail, filename:%s\n", file_path);
        return;
    }
    file_length = fb->file_last;
    apr_file_close(fb->file);
    while(pos < file_length) {
        upload_file = cos_create_upload_file(p);
        cos_str_set(&upload_file->filename, file_path);
        upload_file->file_pos = pos;
        pos += 10 * 1024 * 1024;
        upload_file->file_last = pos < file_length ? pos : file_length; //10 MB
        s = cos_upload_part_from_file(options, &bucket, &object, &upload_id,
                part_num++, upload_file, &resp_headers);

        if (cos_status_is_ok(s)) {
            printf("Multipart upload part from file succeeded\n");
        } else {
            printf("Multipart upload part from file failed\n");
        }
    }

    //list part
    params = cos_create_list_upload_part_params(p);
    params->max_ret = 1000;
    cos_list_init(&complete_part_list);
    s = cos_list_upload_part(options, &bucket, &object, &upload_id,
                             params, &resp_headers);

    if (cos_status_is_ok(s)) {
        printf("List multipart succeeded\n");
        cos_list_for_each_entry(cos_list_part_content_t, part_content, &params->part_list, node) {
            printf("part_number = %s, size = %s, last_modified = %s, etag = %s\n",
                   part_content->part_number.data,
                   part_content->size.data,
                   part_content->last_modified.data,
                   part_content->etag.data);
        }
    } else {
        printf("List multipart failed\n");
        cos_pool_destroy(p);
        return;
    }

    cos_list_for_each_entry(cos_list_part_content_t, part_content, &params->part_list, node) {
        complete_part_content = cos_create_complete_part_content(p);
        cos_str_set(&complete_part_content->part_number, part_content->part_number.data);
        cos_str_set(&complete_part_content->etag, part_content->etag.data);
        cos_list_add_tail(&complete_part_content->node, &complete_part_list);
    }

    //complete multipart
    s = cos_complete_multipart_upload(options, &bucket, &object, &upload_id,
            &complete_part_list, complete_headers, &resp_headers);
    log_status(s);
    if (cos_status_is_ok(s)) {
        printf("Complete multipart upload from file succeeded, upload_id:%.*s\n",
               upload_id.len, upload_id.data);
    } else {
        printf("Complete multipart upload from file failed\n");
    }

    cos_pool_destroy(p);
}

void abort_multipart_upload_demo() {
    char object_name[] = "big_file2.txt";  // 对象名称

    cos_pool_t *p = NULL;
    cos_string_t bucket;
    cos_string_t object;
    int is_cname = 0;
    cos_table_t *headers = NULL;
    cos_table_t *resp_headers = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t upload_id;
    cos_status_t *s = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 1);
    cos_str_set(&bucket, bucket_name);
    cos_str_set(&object, object_name);

    s = cos_init_multipart_upload(options, &bucket, &object,
                                  &upload_id, headers, &resp_headers);
    log_status(s);
    if (cos_status_is_ok(s)) {
        printf("Init multipart upload succeeded, upload_id:%.*s\n",
               upload_id.len, upload_id.data);
    } else {
        printf("Init multipart upload failed\n");
        cos_pool_destroy(p);
        return;
    }

    s = cos_abort_multipart_upload(options, &bucket, &object, &upload_id,
                                   &resp_headers);
    log_status(s);
    if (cos_status_is_ok(s)) {
        printf("Abort multipart upload succeeded, upload_id::%.*s\n",
               upload_id.len, upload_id.data);
    } else {
        printf("Abort multipart upload failed\n");
    }

    cos_pool_destroy(p);
}

int main() {
    if (cos_http_io_initialize(NULL, 0) != COSE_OK) {
        exit(1);
    }
    // set log level, default COS_LOG_WARN
    // cos_log_set_level(COS_LOG_WARN);
    put_object_from_file_demo();
    put_object_from_buffer_demo();
    put_object_dir_demo();
    resumable_put_object_demo();
    multipart_upload_file_demo();
    abort_multipart_upload_demo();

    // cos_http_io_deinitialize last
    cos_http_io_deinitialize();
    return 0;
}
