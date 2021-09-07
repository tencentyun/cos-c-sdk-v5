#include "cos_http_io.h"
#include "cos_api.h"
#include "cos_log.h"
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/stat.h>

static char TEST_COS_ENDPOINT[] = "cos.ap-guangzhou.myqcloud.com";
static char *TEST_ACCESS_KEY_ID;                //your secret_id
static char *TEST_ACCESS_KEY_SECRET;            //your secret_key
static char TEST_APPID[] = "<APPID>";    //your appid
static char TEST_BUCKET_NAME[] = "<bucketname-appid>";    //the cos bucket name, syntax: [bucket]-[appid], for example: mybucket-1253666666
static char TEST_UIN[] = "<Uin>";    //your uin
static char TEST_REGION[] = "ap-guangzhou";    //region in endpoint
static char TEST_OBJECT_NAME1[] = "1.txt";
static char TEST_OBJECT_NAME2[] = "test2.dat";
static char TEST_OBJECT_NAME3[] = "test3.dat";
static char TEST_OBJECT_NAME4[] = "multipart.txt";
//static char TEST_DOWNLOAD_NAME2[] = "download_test2.dat";
static char *TEST_APPEND_NAMES[] = {"test.7z.001", "test.7z.002"};
static char TEST_DOWNLOAD_NAME3[] = "download_test3.dat";
static char TEST_MULTIPART_OBJECT[] = "multipart.dat";
static char TEST_DOWNLOAD_NAME4[] = "multipart_download.dat";
static char TEST_MULTIPART_FILE[] = "test.zip";
//static char TEST_MULTIPART_OBJECT2[] = "multipart2.dat";
static char TEST_MULTIPART_OBJECT3[] = "multipart3.dat";
static char TEST_MULTIPART_OBJECT4[] = "multipart4.dat";



void init_test_config(cos_config_t *config, int is_cname)
{
    cos_str_set(&config->endpoint, TEST_COS_ENDPOINT);
    cos_str_set(&config->access_key_id, TEST_ACCESS_KEY_ID);
    cos_str_set(&config->access_key_secret, TEST_ACCESS_KEY_SECRET);
    cos_str_set(&config->appid, TEST_APPID);
    config->is_cname = is_cname;
}

void init_test_request_options(cos_request_options_t *options, int is_cname)
{
    options->config = cos_config_create(options->pool);
    init_test_config(options->config, is_cname);
    options->ctl = cos_http_controller_create(options->pool, 0);
}

void log_status(cos_status_t *s)
{
    cos_warn_log("status->code: %d", s->code);
    if (s->error_code) cos_warn_log("status->error_code: %s", s->error_code);
    if (s->error_msg) cos_warn_log("status->error_msg: %s", s->error_msg);
    if (s->req_id) cos_warn_log("status->req_id: %s", s->req_id);
}

void test_sign()
{
    cos_pool_t *p = NULL;
    const unsigned char secret_key[] = "AKIDZfbOA78asKUYBcXFrJD0a1ICvR98JM";
    const unsigned char time_str[] = "1480932292;1481012292";
    unsigned char sign_key[40];
    cos_buf_t *fmt_str;
    const char * value = NULL;
    const char * uri = "/testfile";
    const char * host = "testbucket-125000000.cn-north.myqcloud.com&range=bytes%3d0-3";
    unsigned char fmt_str_hex[40];

    cos_pool_create(&p, NULL);
    fmt_str = cos_create_buf(p, 1024);

    cos_get_hmac_sha1_hexdigest(sign_key, secret_key, sizeof(secret_key)-1, time_str, sizeof(time_str)-1);
    char * pstr = apr_pstrndup(p, (char*)sign_key, sizeof(sign_key));
    cos_warn_log("sign_key: %s", pstr);

    // method
    value = "get";
    cos_buf_append_string(p, fmt_str, value, strlen(value));                  
    cos_buf_append_string(p, fmt_str, "\n", sizeof("\n")-1);        
    
    // canonicalized resource(URI)
    cos_buf_append_string(p, fmt_str, uri, strlen(uri));                  
    cos_buf_append_string(p, fmt_str, "\n", sizeof("\n")-1); 

    // query-parameters
    cos_buf_append_string(p, fmt_str, "\n", sizeof("\n")-1);
    
    
    // Host
    cos_buf_append_string(p, fmt_str, "host=", sizeof("host=")-1);
    cos_buf_append_string(p, fmt_str, host, strlen(host));                  
    cos_buf_append_string(p, fmt_str, "\n", sizeof("\n")-1);    

    char * pstr3 = apr_pstrndup(p, (char*)fmt_str->pos, cos_buf_size(fmt_str));
    cos_warn_log("Format string: %s", pstr3);

    // Format-String sha1hash
    cos_get_sha1_hexdigest(fmt_str_hex, (unsigned char*)fmt_str->pos, cos_buf_size(fmt_str));

    char * pstr2 = apr_pstrndup(p, (char*)fmt_str_hex, sizeof(fmt_str_hex));
    cos_warn_log("Format string sha1hash: %s", pstr2);
    
    cos_pool_destroy(p);
}

void test_bucket()
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_acl_e cos_acl = COS_ACL_PRIVATE;
    cos_string_t bucket;
    cos_table_t *resp_headers = NULL;
   
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);

    //create test bucket
    s = cos_create_bucket(options, &bucket, cos_acl, &resp_headers);
    log_status(s);

    //list object (get bucket)
    cos_list_object_params_t *list_params = NULL;
    list_params = cos_create_list_object_params(p);
    cos_str_set(&list_params->encoding_type, "url");
    s = cos_list_object(options, &bucket, list_params, &resp_headers);
    log_status(s);
    cos_list_object_content_t *content = NULL;
    char *line = NULL;
    cos_list_for_each_entry(cos_list_object_content_t, content, &list_params->object_list, node) {
        line = apr_psprintf(p, "%.*s\t%.*s\t%.*s\n", content->key.len, content->key.data, 
            content->size.len, content->size.data, 
            content->last_modified.len, content->last_modified.data);
        printf("%s", line);
        printf("next marker: %s\n", list_params->next_marker.data);
    }
    cos_list_object_common_prefix_t *common_prefix = NULL;
    cos_list_for_each_entry(cos_list_object_common_prefix_t, common_prefix, &list_params->common_prefix_list, node) {
        printf("common prefix: %s\n", common_prefix->prefix.data);
    }
    

    //delete bucket
    s = cos_delete_bucket(options, &bucket, &resp_headers);
    log_status(s);
    
    
    cos_pool_destroy(p);    
}

void test_bucket_lifecycle()
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_table_t *resp_headers = NULL;
   
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);

    cos_list_t rule_list;
    cos_list_init(&rule_list);
    cos_lifecycle_rule_content_t *rule_content = NULL;

    rule_content = cos_create_lifecycle_rule_content(p);
    cos_str_set(&rule_content->id, "testrule1");
    cos_str_set(&rule_content->prefix, "abc/");
    cos_str_set(&rule_content->status, "Enabled");
    rule_content->expire.days = 365;
    cos_list_add_tail(&rule_content->node, &rule_list);

    rule_content = cos_create_lifecycle_rule_content(p);
    cos_str_set(&rule_content->id, "testrule2");
    cos_str_set(&rule_content->prefix, "efg/");
    cos_str_set(&rule_content->status, "Disabled");
    cos_str_set(&rule_content->transition.storage_class, "Standard_IA");
    rule_content->transition.days = 999;
    cos_list_add_tail(&rule_content->node, &rule_list);

    rule_content = cos_create_lifecycle_rule_content(p);
    cos_str_set(&rule_content->id, "testrule3");
    cos_str_set(&rule_content->prefix, "xxx/");
    cos_str_set(&rule_content->status, "Enabled");
    rule_content->abort.days = 1;
    cos_list_add_tail(&rule_content->node, &rule_list);
    
    s = cos_put_bucket_lifecycle(options, &bucket, &rule_list, &resp_headers);
    log_status(s);

    cos_list_t rule_list_ret;
    cos_list_init(&rule_list_ret);
    s = cos_get_bucket_lifecycle(options, &bucket, &rule_list_ret, &resp_headers);
    log_status(s);

    cos_delete_bucket_lifecycle(options, &bucket, &resp_headers);
    log_status(s);
    
    cos_pool_destroy(p);    
}


void test_object()
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_table_t *resp_headers;
    cos_table_t *headers = NULL;
    cos_list_t buffer;
    cos_buf_t *content = NULL;
    char * str = "This is my test data.";
    cos_string_t file;
    bool traffic_limit = false;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, TEST_OBJECT_NAME1);

    cos_list_init(&buffer);
    content = cos_buf_pack(options->pool, str, strlen(str));
    cos_list_add_tail(&content->node, &buffer);
    s = cos_put_object_from_buffer(options, &bucket, &object, 
                   &buffer, headers, &resp_headers);
    log_status(s);

    cos_list_t download_buffer;
    cos_list_init(&download_buffer);
    if (traffic_limit) {
        // 限速值设置范围为819200 - 838860800，即100KB/s - 100MB/s，如果超出该范围将返回400错误
        headers = cos_table_make(p, 1);
        cos_table_add_int(headers, "x-cos-traffic-limit", 819200);
    }
    s = cos_get_object_to_buffer(options, &bucket, &object, 
                       NULL, NULL, &download_buffer, &resp_headers);
    log_status(s);
    int64_t len = 0;
    int64_t size = 0;
    int64_t pos = 0;
    cos_list_for_each_entry(cos_buf_t, content, &download_buffer, node) {
        len += cos_buf_size(content);
    }
    char *buf = cos_pcalloc(p, (apr_size_t)(len + 1));
    buf[len] = '\0';
    cos_list_for_each_entry(cos_buf_t, content, &download_buffer, node) {
        size = cos_buf_size(content);
        memcpy(buf + pos, content->pos, (size_t)size);
        pos += size;
    }
    cos_warn_log("Download data=%s", buf);

    
    cos_str_set(&file, TEST_OBJECT_NAME4);
    cos_str_set(&object, TEST_OBJECT_NAME4);
    s = cos_put_object_from_file(options, &bucket, &object, &file, NULL, &resp_headers);
    log_status(s);

    cos_str_set(&file, TEST_DOWNLOAD_NAME3);
    cos_str_set(&object, TEST_OBJECT_NAME3);
    s = cos_get_object_to_file(options, &bucket, &object, NULL, NULL, &file, &resp_headers);
    log_status(s);

    cos_str_set(&object, TEST_OBJECT_NAME2);
    s = cos_head_object(options, &bucket, &object, NULL, &resp_headers);
    log_status(s);

    cos_str_set(&object, TEST_OBJECT_NAME1);
    s = cos_delete_object(options, &bucket, &object, &resp_headers);
    log_status(s);

    cos_str_set(&object, TEST_OBJECT_NAME3);
    s = cos_delete_object(options, &bucket, &object, &resp_headers);
    log_status(s);
    
    cos_str_set(&object, TEST_OBJECT_NAME3);
    int32_t count = sizeof(TEST_APPEND_NAMES)/sizeof(char*);
    int32_t index = 0;
    for (; index < count; index++)
    {
        int64_t position = 0;
        cos_str_set(&file, TEST_APPEND_NAMES[index]);
        s = cos_head_object(options, &bucket, &object, NULL, &resp_headers);
        if(s->code == 200) {
            char *content_length_str = (char*)apr_table_get(resp_headers, COS_CONTENT_LENGTH);
            if (content_length_str != NULL) {
                position = atol(content_length_str);
            }
        }
        s = cos_append_object_from_file(options, &bucket, &object, 
                                        position, &file, NULL, &resp_headers);
        log_status(s);
    }

    
    cos_pool_destroy(p);
}

void test_object_restore()
{
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    cos_string_t object;
    int is_cname = 0;
    cos_table_t *resp_headers = NULL;
    cos_request_options_t *options = NULL;
    cos_status_t *s = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test_restore.dat");

    cos_object_restore_params_t *restore_params = cos_create_object_restore_params(p);
    restore_params->days = 30;
    cos_str_set(&restore_params->tier, "Standard");
    s = cos_post_object_restore(options, &bucket, &object, restore_params, NULL, NULL, &resp_headers);
    log_status(s);

    cos_pool_destroy(p);
}

void progress_callback(int64_t consumed_bytes, int64_t total_bytes)
{
    printf("consumed_bytes = %"APR_INT64_T_FMT", total_bytes = %"APR_INT64_T_FMT"\n", consumed_bytes, total_bytes);
}

void test_put_object_from_file()
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_table_t *resp_headers;
    cos_string_t file;
    bool traffic_limit = false;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_table_t *headers = NULL;
    if (traffic_limit) {
        // 限速值设置范围为819200 - 838860800，即100KB/s - 100MB/s，如果超出该范围将返回400错误
        headers = cos_table_make(p, 1);
        cos_table_add_int(headers, "x-cos-traffic-limit", 819200);
    }
    cos_str_set(&options->config->sts_token, "MyTokenString");
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&file, TEST_OBJECT_NAME4);
    cos_str_set(&object, TEST_OBJECT_NAME4);
    //s = cos_put_object_from_file(options, &bucket, &object, &file, headers, &resp_headers);
    s = cos_do_put_object_from_file(options, &bucket, &object, &file, headers, NULL, progress_callback, &resp_headers, NULL);
    log_status(s);

    cos_pool_destroy(p);
}

void test_put_object_from_file_with_sse() 
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_table_t *resp_headers;
    cos_string_t file;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_table_t *headers = NULL;
    headers = cos_table_make(p, 3);
//  apr_table_add(headers, "x-cos-server-side-encryption", "AES256");
    apr_table_add(headers, "x-cos-server-side-encryption-customer-algorithm", "AES256");
    apr_table_add(headers, "x-cos-server-side-encryption-customer-key", "MDEyMzQ1Njc4OUFCQ0RFRjAxMjM0NTY3ODlBQkNERUY=");
    apr_table_add(headers, "x-cos-server-side-encryption-customer-key-MD5", "U5L61r7jcwdNvT7frmUG8g==");

    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&file, "/home/jojoliang/data/test.jpg");
    cos_str_set(&object, "pic");

    s = cos_put_object_from_file(options, &bucket, &object, &file, headers, &resp_headers);
    log_status(s);
    {
        int i = 0;
        apr_array_header_t * pp = (apr_array_header_t *) apr_table_elts(resp_headers);
        for ( ; i < pp->nelts; i++)
        {
            apr_table_entry_t *ele = (apr_table_entry_t *)pp->elts+i;
            printf("%s: %s\n",ele->key,ele->val);
        }
    }

    cos_pool_destroy(p);
}

void test_get_object_to_file_with_sse()
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
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
    headers = cos_table_make(p, 3);
/*
    apr_table_add(headers, "x-cos-server-side-encryption", "AES256");
*/
/*
    apr_table_add(headers, "x-cos-server-side-encryption-customer-algorithm", "AES256");
    apr_table_add(headers, "x-cos-server-side-encryption-customer-key", "MDEyMzQ1Njc4OUFCQ0RFRjAxMjM0NTY3ODlBQkNERUY=");
    apr_table_add(headers, "x-cos-server-side-encryption-customer-key-MD5", "U5L61r7jcwdNvT7frmUG8g==");
*/
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&file, "getfile");
    cos_str_set(&object, TEST_OBJECT_NAME1);

    s = cos_get_object_to_file(options, &bucket, &object, headers, params, &file, &resp_headers);
    log_status(s);

    {
        int i = 0;
        apr_array_header_t * pp = (apr_array_header_t *) apr_table_elts(resp_headers);
        for ( ; i < pp->nelts; i++)
        {
            apr_table_entry_t *ele = (apr_table_entry_t *)pp->elts+i;
            printf("%s: %s\n",ele->key,ele->val);
        }
    }


    cos_pool_destroy(p);

}

void multipart_upload_file_from_file()
{
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    cos_string_t object;
    int is_cname = 0;
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
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, TEST_MULTIPART_OBJECT);
    
    //init mulitipart
    s = cos_init_multipart_upload(options, &bucket, &object, 
                                  &upload_id, headers, &resp_headers);

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
    res = cos_open_file_for_all_read(p, TEST_MULTIPART_FILE, fb);
    if (res != COSE_OK) {
        cos_error_log("Open read file fail, filename:%s\n", TEST_MULTIPART_FILE);
        return;
    }
    file_length = fb->file_last;
    apr_file_close(fb->file);
    while(pos < file_length) {
        upload_file = cos_create_upload_file(p);
        cos_str_set(&upload_file->filename, TEST_MULTIPART_FILE);
        upload_file->file_pos = pos;
        pos += 2 * 1024 * 1024;
        upload_file->file_last = pos < file_length ? pos : file_length; //2MB
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

    if (cos_status_is_ok(s)) {
        printf("Complete multipart upload from file succeeded, upload_id:%.*s\n", 
               upload_id.len, upload_id.data);
    } else {
        printf("Complete multipart upload from file failed\n");
    }

    cos_pool_destroy(p);
}

void multipart_upload_file_from_buffer()
{
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    cos_string_t object;
    int is_cname = 0;
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
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, TEST_MULTIPART_OBJECT);
    
    //init mulitipart
    s = cos_init_multipart_upload(options, &bucket, &object, 
                                  &upload_id, headers, &resp_headers);

    if (cos_status_is_ok(s)) {
        printf("Init multipart upload succeeded, upload_id:%.*s\n", 
               upload_id.len, upload_id.data);
    } else {
        printf("Init multipart upload failed\n");
        cos_pool_destroy(p);
        return;
    }

    //upload part from buffer
    int res = COSE_OK;
    char *str = "This is my test data....";
    cos_list_t buffer;
    cos_buf_t *content;

    // 上传一个分块
    cos_list_init(&buffer);
    content = cos_buf_pack(p, str, strlen(str));
    cos_list_add_tail(&content->node, &buffer);
    s = cos_upload_part_from_buffer(options, &bucket, &object, &upload_id, 1, &buffer, &resp_headers);

    // 直接获取etag
    char *etag = apr_pstrdup(p, (char*)apr_table_get(resp_headers, "ETag"));
    cos_list_init(&complete_part_list);
    complete_part_content = cos_create_complete_part_content(p);
    cos_str_set(&complete_part_content->part_number, "1");
    cos_str_set(&complete_part_content->etag, etag);
    cos_list_add_tail(&complete_part_content->node, &complete_part_list);

    // 也可以通过 list part 获取取etag
    /*
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
    */

    //complete multipart
    s = cos_complete_multipart_upload(options, &bucket, &object, &upload_id,
            &complete_part_list, complete_headers, &resp_headers);

    if (cos_status_is_ok(s)) {
        printf("Complete multipart upload from file succeeded, upload_id:%.*s\n", 
               upload_id.len, upload_id.data);
    } else {
        printf("Complete multipart upload from file failed\n");
    }

    cos_pool_destroy(p);
}

void abort_multipart_upload()
{
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
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, TEST_MULTIPART_OBJECT);

    s = cos_init_multipart_upload(options, &bucket, &object, 
                                  &upload_id, headers, &resp_headers);

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

    if (cos_status_is_ok(s)) {
        printf("Abort multipart upload succeeded, upload_id::%.*s\n", 
               upload_id.len, upload_id.data);
    } else {
        printf("Abort multipart upload failed\n"); 
    }    

    cos_pool_destroy(p);
}


void list_multipart()
{
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    cos_string_t object;
    int is_cname = 0;
    cos_table_t *resp_headers = NULL;
    cos_request_options_t *options = NULL;
    cos_status_t *s = NULL;
    cos_list_multipart_upload_params_t *list_multipart_params = NULL;
    cos_list_upload_part_params_t *list_upload_param = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    
    list_multipart_params = cos_create_list_multipart_upload_params(p);
    list_multipart_params->max_ret = 999;
    s = cos_list_multipart_upload(options, &bucket, list_multipart_params, &resp_headers);
    log_status(s);

    list_upload_param = cos_create_list_upload_part_params(p);
    list_upload_param->max_ret = 1000;
    cos_string_t upload_id;
    cos_str_set(&upload_id,"149373379126aee264fecbf5fe8ddb8b9cd23b76c73ab1af0bcfd50683cc4254f81ebe2386");
    cos_str_set(&object, TEST_MULTIPART_OBJECT);
    s = cos_list_upload_part(options, &bucket, &object, &upload_id, 
                             list_upload_param, &resp_headers);
    if (cos_status_is_ok(s)) {
        printf("List upload part succeeded, upload_id::%.*s\n", 
               upload_id.len, upload_id.data);
        cos_list_part_content_t *part_content = NULL;
        cos_list_for_each_entry(cos_list_part_content_t, part_content, &list_upload_param->part_list, node) {
            printf("part_number = %s, size = %s, last_modified = %s, etag = %s\n",
                   part_content->part_number.data, 
                   part_content->size.data, 
                   part_content->last_modified.data, 
                   part_content->etag.data);
        }
    } else {
        printf("List upload part failed\n"); 
    }  

     
    
    cos_pool_destroy(p);
    return;
}

void test_resumable()
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t filepath;
    cos_resumable_clt_params_t *clt_params;
    
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, TEST_MULTIPART_OBJECT4);
    cos_str_set(&filepath, TEST_DOWNLOAD_NAME4);

    clt_params = cos_create_resumable_clt_params_content(p, 5*1024*1024, 3, COS_FALSE, NULL);
    s = cos_resumable_download_file(options, &bucket, &object, &filepath, NULL, NULL, clt_params, NULL);
    log_status(s);

    cos_pool_destroy(p);
}

void test_resumable_upload_with_multi_threads()
{
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t filename;
    cos_status_t *s = NULL;
    int is_cname = 0;
    cos_table_t *headers = NULL;
    cos_table_t *resp_headers = NULL;
    cos_request_options_t *options = NULL;
    cos_resumable_clt_params_t *clt_params;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, TEST_MULTIPART_OBJECT4);
    cos_str_set(&filename, TEST_MULTIPART_FILE);

    // upload
    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 1024, 8, COS_FALSE, NULL);
    s = cos_resumable_upload_file(options, &bucket, &object, &filename, headers, NULL, 
        clt_params, NULL, &resp_headers, NULL);

    if (cos_status_is_ok(s)) {
        printf("upload succeeded\n");
    } else {
        printf("upload failed\n");
    }

    cos_pool_destroy(p);
}

void test_delete_objects()
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_string_t bucket;
    cos_status_t *s = NULL;
    cos_table_t *resp_headers = NULL;
    cos_request_options_t *options = NULL;
    char *object_name1 = TEST_OBJECT_NAME2;
    char *object_name2 = TEST_OBJECT_NAME3;
    cos_object_key_t *content1 = NULL;
    cos_object_key_t *content2 = NULL;
    cos_list_t object_list;
    cos_list_t deleted_object_list;
    int is_quiet = COS_TRUE;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);

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

void test_delete_objects_by_prefix()
{
    cos_pool_t *p = NULL;
    cos_request_options_t *options = NULL;
    int is_cname = 0;
    cos_string_t bucket;
    cos_status_t *s = NULL;
    cos_string_t prefix;
    char *prefix_str = "";
    
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&prefix, prefix_str);

    s = cos_delete_objects_by_prefix(options, &bucket, &prefix);
    log_status(s);
    cos_pool_destroy(p);

    printf("test_delete_object_by_prefix ok\n");
}

void test_acl()
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_acl_e cos_acl = COS_ACL_PRIVATE;
    cos_string_t bucket;
    cos_string_t object;
    cos_table_t *resp_headers = NULL;
   
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test.txt");

    //put acl
    cos_string_t read;
    cos_str_set(&read, "id=\"qcs::cam::uin/12345:uin/12345\", id=\"qcs::cam::uin/45678:uin/45678\"");
    s = cos_put_bucket_acl(options, &bucket, cos_acl, &read, NULL, NULL, &resp_headers);
    log_status(s);

    //get acl
    cos_acl_params_t *acl_params = NULL;
    acl_params = cos_create_acl_params(p);
    s = cos_get_bucket_acl(options, &bucket, acl_params, &resp_headers);
    log_status(s);
    printf("acl owner id:%s, name:%s\n", acl_params->owner_id.data, acl_params->owner_name.data);
    cos_acl_grantee_content_t *acl_content = NULL;
    cos_list_for_each_entry(cos_acl_grantee_content_t, acl_content, &acl_params->grantee_list, node) {
        printf("acl grantee type:%s, id:%s, name:%s, permission:%s\n", acl_content->type.data, acl_content->id.data, acl_content->name.data, acl_content->permission.data);
    }

    //put acl
    s = cos_put_object_acl(options, &bucket, &object, cos_acl, &read, NULL, NULL, &resp_headers);
    log_status(s);

    //get acl
    cos_acl_params_t *acl_params2 = NULL;
    acl_params2 = cos_create_acl_params(p);
    s = cos_get_object_acl(options, &bucket, &object, acl_params2, &resp_headers);
    log_status(s);
    printf("acl owner id:%s, name:%s\n", acl_params2->owner_id.data, acl_params2->owner_name.data);
    acl_content = NULL;
    cos_list_for_each_entry(cos_acl_grantee_content_t, acl_content, &acl_params2->grantee_list, node) {
        printf("acl grantee id:%s, name:%s, permission:%s\n", acl_content->id.data, acl_content->name.data, acl_content->permission.data);
    }

    cos_pool_destroy(p);
}

void test_copy()
{
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
   
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test_copy.txt");
    cos_str_set(&src_bucket, "mybucket-1253685564");
    cos_str_set(&src_endpoint, "cn-south.myqcloud.com");
    cos_str_set(&src_object, "test.txt");

    cos_copy_object_params_t *params = NULL;
    params = cos_create_copy_object_params(p);
    s = cos_copy_object(options, &src_bucket, &src_object, &src_endpoint, &bucket, &object, NULL, params, &resp_headers);
    log_status(s);

    cos_pool_destroy(p);
}

void test_modify_storage_class()
{
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
   
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test.txt");
    cos_str_set(&src_bucket, TEST_BUCKET_NAME);
    cos_str_set(&src_endpoint, TEST_COS_ENDPOINT);
    cos_str_set(&src_object, "test.txt");

    // 设置x-cos-metadata-directive和x-cos-storage-class头域(替换为自己要更改的存储类型)
    cos_table_t *headers = cos_table_make(p, 2);
    apr_table_add(headers, "x-cos-metadata-directive", "Replaced");
    // 存储类型包括NTELLIGENT_TIERING，MAZ_INTELLIGENT_TIERING，STANDARD_IA，ARCHIVE，DEEP_ARCHIVE
    apr_table_add(headers, "x-cos-storage-class", "ARCHIVE");

    cos_copy_object_params_t *params = NULL;
    params = cos_create_copy_object_params(p);
    s = cos_copy_object(options, &src_bucket, &src_object, &src_endpoint, &bucket, &object, headers, params, &resp_headers);
    log_status(s);

    cos_pool_destroy(p);
}

void test_copy_mt()
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t src_bucket;
    cos_string_t src_object;
    cos_string_t src_endpoint;
   
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test_copy.txt");
    cos_str_set(&src_bucket, "mybucket-1253685564");
    cos_str_set(&src_endpoint, "cn-south.myqcloud.com");
    cos_str_set(&src_object, "test.txt");

    s = cos_upload_object_by_part_copy_mt(options, &src_bucket, &src_object, &src_endpoint, &bucket, &object, 1024*1024, 8, NULL);
    log_status(s);

    cos_pool_destroy(p);
}

void test_copy_with_part_copy()
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t copy_source;
   
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test_copy.txt");
    cos_str_set(&copy_source, "mybucket-1253685564.cn-south.myqcloud.com/test.txt");

    s = cos_upload_object_by_part_copy(options, &copy_source, &bucket, &object, 1024*1024);
    log_status(s);

    cos_pool_destroy(p);
}

void make_rand_string(cos_pool_t *p, int len, cos_string_t *data)
{
    char *str = NULL;
    int i = 0;
    str = (char *)cos_palloc(p, len + 1);
    for ( ; i < len; i++) {
        str[i] = 'a' + rand() % 32;
    }
    str[len] = '\0';
    cos_str_set(data, str);
}

unsigned long get_file_size(const char *file_path)
{
    unsigned long filesize = -1; 
    struct stat statbuff;

    if(stat(file_path, &statbuff) < 0){
        return filesize;
    } else {
        filesize = statbuff.st_size;
    }

    return filesize;
}

void test_part_copy()
{
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
    char *local_filename = "test_upload_part_copy.file";
    char *download_filename = "test_upload_part_copy.file.download";
    char *source_object_name = "cos_test_upload_part_copy_source_object";
    char *dest_object_name = "cos_test_upload_part_copy_dest_object";
    FILE *fd = NULL;
    cos_string_t download_file;
    cos_string_t dest_bucket;
    cos_string_t dest_object;
    int64_t range_start1 = 0;
    int64_t range_end1 = 6000000;
    int64_t range_start2 = 6000001;
    int64_t range_end2;
    cos_string_t data;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);

    // create multipart upload local file    
    make_rand_string(p, 10 * 1024 * 1024, &data);
    fd = fopen(local_filename, "w");
    fwrite(data.data, sizeof(data.data[0]), data.len, fd);
    fclose(fd);    

    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, source_object_name);
    cos_str_set(&file, local_filename);
    s = cos_put_object_from_file(options, &bucket, &object, &file, NULL, &resp_headers);
    log_status(s);

    //init mulitipart
    cos_str_set(&object, dest_object_name);
    s = cos_init_multipart_upload(options, &bucket, &object, 
                                  &upload_id, NULL, &resp_headers);
    log_status(s);

    //upload part copy 1
    upload_part_copy_params1 = cos_create_upload_part_copy_params(p);
    cos_str_set(&upload_part_copy_params1->copy_source, "mybucket-1253666666.cn-south.myqcloud.com/cos_test_upload_part_copy_source_object");
    cos_str_set(&upload_part_copy_params1->dest_bucket, TEST_BUCKET_NAME);
    cos_str_set(&upload_part_copy_params1->dest_object, dest_object_name);
    cos_str_set(&upload_part_copy_params1->upload_id, upload_id.data);
    upload_part_copy_params1->part_num = part1;
    upload_part_copy_params1->range_start = range_start1;
    upload_part_copy_params1->range_end = range_end1;
    headers = cos_table_make(p, 0);
    s = cos_upload_part_copy(options, upload_part_copy_params1, headers, &resp_headers);
    log_status(s);
    printf("last modified:%s, etag:%s\n", upload_part_copy_params1->rsp_content->last_modify.data, upload_part_copy_params1->rsp_content->etag.data);

    //upload part copy 2
    resp_headers = NULL;
    range_end2 = get_file_size(local_filename) - 1;
    upload_part_copy_params2 = cos_create_upload_part_copy_params(p);
    cos_str_set(&upload_part_copy_params2->copy_source, "mybucket-1253666666.cn-south.myqcloud.com/cos_test_upload_part_copy_source_object");
    cos_str_set(&upload_part_copy_params2->dest_bucket, TEST_BUCKET_NAME);
    cos_str_set(&upload_part_copy_params2->dest_object, dest_object_name);
    cos_str_set(&upload_part_copy_params2->upload_id, upload_id.data);
    upload_part_copy_params2->part_num = part2;
    upload_part_copy_params2->range_start = range_start2;
    upload_part_copy_params2->range_end = range_end2;
    headers = cos_table_make(p, 0);
    s = cos_upload_part_copy(options, upload_part_copy_params2, headers, &resp_headers);
    log_status(s);
    printf("last modified:%s, etag:%s\n", upload_part_copy_params1->rsp_content->last_modify.data, upload_part_copy_params1->rsp_content->etag.data);

    //list part
    list_upload_part_params = cos_create_list_upload_part_params(p);
    list_upload_part_params->max_ret = 10;
    cos_list_init(&complete_part_list);
        
    cos_str_set(&dest_bucket, TEST_BUCKET_NAME);
    cos_str_set(&dest_object, dest_object_name);
    s = cos_list_upload_part(options, &dest_bucket, &dest_object, &upload_id, 
                             list_upload_part_params, &list_part_resp_headers);
    log_status(s);
    cos_list_for_each_entry(cos_list_part_content_t, part_content, &list_upload_part_params->part_list, node) {
        complete_content = cos_create_complete_part_content(p);
        cos_str_set(&complete_content->part_number, part_content->part_number.data);
        cos_str_set(&complete_content->etag, part_content->etag.data);
        cos_list_add_tail(&complete_content->node, &complete_part_list);
    }
     
    //complete multipart
    headers = cos_table_make(p, 0);
    s = cos_complete_multipart_upload(options, &dest_bucket, &dest_object, 
            &upload_id, &complete_part_list, headers, &complete_resp_headers);
    log_status(s);
    
    //check upload copy part content equal to local file
    headers = cos_table_make(p, 0);
    cos_str_set(&download_file, download_filename);
    s = cos_get_object_to_file(options, &dest_bucket, &dest_object, headers, 
                               query_params, &download_file, &resp_headers);
    log_status(s);
    printf("local file len = %"APR_INT64_T_FMT", download file len = %"APR_INT64_T_FMT, get_file_size(local_filename), get_file_size(download_filename));
    remove(download_filename);
    remove(local_filename);
    cos_pool_destroy(p);

    printf("test part copy ok\n");
}


void test_cors()
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_table_t *resp_headers = NULL;
   
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);

    cos_list_t rule_list;
    cos_list_init(&rule_list);
    cos_cors_rule_content_t *rule_content = NULL;

    rule_content = cos_create_cors_rule_content(p);
    cos_str_set(&rule_content->id, "testrule1");
    cos_str_set(&rule_content->allowed_origin, "http://www.qq1.com");
    cos_str_set(&rule_content->allowed_method, "GET");
    cos_str_set(&rule_content->allowed_header, "*");
    cos_str_set(&rule_content->expose_header, "xxx");
    rule_content->max_age_seconds = 3600;
    cos_list_add_tail(&rule_content->node, &rule_list);

    rule_content = cos_create_cors_rule_content(p);
    cos_str_set(&rule_content->id, "testrule2");
    cos_str_set(&rule_content->allowed_origin, "http://www.qq2.com");
    cos_str_set(&rule_content->allowed_method, "GET");
    cos_str_set(&rule_content->allowed_header, "*");
    cos_str_set(&rule_content->expose_header, "yyy");
    rule_content->max_age_seconds = 7200;
    cos_list_add_tail(&rule_content->node, &rule_list);

    rule_content = cos_create_cors_rule_content(p);
    cos_str_set(&rule_content->id, "testrule3");
    cos_str_set(&rule_content->allowed_origin, "http://www.qq3.com");
    cos_str_set(&rule_content->allowed_method, "GET");
    cos_str_set(&rule_content->allowed_header, "*");
    cos_str_set(&rule_content->expose_header, "zzz");
    rule_content->max_age_seconds = 60;
    cos_list_add_tail(&rule_content->node, &rule_list);

    //put cors
    s = cos_put_bucket_cors(options, &bucket, &rule_list, &resp_headers);
    log_status(s);

    //get cors
    cos_list_t rule_list_ret;
    cos_list_init(&rule_list_ret);
    s = cos_get_bucket_cors(options, &bucket, &rule_list_ret, &resp_headers);
    log_status(s);
    cos_cors_rule_content_t *content = NULL;
    cos_list_for_each_entry(cos_cors_rule_content_t, content, &rule_list_ret, node) {
        printf("cors id:%s, allowed_origin:%s, allowed_method:%s, allowed_header:%s, expose_header:%s, max_age_seconds:%d\n",
                content->id.data, content->allowed_origin.data, content->allowed_method.data, content->allowed_header.data, content->expose_header.data, content->max_age_seconds);
    }

    //delete cors
    cos_delete_bucket_cors(options, &bucket, &resp_headers);
    log_status(s);
    
    cos_pool_destroy(p);

}

void test_versioning()
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_table_t *resp_headers = NULL;
   
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);

    cos_versioning_content_t *versioning = NULL;
    versioning = cos_create_versioning_content(p);
    cos_str_set(&versioning->status, "Suspended");

    //put bucket versioning
    s = cos_put_bucket_versioning(options, &bucket, versioning, &resp_headers);
    log_status(s);

    //get bucket versioning
    cos_str_set(&versioning->status, "");
    s = cos_get_bucket_versioning(options, &bucket, versioning, &resp_headers);
    log_status(s);
    printf("bucket versioning status: %s\n", versioning->status.data);
    
    cos_pool_destroy(p);

}


void test_replication()
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_request_options_t *dst_options = NULL;
    cos_string_t bucket;
    cos_string_t dst_bucket;
    cos_table_t *resp_headers = NULL;
   
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&dst_bucket, "replicationtest");

    dst_options = cos_request_options_create(p);
    init_test_request_options(dst_options, is_cname);
    cos_str_set(&dst_options->config->endpoint, "cn-east.myqcloud.com");
    
    //enable bucket versioning
    cos_versioning_content_t *versioning = NULL;
    versioning = cos_create_versioning_content(p);
    cos_str_set(&versioning->status, "Enabled");
    s = cos_put_bucket_versioning(options, &bucket, versioning, &resp_headers);
    log_status(s);
    s = cos_put_bucket_versioning(dst_options, &dst_bucket, versioning, &resp_headers);
    log_status(s);

    cos_replication_params_t *replication_param = NULL;
    replication_param = cos_create_replication_params(p);
    cos_str_set(&replication_param->role, "qcs::cam::uin/100000616666:uin/100000616666");
    
    cos_replication_rule_content_t *rule = NULL;
    rule = cos_create_replication_rule_content(p);
    cos_str_set(&rule->id, "Rule_01");
    cos_str_set(&rule->status, "Enabled");
    cos_str_set(&rule->prefix, "test1");
    cos_str_set(&rule->dst_bucket, "qcs:id/0:cos:cn-east:appid/1253686666:replicationtest");
    cos_list_add_tail(&rule->node, &replication_param->rule_list);

    rule = cos_create_replication_rule_content(p);
    cos_str_set(&rule->id, "Rule_02");
    cos_str_set(&rule->status, "Disabled");
    cos_str_set(&rule->prefix, "test2");
    cos_str_set(&rule->storage_class, "Standard_IA");
    cos_str_set(&rule->dst_bucket, "qcs:id/0:cos:cn-east:appid/1253686666:replicationtest");
    cos_list_add_tail(&rule->node, &replication_param->rule_list);

    rule = cos_create_replication_rule_content(p);
    cos_str_set(&rule->id, "Rule_03");
    cos_str_set(&rule->status, "Enabled");
    cos_str_set(&rule->prefix, "test3");
    cos_str_set(&rule->storage_class, "Standard_IA");
    cos_str_set(&rule->dst_bucket, "qcs:id/0:cos:cn-east:appid/1253686666:replicationtest");
    cos_list_add_tail(&rule->node, &replication_param->rule_list);
    
    //put bucket replication
    s = cos_put_bucket_replication(options, &bucket, replication_param, &resp_headers);
    log_status(s);

    //get bucket replication
    cos_replication_params_t *replication_param2 = NULL;
    replication_param2 = cos_create_replication_params(p);
    s = cos_get_bucket_replication(options, &bucket, replication_param2, &resp_headers);
    log_status(s);
    printf("ReplicationConfiguration role: %s\n", replication_param2->role.data);
    cos_replication_rule_content_t *content = NULL;
    cos_list_for_each_entry(cos_replication_rule_content_t, content, &replication_param2->rule_list, node) {
        printf("ReplicationConfiguration rule, id:%s, status:%s, prefix:%s, dst_bucket:%s, storage_class:%s\n",
                content->id.data, content->status.data, content->prefix.data, content->dst_bucket.data, content->storage_class.data);
    }

    //delete bucket replication
    s = cos_delete_bucket_replication(options, &bucket, &resp_headers);
    log_status(s);

    //disable bucket versioning
    cos_str_set(&versioning->status, "Suspended");
    s = cos_put_bucket_versioning(options, &bucket, versioning, &resp_headers);
    log_status(s);
    s = cos_put_bucket_versioning(dst_options, &dst_bucket, versioning, &resp_headers);
    log_status(s);
    
    cos_pool_destroy(p);

}

void test_presigned_url()
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t presigned_url;
    
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, TEST_OBJECT_NAME1);

    cos_gen_presigned_url(options, &bucket, &object, 300, HTTP_GET, &presigned_url);

    printf("presigned url: %s\n", presigned_url.data);

    cos_pool_destroy(p);
    
}

void test_head_bucket()
{
    cos_pool_t *pool = NULL;
    int is_cname = 0;
    cos_status_t *status = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_table_t *resp_headers = NULL;

    //创建内存池
    cos_pool_create(&pool, NULL);

    //初始化请求选项
    options = cos_request_options_create(pool);
    options->config = cos_config_create(options->pool);

    init_test_request_options(options, is_cname);

    cos_str_set(&bucket, TEST_BUCKET_NAME);
    options->ctl = cos_http_controller_create(options->pool, 0);

    status = cos_head_bucket(options, &bucket, &resp_headers);
    log_status(status);

    cos_pool_destroy(pool);
}

void test_get_service()
{
    cos_pool_t *pool = NULL;
    int is_cname = 0;
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

void test_website()
{
    cos_pool_t *pool = NULL;
    int is_cname = 0;
    cos_status_t *status = NULL;
    cos_request_options_t *options = NULL;
    cos_website_params_t  *website_params = NULL;
    cos_website_params_t  *website_result = NULL;
    cos_website_rule_content_t *website_content = NULL;
    cos_table_t *resp_headers = NULL;
    cos_string_t bucket;

    //创建内存池
    cos_pool_create(&pool, NULL);

    //初始化请求选项
    options = cos_request_options_create(pool);
    options->config = cos_config_create(options->pool);

    init_test_request_options(options, is_cname);
    options->ctl = cos_http_controller_create(options->pool, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);

    //创建website参数
    website_params = cos_create_website_params(options->pool);
    cos_str_set(&website_params->index, "index.html");
    cos_str_set(&website_params->redirect_protocol, "https");
    cos_str_set(&website_params->error_document, "Error.html");

    website_content = cos_create_website_rule_content(options->pool);
    cos_str_set(&website_content->condition_errcode, "404");
    cos_str_set(&website_content->redirect_protocol, "https");
    cos_str_set(&website_content->redirect_replace_key, "404.html");
    cos_list_add_tail(&website_content->node, &website_params->rule_list);

    website_content = cos_create_website_rule_content(options->pool);
    cos_str_set(&website_content->condition_prefix, "docs/");
    cos_str_set(&website_content->redirect_protocol, "https");
    cos_str_set(&website_content->redirect_replace_key_prefix, "documents/");
    cos_list_add_tail(&website_content->node, &website_params->rule_list);

    website_content = cos_create_website_rule_content(options->pool);
    cos_str_set(&website_content->condition_prefix, "img/");
    cos_str_set(&website_content->redirect_protocol, "https");
    cos_str_set(&website_content->redirect_replace_key, "demo.jpg");
    cos_list_add_tail(&website_content->node, &website_params->rule_list);

    status = cos_put_bucket_website(options, &bucket, website_params, &resp_headers);
    log_status(status);

    website_result = cos_create_website_params(options->pool);
    status = cos_get_bucket_website(options, &bucket, website_result, &resp_headers);
    log_status(status);
    if (!cos_status_is_ok(status)) {
        cos_pool_destroy(pool);
        return;
    }

    //查看结果
    cos_website_rule_content_t *content = NULL;
    char *line = NULL;
    line = apr_psprintf(options->pool, "%.*s\n", website_result->index.len, website_result->index.data);
    printf("index: %s", line);
    line = apr_psprintf(options->pool, "%.*s\n", website_result->redirect_protocol.len, website_result->redirect_protocol.data);
    printf("redirect protocol: %s", line);
    line = apr_psprintf(options->pool, "%.*s\n", website_result->error_document.len, website_result->error_document.data);
    printf("error document: %s", line);
    cos_list_for_each_entry(cos_website_rule_content_t, content, &website_result->rule_list, node) {
        line = apr_psprintf(options->pool, "%.*s\t%.*s\t%.*s\t%.*s\t%.*s\n", content->condition_errcode.len, content->condition_errcode.data, content->condition_prefix.len, content->condition_prefix.data, content->redirect_protocol.len, content->redirect_protocol.data, content->redirect_replace_key.len, content->redirect_replace_key.data, content->redirect_replace_key_prefix.len, content->redirect_replace_key_prefix.data);
        printf("%s", line);
    }

    status = cos_delete_bucket_website(options, &bucket, &resp_headers);
    log_status(status); 

    cos_pool_destroy(pool);
}

void test_domain()
{
    cos_pool_t *pool = NULL;
    int is_cname = 0;
    cos_status_t *status = NULL;
    cos_request_options_t *options = NULL;
    cos_domain_params_t  *domain_params = NULL;
    cos_domain_params_t  *domain_result = NULL;
    cos_table_t *resp_headers = NULL;
    cos_string_t bucket;

    //创建内存池
    cos_pool_create(&pool, NULL);

    //初始化请求选项
    options = cos_request_options_create(pool);
    options->config = cos_config_create(options->pool);

    init_test_request_options(options, is_cname);
    options->ctl = cos_http_controller_create(options->pool, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);

    //创建domain参数
    domain_params = cos_create_domain_params(options->pool);
    cos_str_set(&domain_params->status, "ENABLED");
    cos_str_set(&domain_params->name, "www.abc.com");
    cos_str_set(&domain_params->type, "REST");
    cos_str_set(&domain_params->forced_replacement, "CNAME");

    status = cos_put_bucket_domain(options, &bucket, domain_params, &resp_headers);
    log_status(status);

    domain_result = cos_create_domain_params(options->pool);
    status = cos_get_bucket_domain(options, &bucket, domain_result, &resp_headers);
    log_status(status);
    if (!cos_status_is_ok(status)) {
        cos_pool_destroy(pool);
        return;
    }

    //查看结果
    char *line = NULL;
    line = apr_psprintf(options->pool, "%.*s\n", domain_result->status.len, domain_result->status.data);
    printf("status: %s", line);
    line = apr_psprintf(options->pool, "%.*s\n", domain_result->name.len, domain_result->name.data);
    printf("name: %s", line);
    line = apr_psprintf(options->pool, "%.*s\n", domain_result->type.len, domain_result->type.data);
    printf("type: %s", line);
    line = apr_psprintf(options->pool, "%.*s\n", domain_result->forced_replacement.len, domain_result->forced_replacement.data);
    printf("forced_replacement: %s", line);

    cos_pool_destroy(pool);
}

void test_logging()
{
    cos_pool_t *pool = NULL;
    int is_cname = 0;
    cos_status_t *status = NULL;
    cos_request_options_t *options = NULL;
    cos_logging_params_t  *params = NULL;
    cos_logging_params_t  *result = NULL;
    cos_table_t *resp_headers = NULL;
    cos_string_t bucket;

    //创建内存池
    cos_pool_create(&pool, NULL);

    //初始化请求选项
    options = cos_request_options_create(pool);
    options->config = cos_config_create(options->pool);

    init_test_request_options(options, is_cname);
    options->ctl = cos_http_controller_create(options->pool, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);

    //创建logging参数
    params = cos_create_logging_params(options->pool);
    cos_str_set(&params->target_bucket, TEST_BUCKET_NAME);
    cos_str_set(&params->target_prefix, "logging/");

    status = cos_put_bucket_logging(options, &bucket, params, &resp_headers);
    log_status(status);

    result = cos_create_logging_params(options->pool);
    status = cos_get_bucket_logging(options, &bucket, result, &resp_headers);
    log_status(status);
    if (!cos_status_is_ok(status)) {
        cos_pool_destroy(pool);
        return;
    }

    //查看结果
    char *line = NULL;
    line = apr_psprintf(options->pool, "%.*s\n", result->target_bucket.len, result->target_bucket.data);
    printf("target bucket: %s", line);
    line = apr_psprintf(options->pool, "%.*s\n", result->target_prefix.len, result->target_prefix.data);
    printf("target prefix: %s", line);

    cos_pool_destroy(pool);
}

void test_inventory() 
{
    cos_pool_t *pool = NULL;
    int is_cname = 0;
    int inum = 3, i, len;
    char buf[inum][32];
    char dest_bucket[128];
    cos_status_t *status = NULL;
    cos_request_options_t *options = NULL;
    cos_table_t *resp_headers = NULL;
    cos_string_t bucket;
    cos_inventory_params_t *get_params = NULL;
    cos_inventory_optional_t *optional = NULL;
    cos_list_inventory_params_t *list_params = NULL;

    //创建内存池
    cos_pool_create(&pool, NULL);

    //初始化请求选项
    options = cos_request_options_create(pool);
    options->config = cos_config_create(options->pool);

    init_test_request_options(options, is_cname);
    options->ctl = cos_http_controller_create(options->pool, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);

    // put bucket inventory 
    len = snprintf(dest_bucket, 128, "qcs::cos:%s::%s", TEST_REGION, TEST_BUCKET_NAME);
    dest_bucket[len] = 0;
    for (i = 0; i < inum; i++) {
        cos_inventory_params_t *params = cos_create_inventory_params(pool);
        cos_inventory_optional_t *optional;
        len = snprintf(buf[i], 32, "id%d", i);
        buf[i][len] = 0;
        cos_str_set(&params->id, buf[i]);
        cos_str_set(&params->is_enabled, "true");
        cos_str_set(&params->frequency, "Daily");
        cos_str_set(&params->filter_prefix, "myPrefix");
        cos_str_set(&params->included_object_versions, "All");
        cos_str_set(&params->destination.format, "CSV");
        cos_str_set(&params->destination.account_id, TEST_UIN);
        cos_str_set(&params->destination.bucket, dest_bucket);
        cos_str_set(&params->destination.prefix, "invent");
        params->destination.encryption = 1;
        optional = cos_create_inventory_optional(pool);
        cos_str_set(&optional->field, "Size");
        cos_list_add_tail(&optional->node, &params->fields);
        optional = cos_create_inventory_optional(pool);
        cos_str_set(&optional->field, "LastModifiedDate");
        cos_list_add_tail(&optional->node, &params->fields);
        optional = cos_create_inventory_optional(pool);
        cos_str_set(&optional->field, "ETag");
        cos_list_add_tail(&optional->node, &params->fields);
        optional = cos_create_inventory_optional(pool);
        cos_str_set(&optional->field, "StorageClass");
        cos_list_add_tail(&optional->node, &params->fields);
        optional = cos_create_inventory_optional(pool);
        cos_str_set(&optional->field, "ReplicationStatus");
        cos_list_add_tail(&optional->node, &params->fields);

        status = cos_put_bucket_inventory(options, &bucket, params, &resp_headers);
        log_status(status);
    }

    // get inventory 
    get_params = cos_create_inventory_params(pool);
    cos_str_set(&get_params->id, buf[inum/2]);
    status = cos_get_bucket_inventory(options, &bucket, get_params, &resp_headers);
    log_status(status); 

    printf("id: %s\nis_enabled: %s\nfrequency: %s\nfilter_prefix: %s\nincluded_object_versions: %s\n", 
            get_params->id.data, get_params->is_enabled.data, get_params->frequency.data, get_params->filter_prefix.data, get_params->included_object_versions.data);
    printf("destination:\n");
    printf("\tencryption: %d\n", get_params->destination.encryption);
    printf("\tformat: %s\n", get_params->destination.format.data);
    printf("\taccount_id: %s\n", get_params->destination.account_id.data);
    printf("\tbucket: %s\n", get_params->destination.bucket.data);
    printf("\tprefix: %s\n", get_params->destination.prefix.data);
    cos_list_for_each_entry(cos_inventory_optional_t, optional, &get_params->fields, node) {
        printf("field: %s\n", optional->field.data);
    }

    // list inventory
    list_params = cos_create_list_inventory_params(pool); 
    status = cos_list_bucket_inventory(options, &bucket, list_params, &resp_headers);
    log_status(status);

    get_params = NULL;
    cos_list_for_each_entry(cos_inventory_params_t, get_params, &list_params->inventorys, node) {
        printf("id: %s\nis_enabled: %s\nfrequency: %s\nfilter_prefix: %s\nincluded_object_versions: %s\n", 
                get_params->id.data, get_params->is_enabled.data, get_params->frequency.data, get_params->filter_prefix.data, get_params->included_object_versions.data);
        printf("destination:\n");
        printf("\tencryption: %d\n", get_params->destination.encryption);
        printf("\tformat: %s\n", get_params->destination.format.data);
        printf("\taccount_id: %s\n", get_params->destination.account_id.data);
        printf("\tbucket: %s\n", get_params->destination.bucket.data);
        printf("\tprefix: %s\n", get_params->destination.prefix.data);
        cos_list_for_each_entry(cos_inventory_optional_t, optional, &get_params->fields, node) {
            printf("field: %s\n", optional->field.data);
        }
    }

    // delete inventory
    for (i = 0; i < inum; i++) {
        cos_string_t id;
        cos_str_set(&id, buf[i]);
        status = cos_delete_bucket_inventory(options, &bucket, &id, &resp_headers);
        log_status(status);
    }

    cos_pool_destroy(pool);
}

void test_tagging()
{
    cos_pool_t *pool = NULL;
    int is_cname = 0;
    cos_status_t *status = NULL;
    cos_request_options_t *options = NULL;
    cos_table_t *resp_headers = NULL;
    cos_string_t bucket;
    cos_tagging_params_t *params = NULL;
    cos_tagging_params_t *result = NULL;
    cos_tagging_tag_t *tag = NULL;

    //创建内存池
    cos_pool_create(&pool, NULL);

    //初始化请求选项
    options = cos_request_options_create(pool);
    options->config = cos_config_create(options->pool);

    init_test_request_options(options, is_cname);
    options->ctl = cos_http_controller_create(options->pool, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);

    // put tagging
    params = cos_create_tagging_params(pool);
    tag = cos_create_tagging_tag(pool);
    cos_str_set(&tag->key, "age");
    cos_str_set(&tag->value, "18");
    cos_list_add_tail(&tag->node, &params->node);

    tag = cos_create_tagging_tag(pool);
    cos_str_set(&tag->key, "name");
    cos_str_set(&tag->value, "xiaoming");
    cos_list_add_tail(&tag->node, &params->node);

    status = cos_put_bucket_tagging(options, &bucket, params, &resp_headers);
    log_status(status);

    // get tagging
    result = cos_create_tagging_params(pool);
    status = cos_get_bucket_tagging(options, &bucket, result, &resp_headers);
    log_status(status);

    tag = NULL;
    cos_list_for_each_entry(cos_tagging_tag_t, tag, &result->node, node) {
        printf("taging key: %s\n", tag->key.data);
        printf("taging value: %s\n", tag->value.data);

    } 

    // delete tagging
    status = cos_delete_bucket_tagging(options, &bucket, &resp_headers);
    log_status(status);

    cos_pool_destroy(pool);
}

void test_intelligenttiering()
{
    cos_pool_t *pool = NULL;
    int is_cname = 0;
    cos_status_t *status = NULL;
    cos_request_options_t *options = NULL;
    cos_table_t *resp_headers = NULL;
    cos_string_t bucket;
    cos_intelligenttiering_params_t *params = NULL;
    cos_intelligenttiering_params_t *result = NULL;

    //创建内存池
    cos_pool_create(&pool, NULL);

    //初始化请求选项
    options = cos_request_options_create(pool);
    options->config = cos_config_create(options->pool);

    init_test_request_options(options, is_cname);
    options->ctl = cos_http_controller_create(options->pool, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);

    // put intelligenttiering
    params = cos_create_intelligenttiering_params(pool);
    cos_str_set(&params->status, "Enabled");
    params->days = 30; 

    status = cos_put_bucket_intelligenttiering(options, &bucket, params, &resp_headers);
    log_status(status);

    // get intelligenttiering
    result = cos_create_intelligenttiering_params(pool);
    status = cos_get_bucket_intelligenttiering(options, &bucket, result, &resp_headers);
    log_status(status);

    printf("status: %s\n", result->status.data);
    printf("days: %d\n", result->days);
    cos_pool_destroy(pool);
}

void test_directory()
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t file;
    cos_table_t *resp_headers;
    cos_table_t *headers = NULL;
    cos_list_t buffer;
    int is_truncated = 1;
    cos_string_t marker;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "folder/");
    cos_list_init(&buffer);
    s = cos_put_object_from_buffer(options, &bucket, &object, 
                   &buffer, headers, &resp_headers);
    log_status(s);

    cos_str_set(&file, "examplefile");
    cos_str_set(&object, "folder/exampleobject");
    s = cos_put_object_from_file(options, &bucket, &object, &file, NULL, &resp_headers);
    log_status(s);

    //list object (get bucket)
    cos_list_object_params_t *list_params = NULL;
    list_params = cos_create_list_object_params(p);
    cos_str_set(&list_params->encoding_type, "url");
    cos_str_set(&list_params->prefix, "folder/");
    cos_str_set(&marker, "");
    while (is_truncated) {
        list_params->marker = marker;
        s = cos_list_object(options, &bucket, list_params, &resp_headers);
        if (!cos_status_is_ok(s)) {
            printf("list object failed, req_id:%s\n", s->req_id);
            break;
        }
        cos_list_object_content_t *content = NULL;
        char *line = NULL;
        cos_list_for_each_entry(cos_list_object_content_t, content, &list_params->object_list, node) {
            s = cos_delete_object(options, &bucket, &content->key, &resp_headers);
            log_status(s);
            if (!cos_status_is_ok(s)) {
                printf("delete object[%s] failed, req_id:%s\n", content->key.data, s->req_id);
            }
        }
        is_truncated = list_params->truncated;
        marker = list_params->next_marker;
    }
    cos_pool_destroy(p);
}

void test_move()
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
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
    options->config = cos_config_create(options->pool);
    cos_str_set(&options->config->endpoint, TEST_COS_ENDPOINT);
    cos_str_set(&options->config->access_key_id, TEST_ACCESS_KEY_ID);
    cos_str_set(&options->config->access_key_secret, TEST_ACCESS_KEY_SECRET);
    cos_str_set(&options->config->appid, TEST_APPID);
    options->config->is_cname = is_cname;
    options->ctl = cos_http_controller_create(options->pool, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    
    //设置对象复制
    cos_str_set(&object, TEST_OBJECT_NAME1);
    cos_str_set(&src_endpoint, "ap-guangzhou.myqcloud.com");
    cos_str_set(&src_object, TEST_OBJECT_NAME2);
    
    cos_copy_object_params_t *params = NULL;
    params = cos_create_copy_object_params(p);
    s = cos_copy_object(options, &bucket, &src_object, &src_endpoint, &bucket, &object, NULL, params, &resp_headers);
    log_status(s);
    if (cos_status_is_ok(s)) {
        s = cos_delete_object(options, &bucket, &src_object, &resp_headers);
        log_status(s);
        printf("move object succeeded\n");
    } else {
        printf("move object failed\n");
    }

    //销毁内存池
    cos_pool_destroy(p);
}

// 基础图片处理
void test_ci_base_image_process()
{
    cos_pool_t *p = NULL;
    int is_cname = 0; 
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t file;
    cos_table_t *resp_headers;
    cos_table_t *params = NULL;
      
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    options->config = cos_config_create(options->pool);
    cos_str_set(&options->config->endpoint, TEST_COS_ENDPOINT);
    cos_str_set(&options->config->access_key_id, TEST_ACCESS_KEY_ID);
    cos_str_set(&options->config->access_key_secret, TEST_ACCESS_KEY_SECRET);
    cos_str_set(&options->config->appid, TEST_APPID);
    options->config->is_cname = is_cname;
    options->ctl = cos_http_controller_create(options->pool, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);

    params = cos_table_make(p, 1);
    apr_table_addn(params, "imageMogr2/thumbnail/!50p", "");
    cos_str_set(&file, "test.jpg");
    cos_str_set(&object, "test.jpg");
    s = cos_get_object_to_file(options, &bucket, &object, NULL, params, &file, &resp_headers);
    log_status(s);
    if (!cos_status_is_ok(s)) {
        printf("cos_get_object_to_file fail, req_id:%s\n", s->req_id);
    }
    cos_pool_destroy(p);
}

// 持久化处理
void test_ci_image_process()
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t file;
    cos_table_t *resp_headers;
    cos_table_t *headers = NULL;
    cos_table_t *params = NULL;
    ci_operation_result_t *results = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test.jpg");

    // 云上数据处理
    headers = cos_table_make(p, 1);
    apr_table_addn(headers, "pic-operations", "{\"is_pic_info\":1,\"rules\":[{\"fileid\":\"test.png\",\"rule\":\"imageView2/format/png\"}]}");
    s = ci_image_process(options, &bucket, &object, headers, &resp_headers, &results);
    log_status(s);
    printf("origin key: %s\n", results->origin.key.data);
    printf("process key: %s\n", results->object.key.data);

    // 上传时处理
    headers = cos_table_make(p, 1);
    apr_table_addn(headers, "pic-operations", "{\"is_pic_info\":1,\"rules\":[{\"fileid\":\"test.png\",\"rule\":\"imageView2/format/png\"}]}");
    cos_str_set(&file, "test.jpg");
    cos_str_set(&object, "test.jpg");
    s = ci_put_object_from_file(options, &bucket, &object, &file, headers, &resp_headers, &results);
    log_status(s);
    printf("origin key: %s\n", results->origin.key.data);
    printf("process key: %s\n", results->object.key.data);

    cos_pool_destroy(p);
}

// 二维码识别
void test_ci_image_qrcode()
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t file;
    cos_table_t *resp_headers;
    cos_table_t *headers = NULL;
    cos_table_t *params = NULL;
    ci_operation_result_t *results = NULL;
    ci_qrcode_info_t *content = NULL;
    ci_qrcode_result_t *result2 = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test.jpg");
    
    headers = cos_table_make(p, 1);
    apr_table_addn(headers, "pic-operations", "{\"is_pic_info\":1,\"rules\":[{\"fileid\":\"test.png\",\"rule\":\"QRcode/cover/1\"}]}");
    // 上传时识别
    cos_str_set(&file, "test.jpg");
    cos_str_set(&object, "test.jpg");
    s = ci_put_object_from_file(options, &bucket, &object, &file, headers, &resp_headers, &results);
    log_status(s);
    if (!cos_status_is_ok(s)) {
        printf("put object failed\n");
    }
    printf("CodeStatus: %d\n", results->object.code_status);
    cos_list_for_each_entry(ci_qrcode_info_t, content, &results->object.qrcode_info, node) {
        printf("CodeUrl: %s\n", content->code_url.data);
        printf("Point: %s\n", content->point[0].data);
        printf("Point: %s\n", content->point[1].data);
        printf("Point: %s\n", content->point[2].data);
        printf("Point: %s\n", content->point[3].data);
    }

    // 下载时识别
    s = ci_get_qrcode(options, &bucket, &object, 1, NULL, NULL, &resp_headers, &result2);
    log_status(s);
    if (!cos_status_is_ok(s)) {
        printf("get object failed\n");
    }
    printf("CodeStatus: %d\n", result2->code_status);
    cos_list_for_each_entry(ci_qrcode_info_t, content, &result2->qrcode_info, node) {
        printf("CodeUrl: %s\n", content->code_url.data);
        printf("Point: %s\n", content->point[0].data);
        printf("Point: %s\n", content->point[1].data);
        printf("Point: %s\n", content->point[2].data);
        printf("Point: %s\n", content->point[3].data);
    }
    printf("ImageResult: %s\n", result2->result_image.data);

    //销毁内存池
    cos_pool_destroy(p); 
}

// 图片压缩
void test_ci_image_compression()
{
    cos_pool_t *p = NULL;
    int is_cname = 0; 
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t file;
    cos_table_t *resp_headers;
    cos_table_t *params = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    options->config = cos_config_create(options->pool);
    cos_str_set(&options->config->endpoint, TEST_COS_ENDPOINT);
    cos_str_set(&options->config->access_key_id, TEST_ACCESS_KEY_ID);
    cos_str_set(&options->config->access_key_secret, TEST_ACCESS_KEY_SECRET);
    cos_str_set(&options->config->appid, TEST_APPID);
    options->config->is_cname = is_cname;
    options->ctl = cos_http_controller_create(options->pool, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);

    params = cos_table_make(p, 1);
    apr_table_addn(params, "imageMogr2/format/tpg", "");
    cos_str_set(&object, "test.jpg");
    cos_str_set(&file, "test.tpg");
    s = cos_get_object_to_file(options, &bucket, &object, NULL, params, &file, &resp_headers);
    log_status(s);
    if (!cos_status_is_ok(s)) {
        printf("cos_get_object_to_file fail, req_id:%s\n", s->req_id);
    }

    params = cos_table_make(p, 1);
    apr_table_addn(params, "imageMogr2/format/heif", "");
    cos_str_set(&file, "test.heif");
    s = cos_get_object_to_file(options, &bucket, &object, NULL, params, &file, &resp_headers);
    log_status(s);
    if (!cos_status_is_ok(s)) {
        printf("cos_get_object_to_file fail, req_id:%s\n", s->req_id);
    }
}

int main(int argc, char *argv[])
{
    int exit_code = -1;

    // 通过环境变量获取 SECRETID 和 SECRETKEY
    TEST_ACCESS_KEY_ID     = getenv("COS_SECRETID");
    TEST_ACCESS_KEY_SECRET = getenv("COS_SECRETKEY");
 
    if (cos_http_io_initialize(NULL, 0) != COSE_OK) {
       exit(1);
    }

    //set log level, default COS_LOG_WARN
    cos_log_set_level(COS_LOG_WARN);

    //set log output, default stderr
    cos_log_set_output(NULL);

    //test_intelligenttiering();
    //test_tagging();
    //test_logging();
    //test_inventory();
    //test_put_object_from_file_with_sse();
    //test_get_object_to_file_with_sse();
    //test_head_bucket();
    //test_get_service();
    //test_website();
    //test_domain();
    //test_delete_objects();
    //test_delete_objects_by_prefix();
    //test_bucket();
    //test_bucket_lifecycle();
    //test_object_restore();
    //test_put_object_from_file();
    //test_sign();
    //test_object();
    //multipart_upload_file_from_file();
    //multipart_upload_file_from_buffer();
    //abort_multipart_upload();
    //list_multipart();
    
    //pthread_t tid[20];
    //test_resumable_upload_with_multi_threads();
    //test_resumable();
    //test_bucket();
    //test_acl();
    //test_copy();
    //test_modify_storage_class();
    //test_cors();
    //test_versioning();
    //test_replication();
    //test_part_copy();
    //test_copy_with_part_copy();
    //test_move();
    //test_directory();
    //test_ci_base_image_process();
    //test_ci_image_process();
    //test_ci_image_qrcode();
    //test_ci_image_compression();

    //cos_http_io_deinitialize last
    cos_http_io_deinitialize();

    return exit_code;
}

