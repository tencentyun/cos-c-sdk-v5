#include <sys/stat.h>
#include "cos_config.h"
#include "cos_api.h"
#include "cos_test_util.h"

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

cos_buf_t *make_random_buf(cos_pool_t *p, int len)
{
    int bytes;
    cos_buf_t *b;
    cos_string_t str;

    make_rand_string(p, 16, &str);
    b = cos_create_buf(p, len);

    while (b->last < b->end) {
        bytes = b->end - b->last;
        bytes = cos_min(bytes, 16);
        memcpy(b->last, str.data, bytes);
        b->last += bytes;
    }

    return b;
}

void make_random_body(cos_pool_t *p, int count, cos_list_t *bc)
{
    int i = 0;
    int len;
    cos_buf_t *b;

    srand((int)time(0));
    for (; i < count; ++i) {
        len = 1 + (int)(4096.0*rand() / (RAND_MAX+1.0));
        b = make_random_buf(p, len);
        cos_list_add_tail(&b->node, bc);
    }
}
void make_random_body_with_size(cos_pool_t *p, int size, cos_list_t *bc)
{
    int i = 0;
    cos_buf_t *b;

    while (size >0) {
        if (size >= 1024){
            b = make_random_buf(p, 1024);
            size -= 1024;
        }else {
            b = make_random_buf(p, size);
            size = 0;
        }
        cos_list_add_tail(&b->node, bc);
    }
}
int make_random_file(cos_pool_t *p, const char *filename, int len)
{
    apr_file_t *file;
    cos_string_t str;
    apr_size_t nbytes;
    int ret;

    if ((ret = apr_file_open(&file, filename, APR_CREATE | APR_WRITE | APR_TRUNCATE,
        APR_UREAD | APR_UWRITE | APR_GREAD, p)) != APR_SUCCESS) {
            return ret;
    }

    make_rand_string(p, len, &str);
    nbytes = len;

    ret = apr_file_write(file, str.data, &nbytes);
    apr_file_close(file);

    return ret;
}

int fill_test_file(cos_pool_t *p, const char *filename, const char *content) 
{
    apr_file_t *file;
    apr_size_t nbytes;
    int ret;

    if ((ret = apr_file_open(&file, filename, APR_CREATE | APR_WRITE | APR_TRUNCATE,
        APR_UREAD | APR_UWRITE | APR_GREAD, p)) != APR_SUCCESS) {
            return ret;
    }

    nbytes = strlen(content);

    ret = apr_file_write(file, content, &nbytes);
    apr_file_close(file);

    return ret;
}

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

cos_status_t * create_test_bucket(const cos_request_options_t *options,
                                  const char *bucket_name, 
                                  cos_acl_e cos_acl)
{
    cos_string_t bucket;
    cos_table_t *resp_headers;
    cos_status_t * s;

    cos_str_set(&bucket, bucket_name);

    s = cos_create_bucket(options, &bucket, cos_acl, &resp_headers);
    return s;
}

cos_status_t *create_test_object(const cos_request_options_t *options, 
                                 const char *bucket_name, 
                                 const char *object_name, 
                                 const char *data, 
                                 cos_table_t *headers)
{
    cos_string_t bucket;
    cos_string_t object;
    cos_table_t *resp_headers;
    cos_list_t buffer;
    cos_buf_t *content;
    cos_status_t * s;

    test_object_base();
    cos_list_init(&buffer);
    content = cos_buf_pack(options->pool, data, strlen(data));
    cos_list_add_tail(&content->node, &buffer);

    s = cos_put_object_from_buffer(options, &bucket, &object, 
                                   &buffer, headers, &resp_headers);
    return s;
}

cos_status_t *create_test_object_from_file(const cos_request_options_t *options, 
                                          const char *bucket_name,
                                          const char *object_name, 
                                          const char *filename, 
                                          cos_table_t *headers)
{
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t file;
    cos_table_t *resp_headers;
    cos_status_t * s;

    test_object_base();
    cos_str_set(&file, filename);

    s = cos_put_object_from_file(options, &bucket, &object, &file, 
                                 headers, &resp_headers);
    return s;
}

cos_status_t *delete_test_object(const cos_request_options_t *options, 
                                 const char *bucket_name, 
                                 const char *object_name)
{
    cos_string_t bucket;
    cos_string_t object;
    cos_table_t *resp_headers;
    cos_status_t * s;

    test_object_base();
    s = cos_delete_object(options, &bucket, &object, &resp_headers);
    return s;
}

cos_status_t *init_test_multipart_upload(const cos_request_options_t *options, 
                                         const char *bucket_name, 
                                         const char *object_name, 
                                         cos_string_t *upload_id)
{
    cos_string_t bucket;
    cos_string_t object;
    cos_table_t *headers;
    cos_table_t *resp_headers;
    cos_status_t *s;

    test_object_base();
    headers = cos_table_make(options->pool, 5);

    s = cos_init_multipart_upload(options, &bucket, &object, 
                                  upload_id, headers, &resp_headers);

    return s;
}

cos_status_t *abort_test_multipart_upload(const cos_request_options_t *options, 
                                          const char *bucket_name, 
                                          const char *object_name, 
                                          cos_string_t *upload_id)
{
    cos_string_t bucket;
    cos_string_t object;
    cos_table_t *resp_headers;
    cos_status_t *s;

    test_object_base();
    s = cos_abort_multipart_upload(options, &bucket, &object, upload_id, 
                                   &resp_headers);

    return s;
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

char *decrypt(const char *encrypted_str, cos_pool_t *pool)
{
    char *res_str = NULL;
    int i = 0;

    if (encrypted_str == NULL) {
        return NULL;
    }

    res_str =  (char *)cos_palloc(pool, strlen(encrypted_str) + 1);

    while (*encrypted_str != '\0') {
        res_str[i] = 0x6a ^ *encrypted_str;
        encrypted_str++;
        i++;
    }
    res_str[i] = '\0';

    return res_str;
}

void progress_callback(int64_t consumed_bytes, int64_t total_bytes) 
{
    assert(total_bytes >= consumed_bytes);  
}

void percentage(int64_t consumed_bytes, int64_t total_bytes) 
{
    assert(total_bytes >= consumed_bytes);
}
