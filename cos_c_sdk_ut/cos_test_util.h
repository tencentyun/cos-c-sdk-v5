#ifndef COS_TEST_UTIL_H
#define COS_TEST_UTIL_H

#include "CuTest.h"
#include "cos_http_io.h"
#include "cos_string.h"
#include "cos_transport.h"
#include "cos_status.h"
#include "cos_define.h"

COS_CPP_START

#define test_object_base() do {                                         \
        cos_str_set(&bucket, bucket_name);                              \
        cos_str_set(&object, object_name);                              \
    } while(0)

void make_rand_string(cos_pool_t *p, int len, cos_string_t *data);

cos_buf_t *make_random_buf(cos_pool_t *p, int len);

void make_random_body(cos_pool_t *p, int count, cos_list_t *bc);

int make_random_file(cos_pool_t *p, const char *filename, int len);

int fill_test_file(cos_pool_t *p, const char *filename, const char *content);

void init_test_config(cos_config_t *config, int is_cname);

void init_test_request_options(cos_request_options_t *options, int is_cname);

cos_status_t * create_test_bucket(const cos_request_options_t *options,
    const char *bucket_name, cos_acl_e cos_acl);

cos_status_t *create_test_object(const cos_request_options_t *options, const char *bucket_name, 
    const char *object_name, const char *data, cos_table_t *headers);

cos_status_t *create_test_object_from_file(const cos_request_options_t *options, const char *bucket_name,
    const char *object_name, const char *filename, cos_table_t *headers);

cos_status_t *delete_test_object(const cos_request_options_t *options,
    const char *bucket_name, const char *object_name);

cos_status_t *init_test_multipart_upload(const cos_request_options_t *options, const char *bucket_name, 
    const char *object_name, cos_string_t *upload_id);

cos_status_t *abort_test_multipart_upload(const cos_request_options_t *options, const char *bucket_name,
    const char *object_name, cos_string_t *upload_id);

unsigned long get_file_size(const char *file_path);

char *decrypt(const char *encrypted_str, cos_pool_t *pool);

void percentage(int64_t consumed_bytes, int64_t total_bytes);
void progress_callback(int64_t consumed_bytes, int64_t total_bytes);

COS_CPP_END

#endif
