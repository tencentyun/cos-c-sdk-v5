#include "CuTest.h"
#include "cos_log.h"
#include "cos_sys_util.h"
#include "cos_string.h"
#include "cos_status.h"
#include "cos_transport.h"
#include "cos_http_io.h"
#include "cos_auth.h"
#include "cos_utility.h"
#include "cos_xml.h"
#include "cos_api.h"
#include "cos_config.h"
#include "cos_test_util.h"

extern cos_status_t *cos_get_sorted_uploaded_part(cos_request_options_t *options,
                                           const cos_string_t *bucket, 
                                           const cos_string_t *object, 
                                           const cos_string_t *upload_id, 
                                           cos_list_t *complete_part_list, 
                                           int *part_count);



void test_multipart_setup(CuTest *tc)
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_acl_e cos_acl = COS_ACL_PRIVATE;

    //create test bucket
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    s = create_test_bucket(options, TEST_BUCKET_NAME, cos_acl);

    CuAssertIntEquals(tc, 200, s->code);

    cos_pool_destroy(p);
}

void test_multipart_cleanup(CuTest *tc)
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_string_t bucket;
    cos_request_options_t *options = NULL;
    char *object_name = "cos_test_multipart_upload";
    char *object_name1 = "cos_test_multipart_upload_from_file";
    char *object_name2 = "cos_test_upload_part_copy_dest_object";
    char *object_name3 = "cos_test_upload_part_copy_source_object";
    char *object_name4 = "cos_test_list_upload_part_with_empty";
    char *object_name5 = "test_cos_get_sorted_uploaded_part";
    char *object_name6 = "test_cos_get_sorted_uploaded_part_with_empty";
    cos_table_t *resp_headers = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);

    //delete test object
    delete_test_object(options, TEST_BUCKET_NAME, object_name);
    delete_test_object(options, TEST_BUCKET_NAME, object_name1);
    delete_test_object(options, TEST_BUCKET_NAME, object_name2);
    delete_test_object(options, TEST_BUCKET_NAME, object_name3);
    delete_test_object(options, TEST_BUCKET_NAME, object_name4);
    delete_test_object(options, TEST_BUCKET_NAME, object_name5);
    delete_test_object(options, TEST_BUCKET_NAME, object_name6);

    //delete test bucket
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_delete_bucket(options, &bucket, &resp_headers);
    apr_sleep(apr_time_from_sec(3));

    cos_pool_destroy(p);
}

void test_init_abort_multipart_upload(CuTest *tc)
{
    cos_pool_t *p = NULL;
    char *object_name = "cos_test_abort_multipart_upload";
    cos_request_options_t *options = NULL;
    int is_cname = 0;
    cos_string_t upload_id;
    cos_status_t *s = NULL;

    //test init multipart
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    s = init_test_multipart_upload(options, TEST_BUCKET_NAME, object_name, &upload_id);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertTrue(tc, upload_id.len > 0);
    CuAssertPtrNotNull(tc, upload_id.data);

    //abort multipart
    s = abort_test_multipart_upload(options, TEST_BUCKET_NAME, object_name, &upload_id);
    CuAssertIntEquals(tc, 200, s->code);

    cos_pool_destroy(p);

    printf("test_init_abort_multipart_upload ok\n");
}

void test_list_multipart_upload(CuTest *tc)
{
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    char *object_name1 = "cos_test_abort_multipart_upload1";
    char *object_name2 = "cos_test_abort_multipart_upload2";
    int is_cname = 0;
    cos_request_options_t *options = NULL;
    cos_string_t upload_id1;
    cos_string_t upload_id2;
    cos_status_t *s = NULL;
    cos_table_t *resp_headers;
    cos_list_multipart_upload_params_t *params = NULL;
    char *expect_next_key_marker = "cos_test_abort_multipart_upload1";

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    s = init_test_multipart_upload(options, TEST_BUCKET_NAME, object_name1, &upload_id1);
    CuAssertIntEquals(tc, 200, s->code);

    s = init_test_multipart_upload(options, TEST_BUCKET_NAME, object_name2, &upload_id2);
    CuAssertIntEquals(tc, 200, s->code);

    params = cos_create_list_multipart_upload_params(p);
    params->max_ret = 1;
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    s = cos_list_multipart_upload(options, &bucket, params, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertIntEquals(tc, 1, params->truncated);
    CuAssertStrEquals(tc, expect_next_key_marker, params->next_key_marker.data);
    CuAssertPtrNotNull(tc, resp_headers);

    cos_list_init(&params->upload_list);
    cos_str_set(&params->key_marker, params->next_key_marker.data);
    cos_str_set(&params->upload_id_marker, params->next_upload_id_marker.data);

    s = cos_list_multipart_upload(options, &bucket, params, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    //CuAssertIntEquals(tc, 0, params->truncated);

    s = abort_test_multipart_upload(options, TEST_BUCKET_NAME, object_name1, &upload_id1);
    CuAssertIntEquals(tc, 200, s->code);
    s = abort_test_multipart_upload(options, TEST_BUCKET_NAME, object_name2, &upload_id2);
    CuAssertIntEquals(tc, 200, s->code);
    cos_pool_destroy(p);

    printf("test_list_multipart_upload ok\n");    
}

void test_multipart_upload(CuTest *tc)
{
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    char *object_name = "cos_test_multipart_upload";
    cos_string_t object;
    int is_cname = 0;
    cos_request_options_t *options = NULL;
    cos_status_t *s = NULL;
    cos_list_t buffer;
    cos_table_t *headers = NULL;
    cos_table_t *upload_part_resp_headers = NULL;
    cos_list_upload_part_params_t *params = NULL;
    cos_table_t *list_part_resp_headers = NULL;
    cos_string_t upload_id;
    cos_list_t complete_part_list;
    cos_list_part_content_t *part_content1 = NULL;
    cos_list_part_content_t *part_content2 = NULL;
    cos_complete_part_content_t *complete_content1 = NULL;
    cos_complete_part_content_t *complete_content2 = NULL;
    cos_table_t *complete_resp_headers = NULL;
    cos_table_t *head_resp_headers = NULL;
    int part_num = 1;
    int part_num1 = 2;
    char *expect_part_num_marker = "1";

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);

    headers = cos_table_make(options->pool, 2);

    //init mulitipart
    s = init_test_multipart_upload(options, TEST_BUCKET_NAME, object_name, &upload_id);
    CuAssertIntEquals(tc, 200, s->code);

    //upload part
    cos_list_init(&buffer);
    make_random_body(p, 1000, &buffer);

    s = cos_upload_part_from_buffer(options, &bucket, &object, &upload_id,
        part_num, &buffer, &upload_part_resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, upload_part_resp_headers);

    cos_list_init(&buffer);
    make_random_body(p, 1000, &buffer);
    s = cos_upload_part_from_buffer(options, &bucket, &object, &upload_id,
        part_num1, &buffer, &upload_part_resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, upload_part_resp_headers);

    //list part
    params = cos_create_list_upload_part_params(p);
    params->max_ret = 1;
    cos_list_init(&complete_part_list);

    s = cos_list_upload_part(options, &bucket, &object, &upload_id, 
                             params, &list_part_resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertIntEquals(tc, 1, params->truncated);
    CuAssertStrEquals(tc, expect_part_num_marker, 
                      params->next_part_number_marker.data);
    CuAssertPtrNotNull(tc, list_part_resp_headers);

    cos_list_for_each_entry(cos_list_part_content_t, part_content1, &params->part_list, node) {
        complete_content1 = cos_create_complete_part_content(p);
        cos_str_set(&complete_content1->part_number, part_content1->part_number.data);
        cos_str_set(&complete_content1->etag, part_content1->etag.data);
        cos_list_add_tail(&complete_content1->node, &complete_part_list);
    }

    cos_list_init(&params->part_list);
    cos_str_set(&params->part_number_marker, params->next_part_number_marker.data);
    s = cos_list_upload_part(options, &bucket, &object, &upload_id, params, &list_part_resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    //CuAssertIntEquals(tc, 0, params->truncated);
    CuAssertPtrNotNull(tc, list_part_resp_headers);

    cos_list_for_each_entry(cos_list_part_content_t, part_content2, &params->part_list, node) {
        complete_content2 = cos_create_complete_part_content(p);
        cos_str_set(&complete_content2->part_number, part_content2->part_number.data);
        cos_str_set(&complete_content2->etag, part_content2->etag.data);
        cos_list_add_tail(&complete_content2->node, &complete_part_list);
    }

    //complete multipart
    s = cos_complete_multipart_upload(options, &bucket, &object, &upload_id,
            &complete_part_list, headers, &complete_resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, complete_resp_headers);
    
    //check content type
    apr_table_clear(headers);
    s = cos_head_object(options, &bucket, &object, headers, &head_resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, head_resp_headers);

    cos_pool_destroy(p);

    printf("test_multipart_upload ok\n");
}

void test_multipart_upload_from_file(CuTest *tc)
{
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    char *object_name = "cos_test_multipart_upload_from_file";
    char *file_path = "test_upload_part_copy.file";
    FILE* fd = NULL;
    cos_string_t object;
    int is_cname = 0;
    cos_request_options_t *options = NULL;
    cos_status_t *s = NULL;
    cos_upload_file_t *upload_file = NULL;
    cos_table_t *upload_part_resp_headers = NULL;
    cos_list_upload_part_params_t *params = NULL;
    cos_table_t *list_part_resp_headers = NULL;
    cos_string_t upload_id;
    cos_list_t complete_part_list;
    cos_list_part_content_t *part_content1 = NULL;
    cos_complete_part_content_t *complete_content1 = NULL;
    cos_table_t *complete_resp_headers = NULL;
    cos_string_t data;
    int part_num = 1;
    int part_num1 = 2;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);

    // create multipart upload local file    
    make_rand_string(p, 1024 * 1024, &data);
    fd = fopen(file_path, "w");
    CuAssertTrue(tc, fd != NULL);
    fwrite(data.data, sizeof(data.data[0]), data.len, fd);
    fclose(fd);

    //init mulitipart
    s = init_test_multipart_upload(options, TEST_BUCKET_NAME, object_name, &upload_id);
    CuAssertIntEquals(tc, 200, s->code);

    //upload part from file
    upload_file = cos_create_upload_file(p);
    cos_str_set(&upload_file->filename, file_path);
    upload_file->file_pos = 0;
    upload_file->file_last = 512 * 1024; //200k
    
    s = cos_upload_part_from_file(options, &bucket, &object, &upload_id,
        part_num, upload_file, &upload_part_resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, upload_part_resp_headers);
    
    upload_file->file_pos = 512 *1024;//remain content start pos
    upload_file->file_last = get_file_size(file_path);
    
    s = cos_upload_part_from_file(options, &bucket, &object, &upload_id,
        part_num1, upload_file, &upload_part_resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, upload_part_resp_headers);
    
    //list part
    params = cos_create_list_upload_part_params(p);
    cos_str_set(&params->part_number_marker, "");
    params->max_ret = 10;
    params->truncated = 0;
    cos_list_init(&complete_part_list);
    
    s = cos_list_upload_part(options, &bucket, &object, &upload_id, params, &list_part_resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertIntEquals(tc, 0, params->truncated);
    CuAssertPtrNotNull(tc, list_part_resp_headers);

    cos_list_for_each_entry(cos_list_part_content_t, part_content1, &params->part_list, node) {
        complete_content1 = cos_create_complete_part_content(p);
        cos_str_set(&complete_content1->part_number, part_content1->part_number.data);
        cos_str_set(&complete_content1->etag, part_content1->etag.data);
        cos_list_add_tail(&complete_content1->node, &complete_part_list);
    }

    //complete multipart
    s = cos_complete_multipart_upload(options, &bucket, &object, &upload_id,
            &complete_part_list, NULL, &complete_resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, complete_resp_headers);

    remove(file_path);
    cos_pool_destroy(p);

    printf("test_multipart_upload_from_file ok\n");
}

void test_upload_part_copy(CuTest *tc)
{
    cos_pool_t *p = NULL;
    cos_request_options_t *options = NULL;
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
    CuAssertTrue(tc, fd != NULL);
    fwrite(data.data, sizeof(data.data[0]), data.len, fd);
    fclose(fd);    

    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 0);
    s = create_test_object_from_file(options, TEST_BUCKET_NAME, source_object_name, 
        local_filename, headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, headers);

    //init mulitipart
    s = init_test_multipart_upload(options, TEST_BUCKET_NAME, dest_object_name, &upload_id);
    CuAssertIntEquals(tc, 200, s->code);

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
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, resp_headers);

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
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, resp_headers);

    //list part
    list_upload_part_params = cos_create_list_upload_part_params(p);
    list_upload_part_params->max_ret = 10;
    cos_list_init(&complete_part_list);
        
    cos_str_set(&dest_bucket, TEST_BUCKET_NAME);
    cos_str_set(&dest_object, dest_object_name);
    s = cos_list_upload_part(options, &dest_bucket, &dest_object, &upload_id, 
                             list_upload_part_params, &list_part_resp_headers);

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
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, complete_resp_headers);

    //check upload copy part content equal to local file
    headers = cos_table_make(p, 0);
    cos_str_set(&download_file, download_filename);
    s = cos_get_object_to_file(options, &dest_bucket, &dest_object, headers, 
                               query_params, &download_file, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertIntEquals(tc, get_file_size(local_filename), get_file_size(download_filename));    
    CuAssertPtrNotNull(tc, resp_headers);

    remove(download_filename);
    remove(local_filename);
    cos_pool_destroy(p);

    printf("test_upload_part_copy ok\n");
}

void test_upload_file_failed_without_uploadid(CuTest *tc) 
{
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    char *object_name = "cos_test_multipart_upload_from_file";
    cos_string_t object; 
    int is_cname = 0; 
    cos_request_options_t *options = NULL;
    cos_status_t *s = NULL;
    int part_size = 100*1024;
    cos_string_t upload_id;
    cos_string_t filepath;
    
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, "invalid_bucket");
    cos_str_set(&object, object_name);
    cos_str_null(&upload_id);
    cos_str_set(&filepath, __FILE__);
    s = cos_upload_file(options, &bucket, &object, &upload_id, &filepath, 
                        part_size, NULL);
    CuAssertIntEquals(tc, 400, s->code);

    cos_pool_destroy(p);

    printf("test_upload_file_failed_without_uploadid ok\n");
}

void test_upload_file(CuTest *tc) 
{
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    char *object_name = "cos_test_multipart_upload_from_file";
    cos_string_t object; 
    int is_cname = 0; 
    cos_request_options_t *options = NULL;
    cos_status_t *s = NULL;
    int part_size = 100 * 1024;
    cos_string_t upload_id;
    cos_string_t filepath;
    
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_str_null(&upload_id);
    cos_str_set(&filepath, __FILE__);
    s = cos_upload_file(options, &bucket, &object, &upload_id, &filepath, 
                        part_size, NULL);
    CuAssertIntEquals(tc, 200, s->code);

    cos_pool_destroy(p);

    printf("test_upload_file ok\n");
}


void test_upload_file_from_recover(CuTest *tc) 
{
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    char *object_name = "cos_test_multipart_upload_from_file";
    cos_string_t object; 
    int is_cname = 0; 
    cos_request_options_t *options = NULL;
    cos_status_t *s = NULL;
    int part_size = 100*1024;
    cos_string_t upload_id;
    cos_string_t filepath;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);

    //init mulitipart
    s = init_test_multipart_upload(options, TEST_BUCKET_NAME, 
                                   object_name, &upload_id);
    CuAssertIntEquals(tc, 200, s->code);
    
    cos_str_set(&filepath, __FILE__);
    s = cos_upload_file(options, &bucket, &object, &upload_id, &filepath, 
                        part_size, NULL);
    CuAssertIntEquals(tc, 200, s->code);

    cos_pool_destroy(p);

    printf("test_upload_file_from_recover ok\n");
}

void test_upload_file_from_recover_failed(CuTest *tc) 
{
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    char *object_name = "cos_test_multipart_upload_from_file";
    cos_string_t object; 
    int is_cname = 0; 
    cos_request_options_t *options = NULL;
    cos_status_t *s = NULL;
    int part_size = 100*1024;
    cos_string_t upload_id;
    cos_string_t filepath;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);

    //init mulitipart
    s = init_test_multipart_upload(options, TEST_BUCKET_NAME, 
                                   object_name, &upload_id);
    CuAssertIntEquals(tc, 200, s->code);
    
    cos_str_set(&filepath, __FILE__);
    cos_str_set(&bucket, "invalid_bucket");
    s = cos_upload_file(options, &bucket, &object, &upload_id, &filepath, 
                        part_size, NULL);
    CuAssertIntEquals(tc, 404, s->code);

    //abort multipart
    s = abort_test_multipart_upload(options, TEST_BUCKET_NAME,
                                    object_name, &upload_id);
    CuAssertIntEquals(tc, 200, s->code);

    cos_pool_destroy(p);

    printf("test_upload_file_from_recover_failed ok\n");
}

void test_list_upload_part_with_empty(CuTest *tc)
{
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    char *object_name = "cos_test_list_upload_part_with_empty";
    cos_string_t object;
    int is_cname = 0;
    cos_request_options_t *options = NULL;
    cos_status_t *s = NULL;
    cos_table_t *headers = NULL;
    cos_list_upload_part_params_t *params = NULL;
    cos_table_t *list_part_resp_headers = NULL;
    cos_string_t upload_id;
    cos_list_t complete_part_list;
    cos_table_t *complete_resp_headers = NULL;
    char *content_type_for_complete = "video/MP2T";
    cos_list_part_content_t *part_content1 = NULL;
    cos_complete_part_content_t *complete_content1 = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);

    headers = cos_table_make(options->pool, 2);

    //init mulitipart
    s = init_test_multipart_upload(options, TEST_BUCKET_NAME, object_name, &upload_id);
    CuAssertIntEquals(tc, 200, s->code);

    //list part
    params = cos_create_list_upload_part_params(p);
    params->max_ret = 1;
    cos_list_init(&complete_part_list);

    s = cos_list_upload_part(options, &bucket, &object, &upload_id, 
                             params, &list_part_resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertIntEquals(tc, 0, params->truncated);
    CuAssertStrEquals(tc, NULL, params->next_part_number_marker.data);
    CuAssertPtrNotNull(tc, list_part_resp_headers);

    // test for #COS-1161
    cos_list_for_each_entry(cos_list_part_content_t, part_content1, &params->part_list, node) {
        complete_content1 = cos_create_complete_part_content(p);
        cos_str_set(&complete_content1->part_number, part_content1->part_number.data);
        cos_str_set(&complete_content1->etag, part_content1->etag.data);
        cos_list_add_tail(&complete_content1->node, &complete_part_list);
    }

    //complete multipart
    apr_table_add(headers, COS_CONTENT_TYPE, content_type_for_complete);
    s = cos_complete_multipart_upload(options, &bucket, &object, &upload_id,
            &complete_part_list, headers, &complete_resp_headers);
    CuAssertIntEquals(tc, 400, s->code);
    CuAssertPtrNotNull(tc, complete_resp_headers);

    delete_test_object(options, TEST_BUCKET_NAME, object_name);

    cos_pool_destroy(p);

    printf("test_list_upload_part_with_empty ok\n");
}

void test_cos_get_sorted_uploaded_part(CuTest *tc)
{
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    char *object_name = "test_cos_get_sorted_uploaded_part";
    cos_string_t object;
    int is_cname = 0;
    cos_request_options_t *options = NULL;
    cos_status_t *s = NULL;
    cos_list_t buffer;
    cos_table_t *headers = NULL;
    cos_table_t *upload_part_resp_headers = NULL;
    cos_string_t upload_id;
    cos_list_t complete_part_list;
    cos_table_t *complete_resp_headers = NULL;
    int part_num = 1;
    int part_num1 = 2;
    int part_count = 0;
    char *content_type_for_complete = "video/MP2T";

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);

    //init mulitipart
    s = init_test_multipart_upload(options, TEST_BUCKET_NAME, 
                                   object_name, &upload_id);
    CuAssertIntEquals(tc, 200, s->code);

    //upload part
    cos_list_init(&buffer);
    make_random_body(p, 10, &buffer);

    s = cos_upload_part_from_buffer(options, &bucket, &object, &upload_id,
        part_num, &buffer, &upload_part_resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, upload_part_resp_headers);

    cos_list_init(&buffer);
    make_random_body(p, 10, &buffer);
    s = cos_upload_part_from_buffer(options, &bucket, &object, &upload_id,
        part_num1, &buffer, &upload_part_resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, upload_part_resp_headers);

    //get sorted uploaded part
    cos_list_init(&complete_part_list);

    s = cos_get_sorted_uploaded_part(options, &bucket, &object, 
            &upload_id, &complete_part_list, &part_count);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertIntEquals(tc, 2, part_count);

    //complete multipart
    headers = cos_table_make(options->pool, 1);
    apr_table_add(headers, COS_CONTENT_TYPE, content_type_for_complete);
    s = cos_complete_multipart_upload(options, &bucket, &object, &upload_id,
            &complete_part_list, headers, &complete_resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, complete_resp_headers);

    delete_test_object(options, TEST_BUCKET_NAME, object_name);
    cos_pool_destroy(p);

    printf("test_cos_get_sorted_uploaded_part ok\n");
}

void test_cos_get_sorted_uploaded_part_with_empty(CuTest *tc)
{
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    char *object_name = "test_cos_get_sorted_uploaded_part_with_empty";
    cos_string_t object;
    int is_cname = 0;
    cos_request_options_t *options = NULL;
    cos_status_t *s = NULL;
    cos_string_t upload_id;
    cos_list_t complete_part_list;
    int part_count = 0;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);

    //init mulitipart
    s = init_test_multipart_upload(options, TEST_BUCKET_NAME, 
                                   object_name, &upload_id);
    CuAssertIntEquals(tc, 200, s->code);

    //get sorted uploaded part
    cos_list_init(&complete_part_list);

    s = cos_get_sorted_uploaded_part(options, &bucket, &object, &upload_id,
            &complete_part_list, &part_count);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertIntEquals(tc, 0, part_count);

    //abort multipart
    s = abort_test_multipart_upload(options, TEST_BUCKET_NAME,
                                    object_name, &upload_id);
    CuAssertIntEquals(tc, 200, s->code);

    delete_test_object(options, TEST_BUCKET_NAME, object_name);
    cos_pool_destroy(p);

    printf("test_cos_get_sorted_uploaded_part_with_empty ok\n");
}

CuSuite *test_cos_multipart()
{
    CuSuite* suite = CuSuiteNew();

    SUITE_ADD_TEST(suite, test_multipart_setup);
    SUITE_ADD_TEST(suite, test_init_abort_multipart_upload);
    SUITE_ADD_TEST(suite, test_list_multipart_upload);
    SUITE_ADD_TEST(suite, test_multipart_upload);
    SUITE_ADD_TEST(suite, test_multipart_upload_from_file);
    SUITE_ADD_TEST(suite, test_upload_file);
    SUITE_ADD_TEST(suite, test_upload_file_failed_without_uploadid);
    SUITE_ADD_TEST(suite, test_upload_file_from_recover);
    SUITE_ADD_TEST(suite, test_upload_file_from_recover_failed);
    SUITE_ADD_TEST(suite, test_list_upload_part_with_empty);
    SUITE_ADD_TEST(suite, test_cos_get_sorted_uploaded_part);
    SUITE_ADD_TEST(suite, test_cos_get_sorted_uploaded_part_with_empty);
    SUITE_ADD_TEST(suite, test_multipart_cleanup);

    return suite;
}
