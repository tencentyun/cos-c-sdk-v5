#include "CuTest.h"
#include "cos_log.h"
#include "cos_sys_util.h"
#include "cos_string.h"
#include "cos_status.h"
#include "cos_auth.h"
#include "cos_utility.h"
#include "cos_xml.h"
#include "cos_api.h"
#include "cos_config.h"
#include "cos_test_util.h"
#include "cos_crc64.h"

#if defined(WIN32)
static char *test_local_file = "..\\cos_c_sdk_ut\\BingWallpaper-2017-01-19.jpg";
#else
static char *test_local_file = "../../../cos_c_sdk_ut/BingWallpaper-2017-01-19.jpg";
#endif

void test_resumable_setup(CuTest *tc)
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_acl_e cos_acl = COS_ACL_PRIVATE;

    /* create test bucket */
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    s = create_test_bucket(options, TEST_BUCKET_NAME, cos_acl);

    CuAssertIntEquals(tc, 200, s->code);
    cos_pool_destroy(p);
}

void test_resumable_cleanup(CuTest *tc)
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_string_t bucket;
    cos_request_options_t *options = NULL;
    cos_table_t *resp_headers = NULL;
    cos_status_t *s = NULL;
    cos_string_t prefix;
    char *prefix_str = "";

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    
    /* delete test object */
    cos_str_set(&prefix, prefix_str);
    s = cos_delete_objects_by_prefix(options, &bucket, &prefix);
    printf("delete all objects, status code=%d\n", s->code);
    
    /* delete test bucket */
    cos_delete_bucket(options, &bucket, &resp_headers);
    apr_sleep(apr_time_from_sec(3));

    cos_pool_destroy(p);
}

// ---------------------------- UT ----------------------------

void test_resumable_cos_get_thread_num(CuTest *tc)
{
    cos_pool_t *p = NULL;
    cos_resumable_clt_params_t *clt_params;
    int32_t thread_num = 0;

    cos_pool_create(&p, NULL);
    
    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 100, 1024, COS_FALSE, NULL);
    thread_num = cos_get_thread_num(clt_params);
    CuAssertIntEquals(tc, 1024, thread_num);

    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 100, 0, COS_FALSE, NULL);
    thread_num = cos_get_thread_num(clt_params);
    CuAssertIntEquals(tc, 1, thread_num);

    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 100, -1, COS_FALSE, NULL);
    thread_num = cos_get_thread_num(clt_params);
    CuAssertIntEquals(tc, 1, thread_num);

    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 100, 1025, COS_FALSE, NULL);
    thread_num = cos_get_thread_num(clt_params);
    CuAssertIntEquals(tc, 1, thread_num);

    cos_pool_destroy(p);

    printf("test_resumable_cos_get_thread_num ok\n");
}

void test_resumable_cos_get_checkpoint_path(CuTest *tc)
{
    cos_pool_t *p = NULL;
    cos_resumable_clt_params_t *clt_params;
    cos_string_t file_path = cos_null_string;
    cos_string_t checkpoint_path = cos_null_string;

    cos_pool_create(&p, NULL);

    cos_str_set(&file_path, "D:\\work\\cos\\BingWallpaper-2017-01-19.jpg");
    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 100, 1024, COS_FALSE, NULL);
    cos_get_checkpoint_path(clt_params, &file_path, p, &checkpoint_path);
    CuAssertTrue(tc, checkpoint_path.data == NULL);
    CuAssertTrue(tc, checkpoint_path.len == 0);

    cos_str_set(&checkpoint_path, "BingWallpaper-2017-01-19.jpg.ucp");
    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 100, 1024, COS_TRUE, checkpoint_path.data);
    cos_get_checkpoint_path(clt_params, &file_path, p, &checkpoint_path);
    CuAssertStrEquals(tc, "BingWallpaper-2017-01-19.jpg.ucp", checkpoint_path.data);

    // win path
    cos_str_set(&file_path, "D:\\work\\cos\\BingWallpaper-2017-01-19.jpg");
    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 100, 1024, COS_TRUE, NULL);
    cos_get_checkpoint_path(clt_params, &file_path, p, &checkpoint_path);
    CuAssertStrEquals(tc, "D:\\work\\cos\\BingWallpaper-2017-01-19.jpg.cp", checkpoint_path.data);

    cos_str_set(&checkpoint_path, "");
    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 100, 1024, COS_TRUE, NULL);
    cos_get_checkpoint_path(clt_params, &file_path, p, &checkpoint_path);
    CuAssertStrEquals(tc, "D:\\work\\cos\\BingWallpaper-2017-01-19.jpg.cp", checkpoint_path.data);

    // linux path
    cos_str_set(&file_path, "/home/tim/work/cos/BingWallpaper-2017-01-19.jpg");
    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 100, 1024, COS_TRUE, NULL);
    cos_get_checkpoint_path(clt_params, &file_path, p, &checkpoint_path);
    CuAssertStrEquals(tc, "/home/tim/work/cos/BingWallpaper-2017-01-19.jpg.cp", checkpoint_path.data);

    cos_str_set(&checkpoint_path, "");
    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 100, 1024, COS_TRUE, NULL);
    cos_get_checkpoint_path(clt_params, &file_path, p, &checkpoint_path);
    CuAssertStrEquals(tc, "/home/tim/work/cos/BingWallpaper-2017-01-19.jpg.cp", checkpoint_path.data);

    cos_pool_destroy(p);

    printf("test_resumable_cos_get_checkpoint_path ok\n");
}

void test_resumable_cos_get_file_info(CuTest *tc)
{
    cos_pool_t *p = NULL;
    cos_string_t file_path = cos_null_string;
    char *local_file = "test_resumable_cos_get_file_info.txt";
    apr_finfo_t finfo;
    int rv;

    cos_pool_create(&p, NULL);

    // invalid path
    cos_str_set(&file_path, "");
    rv = cos_get_file_info(&file_path, p, &finfo);
    CuAssertTrue(tc, APR_STATUS_IS_ENOENT(rv));

    // file not exist
    cos_str_set(&file_path, "/uvwxyz/abchij/test.udp");
    rv = cos_get_file_info(&file_path, p, &finfo);
    CuAssertTrue(tc, APR_STATUS_IS_ENOENT(rv));

    // empty file
    rv = fill_test_file(p, local_file, "");
    CuAssertIntEquals(tc, APR_SUCCESS, rv);
    cos_str_set(&file_path, local_file);
    rv = cos_get_file_info(&file_path, p, &finfo);
    CuAssertIntEquals(tc, COSE_OK, rv);
    CuAssertTrue(tc, 0 == finfo.size);

    // normal
    rv = make_random_file(p, local_file, 1024);
    CuAssertIntEquals(tc, APR_SUCCESS, rv);
    rv = cos_get_file_info(&file_path, p, &finfo);
    CuAssertIntEquals(tc, COSE_OK, rv);
    CuAssertTrue(tc, 1024 == finfo.size);

    apr_file_remove(local_file, p);

    cos_pool_destroy(p);

    printf("test_resumable_cos_get_file_info ok\n");
}

void test_resumable_cos_does_file_exist(CuTest *tc)
{
    cos_pool_t *p = NULL;
    cos_string_t file_path = cos_null_string;
    char *local_file = "test_resumable_cos_does_file_exist.txt";
    int rv;

    cos_pool_create(&p, NULL);

    // invalid path
    cos_str_set(&file_path, "");
    rv = cos_does_file_exist(&file_path, p);
    CuAssertTrue(tc, !rv);

    // file not exist
    cos_str_set(&file_path, "/uvwxyz/abchij/test.udp");
    rv = cos_does_file_exist(&file_path, p);
    CuAssertTrue(tc, !rv);

    // normal
    rv = make_random_file(p, local_file, 1024);
    CuAssertIntEquals(tc, APR_SUCCESS, rv);
    cos_str_set(&file_path, local_file);
    rv = cos_does_file_exist(&file_path, p);
    CuAssertTrue(tc, rv);

    apr_file_remove(local_file, p);

    cos_pool_destroy(p);

    printf("test_resumable_cos_does_file_exist ok\n");
}

void test_resumable_cos_dump_checkpoint(CuTest *tc)
{
    cos_pool_t *p = NULL;
    cos_string_t file_path = cos_null_string;
    char *cp_file = "test_resumable_cos_dump_checkpoint.ucp";
    cos_checkpoint_t *cp;
    apr_finfo_t finfo;
    cos_string_t upload_id;
    int64_t part_size;
    int rv;

    cos_pool_create(&p, NULL);

    // build checkpoint
    finfo.size = 510598;
    finfo.mtime = 1459922563;  
    cos_str_set(&file_path, "D:\\work\\cos\\BingWallpaper-2017-01-19.jpg");
    cos_str_set(&upload_id, "0004B9894A22E5B1888A1E29F8236E2D");
    part_size = 1024 * 100;

    cp = cos_create_checkpoint_content(p);
    cos_build_upload_checkpoint(p, cp, &file_path, &finfo, &upload_id, part_size);

    cos_str_set(&file_path, cp_file);
    rv = cos_open_checkpoint_file(p, &file_path, cp); 
    CuAssertIntEquals(tc, APR_SUCCESS, rv);

    rv = cos_dump_checkpoint(p, cp);
    CuAssertIntEquals(tc, COSE_OK, rv);
    apr_file_close(cp->thefile);

    // write failed
    rv = apr_file_open(&cp->thefile, file_path.data, APR_READ, APR_UREAD | APR_GREAD, p);
    CuAssertIntEquals(tc, APR_SUCCESS, rv);

    rv = cos_dump_checkpoint(p, cp);
    CuAssertIntEquals(tc, COSE_FILE_TRUNC_ERROR, rv);
    apr_file_close(cp->thefile);

    apr_file_remove(cp_file, p);

    cos_pool_destroy(p);

    printf("test_resumable_cos_dump_checkpoint ok\n");
}

void test_resumable_cos_load_checkpoint(CuTest *tc)
{
    cos_pool_t *p = NULL;
    cos_string_t file_path = cos_null_string;
    char *cp_file = "test_resumable_cos_load_checkpoint.ucp";
    cos_checkpoint_t *cp;
    cos_checkpoint_t *cp_l;
    apr_finfo_t finfo;
    cos_string_t upload_id;
    int64_t part_size;
    int rv;

    cos_pool_create(&p, NULL);

    // build checkpoint
    finfo.size = 510598;
    finfo.mtime = 1459922563;  
    cos_str_set(&file_path, "D:\\work\\cos\\BingWallpaper-2017-01-19.jpg");
    cos_str_set(&upload_id, "0004B9894A22E5B1888A1E29F8236E2D");
    part_size = 1024 * 100;

    cp = cos_create_checkpoint_content(p);
    cos_build_upload_checkpoint(p, cp, &file_path, &finfo, &upload_id, part_size);

    cos_str_set(&file_path, cp_file);
    rv = cos_open_checkpoint_file(p, &file_path, cp); 
    CuAssertIntEquals(tc, APR_SUCCESS, rv);

    // dump
    rv = cos_dump_checkpoint(p, cp);
    CuAssertIntEquals(tc, COSE_OK, rv);
    apr_file_close(cp->thefile);

    // load
    cp_l = cos_create_checkpoint_content(p);
    rv = cos_load_checkpoint(p, &file_path, cp_l);
    CuAssertIntEquals(tc, COSE_OK, rv);

    CuAssertStrEquals(tc, cp->md5.data, cp_l->md5.data);
    CuAssertIntEquals(tc, cp->cp_type, cp_l->cp_type);
    CuAssertStrEquals(tc, cp->upload_id.data, cp_l->upload_id.data);
    CuAssertIntEquals(tc, cp->part_num, cp_l->part_num);
    CuAssertTrue(tc, cp->part_size == cp_l->part_size);

    // load failed
    cos_str_set(&file_path, "/uvwxyz/abchij/test.udp");
    rv = cos_load_checkpoint(p, &file_path, cp_l);
    CuAssertIntEquals(tc, COSE_OPEN_FILE_ERROR, rv);

    // content invalid
    rv = make_random_file(p, cp_file, 1024);
    CuAssertIntEquals(tc, APR_SUCCESS, rv);
    cos_str_set(&file_path, cp_file);
    rv = cos_load_checkpoint(p, &file_path, cp_l);
    CuAssertIntEquals(tc, COSE_XML_PARSE_ERROR, rv);

    apr_file_remove(cp_file, p);

    cos_pool_destroy(p);

    printf("test_resumable_cos_load_checkpoint ok\n");
}

void test_resumable_cos_is_upload_checkpoint_valid(CuTest *tc)
{
    cos_pool_t *p = NULL;
    cos_string_t file_path = cos_null_string;
    cos_checkpoint_t *cp;
    apr_finfo_t finfo;
    cos_string_t upload_id;
    int64_t part_size;
    int rv;

    cos_pool_create(&p, NULL);

    // build checkpoint
    finfo.size = 510598;
    finfo.mtime = 1459922563;  
    cos_str_set(&file_path, "D:\\work\\cos\\BingWallpaper-2017-01-19.jpg");
    cos_str_set(&upload_id, "0004B9894A22E5B1888A1E29F8236E2D");
    part_size = 1024 * 100;

    cp = cos_create_checkpoint_content(p);
    cos_build_upload_checkpoint(p, cp, &file_path, &finfo, &upload_id, part_size);

    rv = cos_is_upload_checkpoint_valid(p, cp, &finfo);
    CuAssertTrue(tc, rv);

    finfo.size = 510599;
    rv = cos_is_upload_checkpoint_valid(p, cp, &finfo);
    CuAssertTrue(tc, !rv);

    finfo.mtime = 1459922562; 
    rv = cos_is_upload_checkpoint_valid(p, cp, &finfo);
    CuAssertTrue(tc, !rv);

    cos_pool_destroy(p);

    printf("test_resumable_cos_is_upload_checkpoint_valid ok\n");
}

void test_resumable_checkpoint_xml(CuTest *tc)
{
    cos_pool_t *p = NULL;
    char *xml_doc = NULL;
    cos_checkpoint_t *cp;
    int64_t part_size = 0;
    int i = 0;
    cos_checkpoint_t *cp_actual;
    const char *xml_doc_expected = 
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<Checkpoint><MD5></MD5><Type>1</Type>"
        "<LocalFile>"
        "<Path>D:\\work\\cos\\BingWallpaper-2017-01-19.jpg</Path><Size>510598</Size>"
        "<LastModified>1459922563</LastModified><MD5>fba9dede5f27731c9771645a39863328</MD5>"
        "</LocalFile>"
        "<Object>"
        "<Key>~/cos/BingWallpaper-2017-01-19.jpg</Key><Size>510598</Size>"
        "<LastModified>Fri, 24 Feb 2012 06:07:48 GMT</LastModified><ETag>0F7230CAA4BE94CCBDC99C5500000000</ETag>"
        "</Object>"
        "<UploadId>0004B9894A22E5B1888A1E29F8236E2D</UploadId>"
        "<CPParts>"
        "<Number>1</Number><Size>1048576</Size>"
        "<Parts>"
        "<Part><Index>0</Index><Offset>0</Offset><Size>510598</Size><Completed>1</Completed><ETag></ETag><Crc64>0</Crc64></Part>"
        "</Parts>"
        "</CPParts>"
        "</Checkpoint>\n";
    
    cos_pool_create(&p, NULL);

    cp = cos_create_checkpoint_content(p);
    cp->cp_type = COS_CP_UPLOAD;

    cos_str_set(&cp->file_path, "D:\\work\\cos\\BingWallpaper-2017-01-19.jpg");
    cp->file_size = 510598;
    cp->file_last_modified = 1459922563;
    cos_str_set(&cp->file_md5,"fba9dede5f27731c9771645a39863328");

    cos_str_set(&cp->object_name, "~/cos/BingWallpaper-2017-01-19.jpg");
    cp->object_size = 510598;
    cos_str_set(&cp->object_last_modified, "Fri, 24 Feb 2012 06:07:48 GMT");
    cos_str_set(&cp->object_etag, "0F7230CAA4BE94CCBDC99C5500000000");

    cos_str_set(&cp->upload_id, "0004B9894A22E5B1888A1E29F8236E2D");

    part_size = 1024 * 100;
    cos_get_part_size(cp->file_size, &part_size);
    cp->part_size = part_size;
    for (i = 0; i * part_size < cp->file_size; i++) {
        cp->parts[i].index = i;
        cp->parts[i].offset = i * part_size;
        cp->parts[i].size = cos_min(part_size, (cp->file_size - i * part_size));
        cp->parts[i].completed = COS_TRUE;
        cos_str_set(& cp->parts[i].etag, "");
    }
    cp->part_num = i;

    xml_doc = cos_build_checkpoint_xml(p ,cp);

    CuAssertStrEquals(tc, xml_doc_expected, xml_doc);

    cp_actual = cos_create_checkpoint_content(p);
    cos_checkpoint_parse_from_body(p, xml_doc, cp_actual);

    CuAssertIntEquals(tc, COS_CP_UPLOAD, cp_actual->cp_type);
    CuAssertStrEquals(tc, "", cp_actual->md5.data);

    CuAssertStrEquals(tc, "D:\\work\\cos\\BingWallpaper-2017-01-19.jpg", cp_actual->file_path.data);
    CuAssertTrue(tc, 510598 == cp_actual->file_size);
    CuAssertTrue(tc, 1459922563 == cp_actual->file_last_modified);
    CuAssertStrEquals(tc, "fba9dede5f27731c9771645a39863328", cp_actual->file_md5.data);

    CuAssertStrEquals(tc, "~/cos/BingWallpaper-2017-01-19.jpg", cp_actual->object_name.data);
    CuAssertTrue(tc, 510598 == cp_actual->file_size);
    CuAssertStrEquals(tc, "Fri, 24 Feb 2012 06:07:48 GMT", cp_actual->object_last_modified.data);
    CuAssertStrEquals(tc, "0F7230CAA4BE94CCBDC99C5500000000", cp_actual->object_etag.data);

    CuAssertStrEquals(tc, "0004B9894A22E5B1888A1E29F8236E2D", cp_actual->upload_id.data);

    CuAssertIntEquals(tc, 1, cp_actual->part_num);
    CuAssertTrue(tc, 1048576 == cp_actual->part_size);

    cos_pool_destroy(p);

    printf("test_resumable_checkpoint_xml ok\n");
}

// ---------------------------- FT ----------------------------

void test_resumable_upload_without_checkpoint(CuTest *tc)
{
    cos_pool_t *p = NULL;
    char *object_name = "test_3M.dat";
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t filename;
    cos_status_t *s = NULL;
    int is_cname = 0;
    cos_table_t *headers = NULL;
    cos_table_t *resp_headers = NULL;
    cos_list_t resp_body;
    cos_request_options_t *options = NULL;
    cos_resumable_clt_params_t *clt_params;
    int64_t content_length = 0;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_list_init(&resp_body);
    cos_str_set(&filename, "../../../cos_c_sdk_ut/test_3M.dat");

    // upload object
    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 1024, 4, COS_FALSE, NULL);
    s = cos_resumable_upload_file(options, &bucket, &object, &filename, headers, NULL, 
        clt_params, NULL, &resp_headers, &resp_body);
    CuAssertIntEquals(tc, 200, s->code);

    cos_pool_destroy(p);

    // head object
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    s = cos_head_object(options, &bucket, &object, NULL, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);

    content_length = atol((char*)apr_table_get(resp_headers, COS_CONTENT_LENGTH));
    CuAssertTrue(tc, content_length == get_file_size(&filename));
    printf("test_resumable_upload_without_checkpoint len%d\n",content_length);
    printf("test_resumable_upload_without_checkpoint size%d\n",get_file_size(&filename));
    cos_pool_destroy(p);

    printf("test_resumable_upload_without_checkpoint ok\n");
}

void test_cos_upload_object_by_part_copy(CuTest *tc)
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
    int length = snprintf(NULL, 0, "%s-%s.%s/cos_test_put_object.ts", TEST_BUCKET_NAME, TEST_APPID, TEST_COS_ENDPOINT);
    char *result = (char *)malloc(length + 1);
    snprintf(result, length + 1, "%s-%s.%s/cos_test_put_object.ts", TEST_BUCKET_NAME, TEST_APPID, TEST_COS_ENDPOINT);
    cos_str_set(&copy_source, result);

    s = cos_upload_object_by_part_copy(options, &copy_source, &bucket, &object, 2);
    CuAssertIntEquals(tc, 200, s->code);
    printf("test_cos_upload_object_by_part_copy ok\n");
    free(result);
    cos_pool_destroy(p);
}

void test_cos_upload_object_by_part_copy_change_domain(CuTest *tc)
{
    set_test_retry_change_domin_config(1);
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
    int length = snprintf(NULL, 0, "%s-%s.%s/cos_test_put_object.ts", TEST_BUCKET_NAME, TEST_APPID, TEST_COS_ENDPOINT);
    char *result = (char *)malloc(length + 1);
    snprintf(result, length + 1, "%s-%s.%s/cos_test_put_object.ts", TEST_BUCKET_NAME, TEST_APPID, TEST_COS_ENDPOINT);
    cos_str_set(&copy_source, result);

    s = cos_upload_object_by_part_copy(options, &copy_source, &bucket, &object, 2);
    printf("test_cos_upload_object_by_part_copy_change_domain ok\n");
    free(result);
    cos_pool_destroy(p);
    set_test_retry_change_domin_config(0);
}

void test_cos_download_part_to_file(CuTest *tc)
{
    set_test_retry_change_domin_config(0);
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t filepath;
    cos_table_t *resp_headers = NULL;
    
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test_3M.dat");
    cos_str_set(&filepath, "download3Mtest.dat");

    s = cos_download_part_to_file(options, &bucket, &object, &filepath, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    printf("test_cos_download_part_to_file ok\n");

    cos_pool_destroy(p);
}

void test_cos_download_part_to_file_change_domain(CuTest *tc)
{
    set_test_retry_change_domin_config(1);
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t filepath;
    cos_table_t *resp_headers = NULL;
    
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test_3M.dat");
    cos_str_set(&filepath, "download3Mtest.dat");

    s = cos_download_part_to_file(options, &bucket, &object, &filepath, &resp_headers);
    printf("test_cos_download_part_to_file_change_domain ok\n");
    set_test_retry_change_domin_config(0);
    cos_pool_destroy(p);
}

void test_resumable_upload_partsize_change_domain(CuTest *tc)
{
    set_test_retry_change_domin_config(1);
    cos_pool_t *p = NULL;
    char *object_name = "test_resumable_upload_partsize.jpg";
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t filename;
    cos_status_t *s = NULL;
    int is_cname = 0;
    cos_table_t *headers = NULL;
    cos_table_t *resp_headers = NULL;
    cos_list_t resp_body;
    cos_request_options_t *options = NULL;
    cos_resumable_clt_params_t *clt_params;
    int64_t content_length = 0;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_list_init(&resp_body);
    cos_str_set(&filename, test_local_file);

    // upload object with part size 10MB
    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 1024 * 10, 3, COS_FALSE, NULL);
    s = cos_resumable_upload_file(options, &bucket, &object, &filename, headers, NULL, 
        clt_params, NULL, &resp_headers, &resp_body);

    cos_pool_destroy(p);

    // head object
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    s = cos_head_object(options, &bucket, &object, NULL, &resp_headers);

    content_length = atol((char*)apr_table_get(resp_headers, COS_CONTENT_LENGTH));
    printf("test_resumable_upload_partsize len%d\n",content_length);
    printf("test_resumable_upload_partsize size%d\n",get_file_size(test_local_file));

    cos_pool_destroy(p);

    // upload object with part size 200K
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 0);

    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 200, 3, COS_FALSE, NULL);
    s = cos_resumable_upload_file(options, &bucket, &object, &filename, headers, NULL, 
        clt_params, NULL, &resp_headers, &resp_body);
    cos_pool_destroy(p);

    // head object
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    s = cos_head_object(options, &bucket, &object, NULL, &resp_headers);

    content_length = atol((char*)apr_table_get(resp_headers, COS_CONTENT_LENGTH));
    printf("test_resumable_upload_partsize_change_domain len%d\n",content_length);
    printf("test_resumable_upload_partsize_change_domain size%d\n",get_file_size(test_local_file));

    cos_pool_destroy(p);
    set_test_retry_change_domin_config(0);

    printf("test_resumable_upload_partsize_change_domain ok\n");
}

void test_resumable_upload_partsize(CuTest *tc)
{
    set_test_retry_change_domin_config(0);
    cos_pool_t *p = NULL;
    char *object_name = "test_resumable_upload_partsize.jpg";
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t filename;
    cos_status_t *s = NULL;
    int is_cname = 0;
    cos_table_t *headers = NULL;
    cos_table_t *resp_headers = NULL;
    cos_list_t resp_body;
    cos_request_options_t *options = NULL;
    cos_resumable_clt_params_t *clt_params;
    int64_t content_length = 0;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_list_init(&resp_body);
    cos_str_set(&filename, test_local_file);

    // upload object with part size 10MB
    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 1024 * 10, 3, COS_FALSE, NULL);
    s = cos_resumable_upload_file(options, &bucket, &object, &filename, headers, NULL, 
        clt_params, NULL, &resp_headers, &resp_body);
    CuAssertIntEquals(tc, 200, s->code);

    cos_pool_destroy(p);

    // head object
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    s = cos_head_object(options, &bucket, &object, NULL, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);

    content_length = atol((char*)apr_table_get(resp_headers, COS_CONTENT_LENGTH));
    CuAssertTrue(tc, content_length == get_file_size(test_local_file));
    printf("test_resumable_upload_partsize len%d\n",content_length);
    printf("test_resumable_upload_partsize size%d\n",get_file_size(test_local_file));

    cos_pool_destroy(p);

    // upload object with part size 200K
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 0);

    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 200, 3, COS_FALSE, NULL);
    s = cos_resumable_upload_file(options, &bucket, &object, &filename, headers, NULL, 
        clt_params, NULL, &resp_headers, &resp_body);
    CuAssertIntEquals(tc, 200, s->code);

    cos_pool_destroy(p);

    // head object
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    s = cos_head_object(options, &bucket, &object, NULL, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);

    content_length = atol((char*)apr_table_get(resp_headers, COS_CONTENT_LENGTH));
    CuAssertTrue(tc, content_length == get_file_size(test_local_file));
    printf("test_resumable_upload_partsize len%d\n",content_length);
    printf("test_resumable_upload_partsize size%d\n",get_file_size(test_local_file));

    cos_pool_destroy(p);

    printf("test_resumable_upload_partsize ok\n");
}

void test_resumable_upload_threads(CuTest *tc)
{
    cos_pool_t *p = NULL;
    char *object_name = "test_resumable_upload_threads.jpg";
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t filename;
    cos_status_t *s = NULL;
    int is_cname = 0;
    cos_table_t *headers = NULL;
    cos_table_t *resp_headers = NULL;
    cos_list_t resp_body;
    cos_request_options_t *options = NULL;
    cos_resumable_clt_params_t *clt_params;
    int64_t content_length = 0;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_list_init(&resp_body);
    cos_str_set(&filename, test_local_file);

    // upload object with thread 1
    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 100, 1, COS_FALSE, NULL);
    s = cos_resumable_upload_file(options, &bucket, &object, &filename, headers, NULL, 
        clt_params, NULL, &resp_headers, &resp_body);
    CuAssertIntEquals(tc, 200, s->code);

    cos_pool_destroy(p);

    // head object
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    s = cos_head_object(options, &bucket, &object, NULL, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);

    content_length = atol((char*)apr_table_get(resp_headers, COS_CONTENT_LENGTH));
    CuAssertTrue(tc, content_length == get_file_size(test_local_file));
    printf("test_resumable_upload_threads len%d\n",content_length);
    printf("test_resumable_upload_threads size%d\n",get_file_size(test_local_file));

    cos_pool_destroy(p);

    // upload object with thread 5
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 0);

    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 200, 5, COS_FALSE, NULL);
    s = cos_resumable_upload_file(options, &bucket, &object, &filename, headers, NULL, 
        clt_params, NULL, &resp_headers, &resp_body);
    CuAssertIntEquals(tc, 200, s->code);

    cos_pool_destroy(p);

    // head object
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    s = cos_head_object(options, &bucket, &object, NULL, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);

    content_length = atol((char*)apr_table_get(resp_headers, COS_CONTENT_LENGTH));
    CuAssertTrue(tc, content_length == get_file_size(test_local_file));
    printf("test_resumable_upload_threads len%d\n",content_length);
    printf("test_resumable_upload_threads size%d\n",get_file_size(test_local_file));

    cos_pool_destroy(p);

    // upload object with thread 10
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 0);

    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 100, 10, COS_FALSE, NULL);
    s = cos_resumable_upload_file(options, &bucket, &object, &filename, headers, NULL, 
        clt_params, NULL, &resp_headers, &resp_body);
    CuAssertIntEquals(tc, 200, s->code);

    cos_pool_destroy(p);

    // head object
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    s = cos_head_object(options, &bucket, &object, NULL, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);

    content_length = atol((char*)apr_table_get(resp_headers, COS_CONTENT_LENGTH));
    CuAssertTrue(tc, content_length == get_file_size(test_local_file));
    printf("test_resumable_upload_threads len%d\n",content_length);
    printf("test_resumable_upload_threads size%d\n",get_file_size(test_local_file));

    cos_pool_destroy(p);

    printf("test_resumable_upload_threads ok\n");
}

void test_resumable_upload_with_checkpoint(CuTest *tc)
{
    cos_pool_t *p = NULL;
    char *object_name = "test_resumable_upload_with_checkpoint.jpg";
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t filename;
    cos_status_t *s = NULL;
    int is_cname = 0;
    cos_table_t *headers = NULL;
    cos_table_t *resp_headers = NULL;
    cos_list_t resp_body;
    cos_request_options_t *options = NULL;
    cos_resumable_clt_params_t *clt_params;
    int64_t content_length = 0;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_list_init(&resp_body);
    cos_str_set(&filename, test_local_file);

    // upload object
    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 100, 3, COS_TRUE, NULL);
    s = cos_resumable_upload_file(options, &bucket, &object, &filename, headers, NULL, 
        clt_params, NULL, &resp_headers, &resp_body);
    CuAssertIntEquals(tc, 200, s->code);

    cos_pool_destroy(p);

    // head object
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    s = cos_head_object(options, &bucket, &object, NULL, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);

    content_length = atol((char*)apr_table_get(resp_headers, COS_CONTENT_LENGTH));
    CuAssertTrue(tc, content_length == get_file_size(test_local_file));
    printf("test_resumable_upload_with_checkpoint len%d\n",content_length);
    printf("test_resumable_upload_with_checkpoint size%d\n",get_file_size(test_local_file));

    cos_pool_destroy(p);

    printf("test_resumable_upload_with_checkpoint ok\n");
}

void test_resumable_upload_with_checkpoint_format_invalid(CuTest *tc)
{
    cos_pool_t *p = NULL;
    char *object_name = "test_resumable_upload_with_checkpoint_format_invalid.jpg";
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t filename;
    cos_status_t *s = NULL;
    int is_cname = 0;
    cos_table_t *headers = NULL;
    cos_table_t *resp_headers = NULL;
    cos_list_t resp_body;
    cos_request_options_t *options = NULL;
    cos_resumable_clt_params_t *clt_params;
    int64_t content_length = 0;
    cos_string_t checkpoint_path;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_list_init(&resp_body);
    cos_str_set(&filename, test_local_file);

    // generate checkpoint
    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 100, 3, COS_TRUE, NULL);
    cos_get_checkpoint_path(clt_params, &filename, p, &checkpoint_path);
    fill_test_file(p, checkpoint_path.data, "HiCOS");

    // upload object
    s = cos_resumable_upload_file(options, &bucket, &object, &filename, headers, NULL, 
        clt_params, NULL, &resp_headers, &resp_body);
    CuAssertIntEquals(tc, 200, s->code);

    cos_pool_destroy(p);

    // head object
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    s = cos_head_object(options, &bucket, &object, NULL, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);

    content_length = atol((char*)apr_table_get(resp_headers, COS_CONTENT_LENGTH));
    CuAssertTrue(tc, content_length == get_file_size(test_local_file));
    printf("test_resumable_upload_with_checkpoint_format_invalid len%d\n",content_length);
    printf("test_resumable_upload_with_checkpoint_format_invalid size%d\n",get_file_size(test_local_file));

    cos_pool_destroy(p);

    printf("test_resumable_upload_with_checkpoint_format_invalid ok\n");
}

void test_resumable_upload_with_checkpoint_path_invalid(CuTest *tc)
{
    cos_pool_t *p = NULL;
    char *object_name = "test_resumable_upload_with_checkpoint.jpg";
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t filename;
    cos_status_t *s = NULL;
    int is_cname = 0;
    cos_table_t *headers = NULL;
    cos_table_t *resp_headers = NULL;
    cos_list_t resp_body;
    cos_request_options_t *options = NULL;
    cos_resumable_clt_params_t *clt_params;
    char *cp_path = "/uvwxyz/abchij/test.udp";

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_list_init(&resp_body);
    cos_str_set(&filename, test_local_file);

    // upload
    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 100, 3, COS_TRUE, cp_path);
    s = cos_resumable_upload_file(options, &bucket, &object, &filename, headers, NULL, 
        clt_params, NULL, &resp_headers, &resp_body);
    CuAssertStrEquals(tc, "OpenFileFail", s->error_code);

    cos_pool_destroy(p);

    printf("test_resumable_upload_with_checkpoint_path_invalid ok\n");
}

void test_resumable_upload_with_file_size_unavailable(CuTest *tc)
{
    cos_pool_t *p = NULL;
    char *object_name = "test_resumable_upload_with_file_size_unavailable.jpg";
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t filename;
    cos_status_t *s = NULL;
    int is_cname = 0;
    cos_table_t *headers = NULL;
    cos_table_t *resp_headers = NULL;
    cos_list_t resp_body;
    cos_request_options_t *options = NULL;
    cos_resumable_clt_params_t *clt_params;
    int64_t content_length = 0;
    cos_string_t checkpoint_path;
    char *xml_doc = "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<Checkpoint>"
        "<MD5></MD5><Type>1</Type>"
        "<LocalFile>"
        "<Path>/home/baiyb/work/tmp/aliyun-cos-c-sdk-doing/BingWallpaper-2017-01-19.jpg</Path>"
        "<Size>0</Size><LastModified>1484790044000000</LastModified><MD5></MD5>"
        "</LocalFile>"
        "<Object>"
        "<Key></Key><Size>0</Size><LastModified></LastModified><ETag></ETag>"
        "</Object>"
        "<UploadId>750FBF7EB9104D4F8DDB74F0432A821F</UploadId>"
        "<CPParts>"
        "<Number>8</Number><Size>102400</Size>"
        "<Parts>"
        "<Part><Index>0</Index><Offset>0</Offset><Size>102400</Size><Completed>1</Completed><ETag>&quot;06336E9660D3D9610C79835D27F4D2EF&quot;</ETag></Part>"
        "<Part><Index>1</Index><Offset>102400</Offset><Size>102400</Size><Completed>1</Completed><ETag>&quot;D1C009C43EAA5E64B6B794E47BA37917&quot;</ETag></Part>"
        "<Part><Index>2</Index><Offset>204800</Offset><Size>102400</Size><Completed>1</Completed><ETag>&quot;073D2D906CEB0FADA1F2BA8A0BA54C1D&quot;</ETag></Part>"
        "<Part><Index>3</Index><Offset>307200</Offset><Size>102400</Size><Completed>1</Completed><ETag>&quot;7BA3B455E7B30D734F2CA29548E8BC56&quot;</ETag></Part>"
        "<Part><Index>4</Index><Offset>409600</Offset><Size>102400</Size><Completed>1</Completed><ETag>&quot;296F06C36E3746CD2A28824D3B4F0648&quot;</ETag></Part>"
        "<Part><Index>5</Index><Offset>512000</Offset><Size>102400</Size><Completed>1</Completed><ETag>&quot;06A0A19EC60DD4F51344D900BE543C53&quot;</ETag></Part>"
        "<Part><Index>6</Index><Offset>614400</Offset><Size>102400</Size><Completed>1</Completed><ETag>&quot;B7CE941E6AC00B6B3423572A87EA0B67&quot;</ETag></Part>"
        "<Part><Index>7</Index><Offset>716800</Offset><Size>52886</Size><Completed>1</Completed><ETag>&quot;AE5EEAEBB54232A6F71743AA45A32DA9&quot;</ETag></Part>"
        "</Parts>"
        "</CPParts>"
        "</Checkpoint>";

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_list_init(&resp_body);
    cos_str_set(&filename, test_local_file);

    // generate checkpoint
    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 100, 3, COS_TRUE, NULL);
    cos_get_checkpoint_path(clt_params, &filename, p, &checkpoint_path);
    fill_test_file(p, checkpoint_path.data, xml_doc);

    // upload object
    s = cos_resumable_upload_file(options, &bucket, &object, &filename, headers, NULL, 
        clt_params, NULL, &resp_headers, &resp_body);
    CuAssertIntEquals(tc, 200, s->code);

    cos_pool_destroy(p);

    // head object
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    s = cos_head_object(options, &bucket, &object, NULL, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);

    content_length = atol((char*)apr_table_get(resp_headers, COS_CONTENT_LENGTH));
    CuAssertTrue(tc, content_length == get_file_size(test_local_file));
    printf("test_resumable_upload_with_file_size_unavailable len%d\n",content_length);
    printf("test_resumable_upload_with_file_size_unavailable size%d\n",get_file_size(test_local_file));

    cos_pool_destroy(p);

    printf("test_resumable_upload_with_file_size_unavailable ok\n");
}

void test_resumable_upload_with_uploadid_unavailable(CuTest *tc)
{
    cos_pool_t *p = NULL;
    char *object_name = "test_resumable_upload_with_uploadid_unavailable.jpg";
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t filename;
    cos_status_t *s = NULL;
    int is_cname = 0;
    cos_table_t *headers = NULL;
    cos_table_t *resp_headers = NULL;
    cos_list_t resp_body;
    apr_finfo_t finfo;
    cos_request_options_t *options = NULL;
    cos_resumable_clt_params_t *clt_params;
    char *cp_path = "../../../test.cp";
    char *xml_doc = "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<Checkpoint><MD5></MD5><Type>1</Type><LocalFile>"
        "<Path>cos_c_sdk_test/BingWallpaper-2017-01-19.jpg</Path>"
        "<Size>769686</Size><LastModified>%"
        APR_INT64_T_FMT
        "</LastModified><MD5></MD5></LocalFile>"
        "<Object><Key></Key><Size>0</Size><LastModified></LastModified><ETag></ETag></Object>"
        "<UploadId>F5F901B64DF34BEDA60C9B2B0984B8D4</UploadId>"
        "<CPParts><Number>1</Number><Size>1048576</Size>"
        "<Parts><Part><Index>0</Index><Offset>0</Offset><Size>769686</Size><Completed>0</Completed><ETag></ETag></Part>"
        "</Parts></CPParts></Checkpoint>";

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_list_init(&resp_body);
    cos_str_set(&filename, test_local_file);

    // generate checkpoint
    cos_get_file_info(&filename, p, &finfo);
    xml_doc = apr_psprintf(p, xml_doc, finfo.mtime);
    fill_test_file(p, cp_path, xml_doc);

    // upload object
    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 1024, 1, COS_TRUE, cp_path);
    s = cos_resumable_upload_file(options, &bucket, &object, &filename, headers, NULL, 
        clt_params, NULL, &resp_headers, &resp_body);
    CuAssertIntEquals(tc, 404, s->code);
    CuAssertStrEquals(tc, "NoSuchUpload", s->error_code);

    apr_file_remove(cp_path, p);
    cos_pool_destroy(p);

    printf("test_resumable_upload_with_uploadid_unavailable ok\n");
}

void test_resumable_upload_with_uploadid_available(CuTest *tc)
{
    cos_pool_t *p = NULL;
    cos_pool_t *pool = NULL;
    char *object_name = "test_resumable_upload_with_uploadid_available.jpg";
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t filename;
    cos_status_t *s = NULL;
    int is_cname = 0;
    cos_table_t *headers = NULL;
    cos_table_t *resp_headers = NULL;
    cos_list_t resp_body;
    cos_request_options_t *options = NULL;
    cos_resumable_clt_params_t *clt_params;
    int64_t content_length = 0;
    cos_string_t checkpoint_path;
    cos_string_t upload_id;
    char *xml_doc = "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<Checkpoint>"
        "<MD5></MD5><Type>1</Type>"
        "<LocalFile>"
        "<Path>/home/baiyb/work/tmp/aliyun-cos-c-sdk-doing/BingWallpaper-2017-01-19.jpg</Path>"
        "<Size>769686</Size><LastModified>1484790044000000</LastModified><MD5></MD5>"
        "</LocalFile>"
        "<Object>"
        "<Key></Key><Size>0</Size><LastModified></LastModified><ETag></ETag>"
        "</Object>"
        "<UploadId>%.*s</UploadId>"
        "<CPParts>"
        "<Number>8</Number><Size>102400</Size>"
        "<Parts>"
        "<Part><Index>0</Index><Offset>0</Offset><Size>102400</Size><Completed>0</Completed><ETag></ETag></Part>"
        "<Part><Index>1</Index><Offset>102400</Offset><Size>102400</Size><Completed>0</Completed><ETag></ETag></Part>"
        "<Part><Index>2</Index><Offset>204800</Offset><Size>102400</Size><Completed>0</Completed><ETag></ETag></Part>"
        "<Part><Index>3</Index><Offset>307200</Offset><Size>102400</Size><Completed>0</Completed><ETag></ETag></Part>"
        "<Part><Index>4</Index><Offset>409600</Offset><Size>102400</Size><Completed>0</Completed><ETag></ETag></Part>"
        "<Part><Index>5</Index><Offset>512000</Offset><Size>102400</Size><Completed>0</Completed><ETag></ETag></Part>"
        "<Part><Index>6</Index><Offset>614400</Offset><Size>102400</Size><Completed>0</Completed><ETag></ETag></Part>"
        "<Part><Index>7</Index><Offset>716800</Offset><Size>52886</Size><Completed>0</Completed><ETag></ETag></Part>"
        "</Parts>"
        "</CPParts>"
        "</Checkpoint>";

    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_list_init(&resp_body);
    cos_str_set(&filename, test_local_file);

    // generate upload id
    cos_pool_create(&p, NULL);
    cos_pool_create(&pool, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    s = cos_init_multipart_upload(options, &bucket, &object, &upload_id, headers, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);

    xml_doc = apr_psprintf(pool, xml_doc, upload_id.len, upload_id.data);
    cos_pool_destroy(p);

    // generate checkpoint
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 0);

    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 100, 3, COS_TRUE, NULL);
    cos_get_checkpoint_path(clt_params, &filename, p, &checkpoint_path);
    fill_test_file(p, checkpoint_path.data, xml_doc);

    // upload object
    s = cos_resumable_upload_file(options, &bucket, &object, &filename, headers, NULL, 
        clt_params, NULL, &resp_headers, &resp_body);
    CuAssertIntEquals(tc, 200, s->code);

    cos_pool_destroy(p);

    // head object
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    s = cos_head_object(options, &bucket, &object, NULL, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);

    content_length = atol((char*)apr_table_get(resp_headers, COS_CONTENT_LENGTH));
    CuAssertTrue(tc, content_length == get_file_size(test_local_file));
    printf("test_resumable_upload_with_uploadid_available len%d\n",content_length);
    printf("test_resumable_upload_with_uploadid_available size%d\n",get_file_size(test_local_file));
    cos_pool_destroy(p);
    cos_pool_destroy(pool);

    printf("test_resumable_upload_with_uploadid_available ok\n");
}

void test_resumable_upload_with_file_path_invalid(CuTest *tc)
{
    cos_pool_t *p = NULL;
    char *object_name = "test_resumable_upload_with_file_path_invalid.jpg";
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t filename;
    cos_status_t *s = NULL;
    int is_cname = 0;
    cos_table_t *headers = NULL;
    cos_table_t *resp_headers = NULL;
    cos_list_t resp_body;
    cos_request_options_t *options = NULL;
    cos_resumable_clt_params_t *clt_params;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_list_init(&resp_body);
    cos_str_set(&filename, "/uvwxyz/abchij/test.jpg");

    // upload
    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 1024, 1, COS_TRUE, NULL);
    s = cos_resumable_upload_file(options, &bucket, &object, &filename, headers, NULL, 
        clt_params, NULL, &resp_headers, &resp_body);
    CuAssertStrEquals(tc, "OpenFileFail", s->error_code);

    cos_pool_destroy(p);

    printf("test_resumable_upload_with_file_path_invalid ok\n");
}

void test_resumable_upload_progress_without_checkpoint(CuTest *tc)
{
    cos_pool_t *p = NULL;
    char *object_name = "test_resumable_upload_progress_without_checkpoint.jpg";
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t filename;
    cos_status_t *s = NULL;
    int is_cname = 0;
    cos_table_t *headers = NULL;
    cos_table_t *resp_headers = NULL;
    cos_list_t resp_body;
    cos_request_options_t *options = NULL;
    cos_resumable_clt_params_t *clt_params;
    int64_t content_length = 0;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_list_init(&resp_body);
    cos_str_set(&filename, test_local_file);

    // upload object
    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 100, 3, COS_FALSE, NULL);
    s = cos_resumable_upload_file(options, &bucket, &object, &filename, headers, NULL, 
        clt_params, percentage, &resp_headers, &resp_body);
    CuAssertIntEquals(tc, 200, s->code);

    cos_pool_destroy(p);

    // head object
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    s = cos_head_object(options, &bucket, &object, NULL, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);

    content_length = atol((char*)apr_table_get(resp_headers, COS_CONTENT_LENGTH));
    CuAssertTrue(tc, content_length == get_file_size(test_local_file));
    printf("test_resumable_upload_progress_without_checkpoint len%d\n",content_length);
    printf("test_resumable_upload_progress_without_checkpoint size%d\n",get_file_size(test_local_file));

    cos_pool_destroy(p);

    printf("test_resumable_upload_progress_without_checkpoint ok\n");
}

void test_resumable_upload_progress_with_checkpoint(CuTest *tc)
{
    cos_pool_t *p = NULL;
    char *object_name = "test_resumable_upload_progress_with_checkpoint.jpg";
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t filename;
    cos_status_t *s = NULL;
    int is_cname = 0;
    cos_table_t *headers = NULL;
    cos_table_t *resp_headers = NULL;
    cos_list_t resp_body;
    cos_request_options_t *options = NULL;
    cos_resumable_clt_params_t *clt_params;
    int64_t content_length = 0;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    headers = cos_table_make(p, 0);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, object_name);
    cos_list_init(&resp_body);
    cos_str_set(&filename, test_local_file);

    // upload object
    clt_params = cos_create_resumable_clt_params_content(p, 1024 * 100, 3, COS_TRUE, NULL);
    s = cos_resumable_upload_file(options, &bucket, &object, &filename, headers, NULL, 
        clt_params, percentage, &resp_headers, &resp_body);
    CuAssertIntEquals(tc, 200, s->code);

    cos_pool_destroy(p);

    // head object
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    s = cos_head_object(options, &bucket, &object, NULL, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);

    content_length = atol((char*)apr_table_get(resp_headers, COS_CONTENT_LENGTH));
    CuAssertTrue(tc, content_length == get_file_size(test_local_file));
    printf("test_resumable_upload_progress_with_checkpoint len%d\n",content_length);
    printf("test_resumable_upload_progress_with_checkpoint size%d\n",get_file_size(test_local_file));

    cos_pool_destroy(p);

    printf("test_resumable_upload_progress_with_checkpoint ok\n");
}

void test_resumable_download(CuTest *tc)
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t filepath;
    
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test_3M.dat");
    cos_str_set(&filepath, "download.dat");

    s = cos_resumable_download_file_without_cp(options, &bucket, &object, &filepath, NULL, NULL, 3, 
            5*1024*1024, NULL);
    CuAssertIntEquals(tc, 200, s->code);

    cos_pool_destroy(p);
    
}

void test_resumable_download_file_with_cp(CuTest *tc)
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t filepath;
    cos_resumable_clt_params_t *clt_params;
    cos_table_t *resp_headers = NULL;
    cos_list_t buffer;
    cos_buf_t *content = NULL;
    char *str = NULL;
    
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "3m.bin");

    cos_list_init(&buffer);
    str = cos_palloc(p, 0x300000);
    content = cos_buf_pack(options->pool, str, 0x300000);
    cos_list_add_tail(&content->node, &buffer);
    s = cos_put_object_from_buffer(options, &bucket, &object, &buffer, NULL, &resp_headers);

    clt_params = cos_create_resumable_clt_params_content(p, 1*1024*1024, 3, COS_TRUE, NULL);
    s = cos_resumable_download_file(options, &bucket, &object, &object, NULL, NULL, clt_params, NULL);
    CuAssertIntEquals(tc, 200, s->code);

    s = cos_delete_object(options, &bucket, &object, &resp_headers);

    cos_pool_destroy(p);
}

void test_resumable_download_file_with_cp_change_domain(CuTest *tc)
{
    set_test_retry_change_domin_config(1);
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t filepath;
    cos_resumable_clt_params_t *clt_params;
    cos_table_t *resp_headers = NULL;
    cos_list_t buffer;
    cos_buf_t *content = NULL;
    char *str = NULL;
    
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "3m.bin");

    cos_list_init(&buffer);
    str = cos_palloc(p, 0x300000);
    content = cos_buf_pack(options->pool, str, 0x300000);
    cos_list_add_tail(&content->node, &buffer);
    s = cos_put_object_from_buffer(options, &bucket, &object, &buffer, NULL, &resp_headers);

    clt_params = cos_create_resumable_clt_params_content(p, 1*1024*1024, 3, COS_TRUE, NULL);
    s = cos_resumable_download_file(options, &bucket, &object, &object, NULL, NULL, clt_params, NULL);

    s = cos_delete_object(options, &bucket, &object, &resp_headers);

    cos_pool_destroy(p);
    set_test_retry_change_domin_config(0);
    printf("test_resumable_download_file_with_cp_change_domain ok\n");
}

void test_resumable_copy_mt(CuTest *tc)
{
    set_test_retry_change_domin_config(0);
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
    cos_list_t buffer;
    cos_buf_t *content = NULL;
    char *str = NULL;
   
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test_copy_dst.txt");
    cos_str_set(&src_object, "test_copy_src.txt");
    cos_str_set(&src_endpoint, TEST_COS_ENDPOINT);

    cos_list_init(&buffer);
    str = cos_palloc(p, 0x500000);
    content = cos_buf_pack(options->pool, str, 0x500000);
    cos_list_add_tail(&content->node, &buffer);
    s = cos_put_object_from_buffer(options, &bucket, &src_object, &buffer, NULL, &resp_headers);

    s = cos_upload_object_by_part_copy_mt(options, &bucket, &src_object, &src_endpoint, &bucket, &object, 1024*1024, 3, NULL);
    CuAssertIntEquals(tc, 200, s->code);

    cos_pool_destroy(p);
}

void test_resumable_copy_mt_change_domin(CuTest *tc)
{
    set_test_retry_change_domin_config(1);
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
    cos_list_t buffer;
    cos_buf_t *content = NULL;
    char *str = NULL;
   
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&object, "test_copy_dst.txt");
    cos_str_set(&src_object, "test_copy_src.txt");
    cos_str_set(&src_endpoint, TEST_COS_ENDPOINT);

    cos_list_init(&buffer);
    str = cos_palloc(p, 0x500000);
    content = cos_buf_pack(options->pool, str, 0x500000);
    cos_list_add_tail(&content->node, &buffer);
    s = cos_put_object_from_buffer(options, &bucket, &src_object, &buffer, NULL, &resp_headers);

    s = cos_upload_object_by_part_copy_mt(options, &bucket, &src_object, &src_endpoint, &bucket, &object, 1024*1024, 3, NULL);
    set_test_retry_change_domin_config(0);
    cos_pool_destroy(p);
    printf("test_resumable_copy_mt_change_domin ok\n");
}


CuSuite *test_cos_resumable()
{
    CuSuite* suite = CuSuiteNew();

    SUITE_ADD_TEST(suite, test_resumable_setup);
    SUITE_ADD_TEST(suite, test_resumable_copy_mt);
    SUITE_ADD_TEST(suite, test_resumable_copy_mt_change_domin);
    SUITE_ADD_TEST(suite, test_resumable_download_file_with_cp);
    SUITE_ADD_TEST(suite, test_resumable_download_file_with_cp_change_domain);
    SUITE_ADD_TEST(suite, test_resumable_cos_get_thread_num);
    SUITE_ADD_TEST(suite, test_resumable_cos_get_checkpoint_path);
    SUITE_ADD_TEST(suite, test_resumable_cos_get_file_info);
    SUITE_ADD_TEST(suite, test_resumable_cos_does_file_exist);
    SUITE_ADD_TEST(suite, test_resumable_cos_dump_checkpoint);
    SUITE_ADD_TEST(suite, test_resumable_cos_load_checkpoint);
    SUITE_ADD_TEST(suite, test_resumable_cos_is_upload_checkpoint_valid);
    SUITE_ADD_TEST(suite, test_resumable_checkpoint_xml);
    SUITE_ADD_TEST(suite, test_resumable_upload_without_checkpoint);
    SUITE_ADD_TEST(suite, test_resumable_upload_with_checkpoint);
    SUITE_ADD_TEST(suite, test_resumable_upload_partsize);
    SUITE_ADD_TEST(suite, test_resumable_upload_partsize_change_domain);
    SUITE_ADD_TEST(suite, test_cos_download_part_to_file);
    SUITE_ADD_TEST(suite, test_cos_download_part_to_file_change_domain);
    SUITE_ADD_TEST(suite, test_cos_upload_object_by_part_copy);
    SUITE_ADD_TEST(suite, test_cos_upload_object_by_part_copy_change_domain);
    SUITE_ADD_TEST(suite, test_resumable_upload_threads);
    SUITE_ADD_TEST(suite, test_resumable_upload_with_checkpoint_format_invalid);
    SUITE_ADD_TEST(suite, test_resumable_upload_with_checkpoint_path_invalid);
    SUITE_ADD_TEST(suite, test_resumable_upload_with_file_size_unavailable);
    SUITE_ADD_TEST(suite, test_resumable_upload_with_uploadid_unavailable);
    SUITE_ADD_TEST(suite, test_resumable_upload_with_uploadid_available);
    SUITE_ADD_TEST(suite, test_resumable_upload_with_file_path_invalid);
    SUITE_ADD_TEST(suite, test_resumable_upload_progress_without_checkpoint);
    SUITE_ADD_TEST(suite, test_resumable_upload_progress_with_checkpoint);
    SUITE_ADD_TEST(suite, test_resumable_download);
    SUITE_ADD_TEST(suite, test_resumable_cleanup);
     
    return suite;
}
