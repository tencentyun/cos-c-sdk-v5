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

void test_bucket_setup(CuTest *tc)
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_acl_e cos_acl = COS_ACL_PRIVATE;
    char *object_name1 = "cos_test_object1";
    char *object_name2 = "cos_test_object2";
    char *object_name3 = "cos_tmp1/";
    char *object_name4 = "cos_tmp2/";
    char *object_name5 = "cos_tmp3";
    char *object_name6 = "cos_tmp3/1";
    char *str = "test c cos sdk";
    cos_table_t *headers1 = NULL;
    cos_table_t *headers2 = NULL;
    cos_table_t *headers3 = NULL;
    cos_table_t *headers4 = NULL;
    cos_table_t *headers5 = NULL;
    cos_table_t *headers6 = NULL;

    //set log level, default COS_LOG_WARN
    cos_log_set_level(COS_LOG_WARN);

    //set log output, default stderr
    cos_log_set_output(NULL);

    //create test bucket
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    s = create_test_bucket(options, TEST_BUCKET_NAME, cos_acl);

    CuAssertIntEquals(tc, 200, s->code);
    CuAssertStrEquals(tc, NULL, s->error_code);

    //create test object
    headers1 = cos_table_make(p, 0);
    headers2 = cos_table_make(p, 0);
    headers3 = cos_table_make(p, 0);
    headers4 = cos_table_make(p, 0);
    headers5 = cos_table_make(p, 0);
    headers6 = cos_table_make(p, 0);
    create_test_object(options, TEST_BUCKET_NAME, object_name1, str, headers1);
    create_test_object(options, TEST_BUCKET_NAME, object_name2, str, headers2);
    create_test_object(options, TEST_BUCKET_NAME, object_name3, str, headers3);
    create_test_object(options, TEST_BUCKET_NAME, object_name4, str, headers4);
    create_test_object(options, TEST_BUCKET_NAME, object_name5, str, headers5);
    create_test_object(options, TEST_BUCKET_NAME, object_name6, str, headers6);

    cos_pool_destroy(p);
}

void test_delete_all_objects()
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
    printf("delete all objects, status code=%d\n", s->code);
    cos_pool_destroy(p);

}

void test_bucket_cleanup(CuTest *tc)
{
    cos_pool_t *p = NULL;
    cos_status_t *s = NULL;
    cos_string_t bucket;
    cos_acl_e cos_acl;
    int is_cname = 0;
    cos_request_options_t *options;
    cos_table_t *resp_headers = NULL;

    test_delete_all_objects();

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_acl = COS_ACL_PRIVATE;
    s = create_test_bucket(options, TEST_BUCKET_NAME, cos_acl);

    s = cos_delete_bucket(options, &bucket, &resp_headers);
    CuAssertIntEquals(tc, 204, s->code);

    cos_pool_destroy(p);

    printf("test_delete_bucket ok\n");
    
}

void test_create_bucket(CuTest *tc)
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_acl_e cos_acl;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_acl = COS_ACL_PRIVATE;

    //create the same bucket twice with same bucket acl
    s = create_test_bucket(options, TEST_BUCKET_NAME, cos_acl);
    CuAssertIntEquals(tc, 409, s->code);
    CuAssertStrEquals(tc, "BucketAlreadyExists", s->error_code);

    printf("test_create_bucket ok\n");
}

void test_delete_bucket(CuTest *tc)
{
    cos_pool_t *p = NULL;
    cos_status_t *s = NULL;
    cos_string_t bucket;
    cos_acl_e cos_acl;
    int is_cname = 0;
    cos_request_options_t *options;
    cos_table_t *resp_headers = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_acl = COS_ACL_PUBLIC_READ;
    s = create_test_bucket(options, TEST_BUCKET_NAME, cos_acl);

    //delete bucket not empty
    s = cos_delete_bucket(options, &bucket, &resp_headers);
    CuAssertIntEquals(tc, 409, s->code);
    CuAssertStrEquals(tc, "BucketNotEmpty", s->error_code);
    CuAssertTrue(tc, s->req_id != NULL);
    CuAssertPtrNotNull(tc, resp_headers);

    cos_pool_destroy(p);

    printf("test_delete_bucket ok\n");
}

void test_bucket_acl(CuTest *tc)
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

    //put acl
    cos_string_t read;
    cos_str_set(&read, "id=\"qcs::cam::uin/12345:uin/12345\", id=\"qcs::cam::uin/45678:uin/45678\"");
    s = cos_put_bucket_acl(options, &bucket, cos_acl, &read, NULL, NULL, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);

    //get acl
    cos_acl_params_t *acl_params = NULL;
    acl_params = cos_create_acl_params(p);
    s = cos_get_bucket_acl(options, &bucket, acl_params, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    printf("acl owner id:%s, name:%s\n", acl_params->owner_id.data, acl_params->owner_name.data);
    cos_acl_grantee_content_t *acl_content = NULL;
    cos_list_for_each_entry(cos_acl_grantee_content_t, acl_content, &acl_params->grantee_list, node) {
        printf("acl grantee id:%s, name:%s, permission:%s\n", acl_content->id.data, acl_content->name.data, acl_content->permission.data);
    }

    cos_pool_destroy(p);
}

void test_bucket_cors(CuTest *tc)
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
    CuAssertIntEquals(tc, 200, s->code);

    //get cors
    cos_list_t rule_list_ret;
    cos_list_init(&rule_list_ret);
    s = cos_get_bucket_cors(options, &bucket, &rule_list_ret, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    cos_cors_rule_content_t *content = NULL;
    cos_list_for_each_entry(cos_cors_rule_content_t, content, &rule_list_ret, node) {
        printf("cors id:%s, allowed_origin:%s, allowed_method:%s, allowed_header:%s, expose_header:%s, max_age_seconds:%d\n",
                content->id.data, content->allowed_origin.data, content->allowed_method.data, content->allowed_header.data, content->expose_header.data, content->max_age_seconds);
    }

    //delete cors
    cos_delete_bucket_cors(options, &bucket, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    
    cos_pool_destroy(p);

}

void test_list_object(CuTest *tc)
{
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    cos_request_options_t *options = NULL;
    int is_cname = 0;
    cos_table_t *resp_headers = NULL;
    cos_status_t *s = NULL;
    cos_list_object_params_t *params = NULL;
    cos_list_object_content_t *content = NULL;
    int size = 0;
    char *key = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    params = cos_create_list_object_params(p);
    params->max_ret = 1;
    params->truncated = 0;
    cos_str_set(&params->prefix, "cos_test");
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    s = cos_list_object(options, &bucket, params, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertIntEquals(tc, 1, params->truncated);
    CuAssertStrEquals(tc, "cos_test_object1", params->next_marker.data);
    CuAssertPtrNotNull(tc, resp_headers);

    cos_list_for_each_entry(cos_list_object_content_t, content, &params->object_list, node) {
        ++size;
        key = apr_psprintf(p, "%.*s", content->key.len, content->key.data);
    }
    CuAssertIntEquals(tc, 1 ,size);
    CuAssertStrEquals(tc, "cos_test_object1", key);
    
    size = 0;
    resp_headers = NULL;
    cos_list_init(&params->object_list);
    cos_str_set(&params->marker, params->next_marker.data);
    s = cos_list_object(options, &bucket, params, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    //CuAssertIntEquals(tc, 0, params->truncated);
    cos_list_for_each_entry(cos_list_object_content_t, content, &params->object_list, node) {
        ++size;
        key = apr_psprintf(p, "%.*s", content->key.len, content->key.data);
    }
    CuAssertIntEquals(tc, 1 ,size);
    CuAssertStrEquals(tc, "cos_test_object2", key);
    CuAssertPtrNotNull(tc, resp_headers);
    cos_pool_destroy(p);

    printf("test_list_object ok\n");
}

void test_list_object_with_delimiter(CuTest *tc)
{
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    cos_request_options_t *options = NULL;
    int is_cname = 0;
    cos_table_t *resp_headers = NULL;
    cos_status_t *s = NULL;
    cos_list_object_params_t *params = NULL;
    cos_list_object_common_prefix_t *common_prefix = NULL;
    int size = 0;
    char *prefix = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    params = cos_create_list_object_params(p);
    params->max_ret = 5;
    params->truncated = 0;
    cos_str_set(&params->prefix, "cos_tmp");
    cos_str_set(&params->delimiter, "/");
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    s = cos_list_object(options, &bucket, params, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertIntEquals(tc, 0, params->truncated);
    CuAssertPtrNotNull(tc, resp_headers);

    cos_list_for_each_entry(cos_list_object_common_prefix_t, common_prefix, &params->common_prefix_list, node) {
        ++size;
        prefix = apr_psprintf(p, "%.*s", common_prefix->prefix.len, 
                              common_prefix->prefix.data);
        if (size == 1) {
            CuAssertStrEquals(tc, "cos_tmp1/", prefix);
        } else if(size == 2) {
            CuAssertStrEquals(tc, "cos_tmp2/", prefix);
        }
    }
    CuAssertIntEquals(tc, 2, size);
    cos_pool_destroy(p);

    printf("test_list_object_with_delimiter ok\n");
}

void test_lifecycle(CuTest *tc)
{
    cos_pool_t *p = NULL;
    cos_string_t bucket;
    int is_cname = 0;
    cos_request_options_t *options = NULL;
    cos_table_t *resp_headers = NULL;
    cos_status_t *s = NULL;
    cos_list_t lifecycle_rule_list;
    cos_lifecycle_rule_content_t *invalid_rule_content = NULL;
    cos_lifecycle_rule_content_t *rule_content = NULL;
    cos_lifecycle_rule_content_t *rule_content1 = NULL;
    cos_lifecycle_rule_content_t *rule_content2 = NULL;
    int size = 0;
    char *rule_id = NULL;
    char *prefix = NULL;
    char *status = NULL;
    int days = INT_MAX;
    char* date = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);

    //put invalid lifecycle rule
    cos_list_init(&lifecycle_rule_list);
    invalid_rule_content = cos_create_lifecycle_rule_content(p);
    cos_str_set(&invalid_rule_content->id, "");
    cos_str_set(&invalid_rule_content->prefix, "pre");
    cos_list_add_tail(&invalid_rule_content->node, &lifecycle_rule_list);
    s = cos_put_bucket_lifecycle(options, &bucket, &lifecycle_rule_list, 
                                 &resp_headers);
    CuAssertIntEquals(tc, 400, s->code);
    CuAssertPtrNotNull(tc, resp_headers);

    //put lifecycle
    resp_headers = NULL;
    cos_list_init(&lifecycle_rule_list);
    rule_content1 = cos_create_lifecycle_rule_content(p);
    cos_str_set(&rule_content1->id, "1");
    cos_str_set(&rule_content1->prefix, "pre1");
    cos_str_set(&rule_content1->status, "Enabled");
    rule_content1->expire.days = 1;
    rule_content2 = cos_create_lifecycle_rule_content(p);
    cos_str_set(&rule_content2->id, "2");
    cos_str_set(&rule_content2->prefix, "pre2");
    cos_str_set(&rule_content2->status, "Enabled");
    cos_str_set(&rule_content2->expire.date, "2022-10-11T00:00:00+08:00");
    cos_list_add_tail(&rule_content1->node, &lifecycle_rule_list);
    cos_list_add_tail(&rule_content2->node, &lifecycle_rule_list);

    s = cos_put_bucket_lifecycle(options, &bucket, &lifecycle_rule_list, 
                                 &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, resp_headers);

    //get lifecycle
    resp_headers = NULL;
    cos_list_init(&lifecycle_rule_list);
    s = cos_get_bucket_lifecycle(options, &bucket, &lifecycle_rule_list, 
                                 &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, resp_headers);

    cos_list_for_each_entry(cos_lifecycle_rule_content_t, rule_content, &lifecycle_rule_list, node) {
        if (size == 0) {
            rule_id = apr_psprintf(p, "%.*s", rule_content->id.len, 
                    rule_content->id.data);
            CuAssertStrEquals(tc, "1", rule_id);
            prefix = apr_psprintf(p, "%.*s", rule_content->prefix.len, 
                    rule_content->prefix.data);
            CuAssertStrEquals(tc, "pre1", prefix);
            date = apr_psprintf(p, "%.*s", rule_content->expire.date.len, 
                    rule_content->expire.date.data);
            CuAssertStrEquals(tc, "", date);
            status = apr_psprintf(p, "%.*s", rule_content->status.len, 
                    rule_content->status.data);
            CuAssertStrEquals(tc, "Enabled", status);
            days = rule_content->expire.days;
            CuAssertIntEquals(tc, 1, days);
        }
        else if (size == 1){
            rule_id = apr_psprintf(p, "%.*s", rule_content->id.len, 
                    rule_content->id.data);
            CuAssertStrEquals(tc, "2", rule_id);
            prefix = apr_psprintf(p, "%.*s", rule_content->prefix.len, 
                    rule_content->prefix.data);
            CuAssertStrEquals(tc, "pre2", prefix);
            date = apr_psprintf(p, "%.*s", rule_content->expire.date.len, 
                    rule_content->expire.date.data);
            CuAssertStrEquals(tc, "2022-10-11T00:00:00+08:00", date);
            status = apr_psprintf(p, "%.*s", rule_content->status.len, 
                    rule_content->status.data);
            CuAssertStrEquals(tc, "Enabled", status);
            days = rule_content->expire.days;
            CuAssertIntEquals(tc, INT_MAX, days);
        }
        ++size;
    }
    CuAssertIntEquals(tc, 2 ,size);

    //delete lifecycle
    resp_headers = NULL;
    s = cos_delete_bucket_lifecycle(options, &bucket, &resp_headers);
    CuAssertIntEquals(tc, 204, s->code);
    CuAssertPtrNotNull(tc, resp_headers);
    cos_pool_destroy(p);

    printf("test_lifecycle ok\n");
}

void test_delete_objects_quiet(CuTest *tc)
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_string_t bucket;
    cos_status_t *s = NULL;
    cos_table_t *resp_headers = NULL;
    cos_request_options_t *options = NULL;
    char *object_name1 = "cos_test_object1";
    char *object_name2 = "cos_test_object2";
    cos_object_key_t *content1 = NULL;
    cos_object_key_t *content2 = NULL;
    cos_list_t object_list;
    cos_list_t deleted_object_list;
    int is_quiet = 1;

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

    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, resp_headers);
    cos_pool_destroy(p);

    printf("test_delete_objects_quiet ok\n");
}

void test_delete_objects_not_quiet(CuTest *tc)
{
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_string_t bucket;
    cos_status_t *s = NULL;
    cos_table_t *resp_headers = NULL;
    cos_request_options_t *options = NULL;
    char *object_name1 = "cos_tmp1/";
    char *object_name2 = "cos_tmp2/";
    cos_object_key_t *content = NULL;
    cos_object_key_t *content1 = NULL;
    cos_object_key_t *content2 = NULL;
    cos_list_t object_list;
    cos_list_t deleted_object_list;
    int is_quiet = 0;
    
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

    CuAssertIntEquals(tc, 200, s->code);
    CuAssertPtrNotNull(tc, resp_headers);

    cos_list_for_each_entry(cos_object_key_t, content, &deleted_object_list, node) {
        printf("Deleted key:%.*s\n", content->key.len, content->key.data);
    }
    cos_pool_destroy(p);

    printf("test_delete_objects_not_quiet ok\n");
}

void test_delete_objects_by_prefix(CuTest *tc)
{
    cos_pool_t *p = NULL;
    cos_request_options_t *options = NULL;
    int is_cname = 0;
    cos_string_t bucket;
    cos_status_t *s = NULL;
    cos_string_t prefix;
    char *prefix_str = "cos_tmp3/";
    
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);
    cos_str_set(&prefix, prefix_str);

    s = cos_delete_objects_by_prefix(options, &bucket, &prefix);
    CuAssertIntEquals(tc, 200, s->code);
    cos_pool_destroy(p);

    printf("test_delete_object_by_prefix ok\n");
}

CuSuite *test_cos_bucket()
{
    CuSuite* suite = CuSuiteNew();

    SUITE_ADD_TEST(suite, test_bucket_setup);
    SUITE_ADD_TEST(suite, test_create_bucket);
    //SUITE_ADD_TEST(suite, test_put_bucket_acl);
    //SUITE_ADD_TEST(suite, test_get_bucket_acl);
    SUITE_ADD_TEST(suite, test_delete_objects_by_prefix);
    SUITE_ADD_TEST(suite, test_list_object);
    SUITE_ADD_TEST(suite, test_list_object_with_delimiter);
    SUITE_ADD_TEST(suite, test_lifecycle);
    SUITE_ADD_TEST(suite, test_bucket_acl);
    SUITE_ADD_TEST(suite, test_bucket_cors);
    SUITE_ADD_TEST(suite, test_delete_objects_quiet);
    SUITE_ADD_TEST(suite, test_delete_objects_not_quiet);
    SUITE_ADD_TEST(suite, test_delete_bucket);
    SUITE_ADD_TEST(suite, test_bucket_cleanup);

    return suite;
}
