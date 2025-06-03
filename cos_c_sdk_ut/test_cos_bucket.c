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

void log_status(cos_status_t *s) {
    cos_warn_log("status->code: %d", s->code);
    if (s->error_code) cos_warn_log("status->error_code: %s", s->error_code);
    if (s->error_msg) cos_warn_log("status->error_msg: %s", s->error_msg);
    if (s->req_id) cos_warn_log("status->req_id: %s", s->req_id);
}
void test_bucket_setup(CuTest *tc) {
    fprintf(stderr, "==========test_bucket_setup==========\n");
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
    cos_log_set_level(COS_LOG_DEBUG);

    //set log output, default stderr
    cos_log_set_output(NULL);

    //create test bucket
    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    s = create_test_bucket(options, TEST_BUCKET_NAME, cos_acl);

    log_status(s);
    CuAssertIntEquals(tc, 200, s->code);
    CuAssertStrEquals(tc, NULL, s->error_code);

    //create test object
    headers1 = cos_table_make(p, 0);
    headers2 = cos_table_make(p, 0);
    headers3 = cos_table_make(p, 0);
    headers4 = cos_table_make(p, 0);
    headers5 = cos_table_make(p, 0);
    headers6 = cos_table_make(p, 0);
    s = create_test_object(options, TEST_BUCKET_NAME, object_name1, str, headers1);
    log_status(s);
    s = create_test_object(options, TEST_BUCKET_NAME, object_name2, str, headers2);
    log_status(s);
    s = create_test_object(options, TEST_BUCKET_NAME, object_name3, str, headers3);
    log_status(s);
    s = create_test_object(options, TEST_BUCKET_NAME, object_name4, str, headers4);
    log_status(s);
    s = create_test_object(options, TEST_BUCKET_NAME, object_name5, str, headers5);
    log_status(s);
    s = create_test_object(options, TEST_BUCKET_NAME, object_name6, str, headers6);
    log_status(s);

    cos_pool_destroy(p);
    fprintf(stderr, "==========test_bucket_setup==========\n");
}

void test_delete_all_objects() {
    fprintf(stderr, "==========test_delete_all_objects==========\n");
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
    log_status(s);
    cos_pool_destroy(p);
    fprintf(stderr, "==========test_delete_all_objects==========\n");

}
void test_bucket_delete(CuTest *tc) {
    fprintf(stderr, "==========test_bucket_delete==========\n");
    cos_pool_t *p = NULL;
    cos_status_t *s = NULL;
    cos_string_t bucket;
    int is_cname = 0;
    cos_request_options_t *options;
    cos_table_t *resp_headers = NULL;

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);

    s = cos_delete_bucket(options, &bucket, &resp_headers);
    CuAssertIntEquals(tc, 204, s->code);
    log_status(s);

    cos_pool_destroy(p);

    printf("test_bucket_delete ok\n");

    fprintf(stderr, "==========test_bucket_delete==========\n");
}

void test_bucket_cleanup(CuTest *tc) {
    fprintf(stderr, "==========test_bucket_cleanup==========\n");
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_request_options_t *options;

    test_delete_all_objects();

    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);

    abort_all_test_multipart_upload(options, TEST_BUCKET_NAME);

    cos_pool_destroy(p);

    printf("test_delete_bucket ok\n");

    fprintf(stderr, "==========test_bucket_cleanup==========\n");
}

void test_create_bucket(CuTest *tc) {
    fprintf(stderr, "==========test_create_bucket==========\n");
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
    log_status(s);
    CuAssertStrEquals(tc, "BucketAlreadyExists", s->error_code);

    printf("test_create_bucket ok\n");
    fprintf(stderr, "==========test_create_bucket==========\n");
}

void test_delete_bucket(CuTest *tc) {
    fprintf(stderr, "==========test_delete_bucket==========\n");
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
    log_status(s);
    CuAssertStrEquals(tc, "BucketNotEmpty", s->error_code);
    CuAssertTrue(tc, s->req_id != NULL);
    CuAssertPtrNotNull(tc, resp_headers);

    cos_pool_destroy(p);

    printf("test_delete_bucket ok\n");
    fprintf(stderr, "==========test_delete_bucket==========\n");
}

void test_bucket_acl(CuTest *tc) {
    fprintf(stderr, "==========test_bucket_acl==========\n");
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
    log_status(s);

    //get acl
    cos_acl_params_t *acl_params = NULL;
    acl_params = cos_create_acl_params(p);
    s = cos_get_bucket_acl(options, &bucket, acl_params, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    printf("acl owner id:%s, name:%s\n", acl_params->owner_id.data, acl_params->owner_name.data);
    cos_acl_grantee_content_t *acl_content = NULL;
    cos_list_for_each_entry(cos_acl_grantee_content_t, acl_content, &acl_params->grantee_list, node) {
        printf("acl grantee id:%s, name:%s, permission:%s\n", acl_content->id.data, acl_content->name.data, acl_content->permission.data);
    }

    cos_pool_destroy(p);
    fprintf(stderr, "==========test_bucket_acl==========\n");
}

void test_bucket_cors(CuTest *tc) {
    fprintf(stderr, "==========test_bucket_cors==========\n");
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
    log_status(s);

    //get cors
    cos_list_t rule_list_ret;
    cos_list_init(&rule_list_ret);
    s = cos_get_bucket_cors(options, &bucket, &rule_list_ret, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    cos_cors_rule_content_t *content = NULL;
    cos_list_for_each_entry(cos_cors_rule_content_t, content, &rule_list_ret, node) {
        printf("cors id:%s, allowed_origin:%s, allowed_method:%s, allowed_header:%s, expose_header:%s, max_age_seconds:%d\n",
                content->id.data, content->allowed_origin.data, content->allowed_method.data, content->allowed_header.data, content->expose_header.data, content->max_age_seconds);
    }

    //delete cors
    cos_delete_bucket_cors(options, &bucket, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    log_status(s);

    cos_pool_destroy(p);
    fprintf(stderr, "==========test_bucket_cors==========\n");

}

void test_list_object(CuTest *tc) {
    fprintf(stderr, "==========test_list_object==========\n");
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
    log_status(s);
    CuAssertIntEquals(tc, 1, params->truncated);
    CuAssertStrEquals(tc, "cos_test_object1", params->next_marker.data);
    CuAssertPtrNotNull(tc, resp_headers);

    cos_list_for_each_entry(cos_list_object_content_t, content, &params->object_list, node) {
        ++size;
        key = apr_psprintf(p, "%.*s", content->key.len, content->key.data);
    }
    CuAssertIntEquals(tc, 1, size);
    CuAssertStrEquals(tc, "cos_test_object1", key);

    size = 0;
    resp_headers = NULL;
    cos_list_init(&params->object_list);
    if (params->next_marker.data) {
        cos_str_set(&params->marker, params->next_marker.data);
    }
    s = cos_list_object(options, &bucket, params, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    //CuAssertIntEquals(tc, 0, params->truncated);
    cos_list_for_each_entry(cos_list_object_content_t, content, &params->object_list, node) {
        ++size;
        key = apr_psprintf(p, "%.*s", content->key.len, content->key.data);
    }
    CuAssertIntEquals(tc, 1, size);
    CuAssertStrEquals(tc, "cos_test_object2", key);
    CuAssertPtrNotNull(tc, resp_headers);
    cos_pool_destroy(p);

    printf("test_list_object ok\n");
    fprintf(stderr, "==========test_list_object==========\n");
}

void test_list_object_with_delimiter(CuTest *tc) {
    fprintf(stderr, "==========test_list_object_with_delimiter==========\n");
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
    log_status(s);
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
    fprintf(stderr, "==========test_list_object_with_delimiter==========\n");
}

void test_lifecycle(CuTest *tc) {
    fprintf(stderr, "==========test_lifecycle==========\n");
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
    log_status(s);
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
    cos_str_set(&rule_content2->transition.storage_class, "STANDARD_IA");
    rule_content2->transition.days = 100;
    //cos_str_set(&rule_content2->expire.date, "2022-10-11T00:00:00+08:00");
    cos_list_add_tail(&rule_content1->node, &lifecycle_rule_list);
    cos_list_add_tail(&rule_content2->node, &lifecycle_rule_list);

    s = cos_put_bucket_lifecycle(options, &bucket, &lifecycle_rule_list,
                                 &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);

    //get lifecycle
    resp_headers = NULL;
    cos_list_init(&lifecycle_rule_list);
    s = cos_get_bucket_lifecycle(options, &bucket, &lifecycle_rule_list,
                                 &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
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
        else if (size == 1) {
            rule_id = apr_psprintf(p, "%.*s", rule_content->id.len,
                    rule_content->id.data);
            CuAssertStrEquals(tc, "2", rule_id);
            prefix = apr_psprintf(p, "%.*s", rule_content->prefix.len,
                    rule_content->prefix.data);
            CuAssertStrEquals(tc, "pre2", prefix);
            date = apr_psprintf(p, "%.*s", rule_content->expire.date.len,
                    rule_content->expire.date.data);
            // CuAssertStrEquals(tc, "2022-10-10T16:00:00.000Z", date);
            status = apr_psprintf(p, "%.*s", rule_content->status.len,
                    rule_content->status.data);
            CuAssertStrEquals(tc, "Enabled", status);
            days = rule_content->expire.days;
            CuAssertIntEquals(tc, INT_MAX, days);
        }
        ++size;
    }
    CuAssertIntEquals(tc, 2, size);

    //delete lifecycle
    resp_headers = NULL;
    s = cos_delete_bucket_lifecycle(options, &bucket, &resp_headers);
    CuAssertIntEquals(tc, 204, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);
    cos_pool_destroy(p);

    printf("test_lifecycle ok\n");
    fprintf(stderr, "==========test_lifecycle==========\n");
}

void test_delete_objects_quiet(CuTest *tc) {
    fprintf(stderr, "==========test_delete_objects_quiet==========\n");
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
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);
    cos_pool_destroy(p);

    printf("test_delete_objects_quiet ok\n");
    fprintf(stderr, "==========test_delete_objects_quiet==========\n");
}

void test_delete_objects_not_quiet(CuTest *tc) {
    fprintf(stderr, "==========test_delete_objects_not_quiet==========\n");
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
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);

    cos_list_for_each_entry(cos_object_key_t, content, &deleted_object_list, node) {
        printf("Deleted key:%.*s\n", content->key.len, content->key.data);
    }
    cos_pool_destroy(p);

    printf("test_delete_objects_not_quiet ok\n");
    fprintf(stderr, "==========test_delete_objects_not_quiet==========\n");
}

void test_delete_objects_by_prefix(CuTest *tc) {
    fprintf(stderr, "==========test_delete_objects_by_prefix==========\n");
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
    log_status(s);
    cos_pool_destroy(p);

    printf("test_delete_object_by_prefix ok\n");
    fprintf(stderr, "==========test_delete_objects_by_prefix==========\n");
}

void test_put_bucket_acl(CuTest *tc) {
    fprintf(stderr, "==========test_put_bucket_acl==========\n");
    cos_pool_t *p = NULL;
    cos_request_options_t *options = NULL;
    cos_table_t *resp_headers = NULL;
    int is_cname = 0;
    cos_string_t bucket;
    cos_status_t *s = NULL;
    cos_string_t grant_read;
    cos_string_t grant_write;
    cos_string_t grant_full_control;


    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);

    cos_str_set(&grant_read, "id=\"2779643970\"");
    cos_str_set(&grant_write, "id=\"2779643970\"");
    cos_str_set(&grant_full_control, "id=\"2779643970\"");

    s = cos_put_bucket_acl(options, &bucket, COS_ACL_PRIVATE,
                            &grant_read, &grant_write, &grant_full_control, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);
    cos_pool_destroy(p);

    printf("test_put_bucket_acl ok\n");
    fprintf(stderr, "==========test_put_bucket_acl==========\n");
}

void test_get_bucket_acl(CuTest *tc) {
    fprintf(stderr, "==========test_get_bucket_acl==========\n");
    cos_pool_t *p = NULL;
    cos_request_options_t *options = NULL;
    cos_table_t *resp_headers = NULL;
    int is_cname = 0;
    cos_string_t bucket;
    cos_status_t *s = NULL;
    cos_acl_params_t *acl_param = NULL;


    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);

    acl_param = cos_create_acl_params(p);

    s = cos_get_bucket_acl(options, &bucket, acl_param, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);
    cos_pool_destroy(p);

    printf("test_get_bucket_acl ok\n");
    fprintf(stderr, "==========test_get_bucket_acl==========\n");
}

void test_get_service(CuTest *tc) {
    fprintf(stderr, "==========test_get_service==========\n");
    cos_pool_t *p = NULL;
    cos_request_options_t *options = NULL;
    cos_table_t *resp_headers = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_get_service_params_t *get_service_param = NULL;


    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);

    get_service_param = cos_create_get_service_params(p);

    s = cos_get_service(options, get_service_param, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);
    cos_pool_destroy(p);

    printf("test_get_service ok\n");
    fprintf(stderr, "==========test_get_service==========\n");
}

void test_head_bucket(CuTest *tc) {
    fprintf(stderr, "==========test_head_bucket==========\n");
    cos_pool_t *p = NULL;
    cos_request_options_t *options = NULL;
    cos_table_t *resp_headers = NULL;
    int is_cname = 0;
    cos_string_t bucket;
    cos_status_t *s = NULL;


    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);

    s = cos_head_bucket(options, &bucket, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);
    cos_pool_destroy(p);

    printf("test_head_bucket ok\n");
    fprintf(stderr, "==========test_head_bucket==========\n");
}

void test_check_bucket_exist(CuTest *tc) {
    fprintf(stderr, "==========test_check_bucket_exist==========\n");
    cos_pool_t *p = NULL;
    cos_request_options_t *options = NULL;
    cos_table_t *resp_headers = NULL;
    int is_cname = 0;
    cos_string_t bucket;
    cos_bucket_exist_status_e bucket_exist;
    cos_status_t *s = NULL;


    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);

    s = cos_check_bucket_exist(options, &bucket, &bucket_exist, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);
    cos_pool_destroy(p);

    printf("test_check_bucket_exist ok\n");
    fprintf(stderr, "==========test_check_bucket_exist==========\n");
}

void test_check_bucket_exist_not_find(CuTest *tc) {
    fprintf(stderr, "==========test_check_bucket_exist_not_find==========\n");
    cos_pool_t *p = NULL;
    cos_request_options_t *options = NULL;
    cos_table_t *resp_headers = NULL;
    int is_cname = 0;
    cos_string_t bucket;
    cos_bucket_exist_status_e bucket_exist;
    cos_status_t *s = NULL;


    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, "adahjrvfiaidsuv");

    s = cos_check_bucket_exist(options, &bucket, &bucket_exist, &resp_headers);
    CuAssertIntEquals(tc, 404, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);
    cos_pool_destroy(p);

    printf("test_check_bucket_exist_not_find ok\n");
    fprintf(stderr, "==========test_check_bucket_exist_not_find==========\n");
}

void test_bucket_versioning(CuTest *tc) {
    fprintf(stderr, "==========test_bucket_versioning==========\n");
    cos_pool_t *p = NULL;
    cos_request_options_t *options = NULL;
    cos_table_t *resp_headers = NULL;
    int is_cname = 0;
    cos_string_t bucket;
    cos_status_t *s = NULL;


    cos_pool_create(&p, NULL);
    options = cos_request_options_create(p);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);

    cos_versioning_content_t *versioning = NULL;
    versioning = cos_create_versioning_content(p);
    cos_str_set(&versioning->status, "Enabled");

    //put bucket versioning
    s = cos_put_bucket_versioning(options, &bucket, versioning, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);

    //get bucket versioning
    cos_str_set(&versioning->status, "");
    s = cos_get_bucket_versioning(options, &bucket, versioning, &resp_headers);
    CuAssertStrnEquals(tc, "Enabled", sizeof("Enabled") - 1, versioning->status.data);
    CuAssertPtrNotNull(tc, resp_headers);

    cos_str_set(&versioning->status, "Suspended");
    s = cos_put_bucket_versioning(options, &bucket, versioning, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);

    cos_pool_destroy(p);

    printf("test_bucket_versioning ok\n");
    fprintf(stderr, "==========test_bucket_versioning==========\n");
}

void test_bucket_replication(CuTest *tc) {
    fprintf(stderr, "==========test_bucket_replication==========\n");
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
    cos_str_set(&dst_bucket, "replicationtest-gz-1253960454");

    dst_options = cos_request_options_create(p);
    init_test_request_options(dst_options, is_cname);

    //enable bucket versioning
    cos_versioning_content_t *versioning = NULL;
    versioning = cos_create_versioning_content(p);
    cos_str_set(&versioning->status, "Enabled");
    s = cos_put_bucket_versioning(options, &bucket, versioning, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);
    s = cos_create_bucket(dst_options, &dst_bucket, COS_ACL_PRIVATE, &resp_headers);
    s = cos_put_bucket_versioning(dst_options, &dst_bucket, versioning, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);

    cos_replication_params_t *replication_param = NULL;
    replication_param = cos_create_replication_params(p);
    cos_str_set(&replication_param->role, "qcs::cam::uin/2832742109:uin/2832742109");

    cos_replication_rule_content_t *rule = NULL;
    rule = cos_create_replication_rule_content(p);
    cos_str_set(&rule->id, "Rule_01");
    cos_str_set(&rule->status, "Enabled");
    cos_str_set(&rule->prefix, "test1");
    cos_str_set(&rule->dst_bucket, "qcs:id/0:cos:ap-beijing:appid/1253960454:replicationtest");
    cos_str_set(&rule->storage_class, "Standard");
    cos_list_add_tail(&rule->node, &replication_param->rule_list);

    //put bucket replication
    s = cos_put_bucket_replication(options, &bucket, replication_param, &resp_headers);
    //CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);

    //get bucket replication
    cos_replication_params_t *replication_param2 = NULL;
    replication_param2 = cos_create_replication_params(p);
    s = cos_get_bucket_replication(options, &bucket, replication_param2, &resp_headers);
    //CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);
    printf("ReplicationConfiguration role: %s\n", replication_param2->role.data);
    cos_replication_rule_content_t *content = NULL;
    cos_list_for_each_entry(cos_replication_rule_content_t, content, &replication_param2->rule_list, node) {
        printf("ReplicationConfiguration rule, id:%s, status:%s, prefix:%s, dst_bucket:%s, storage_class:%s\n",
                content->id.data, content->status.data, content->prefix.data, content->dst_bucket.data, content->storage_class.data);
    }

    //delete bucket replication
    s = cos_delete_bucket_replication(options, &bucket, &resp_headers);
    CuAssertIntEquals(tc, 204, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);

    //disable bucket versioning
    cos_str_set(&versioning->status, "Suspended");
    s = cos_put_bucket_versioning(options, &bucket, versioning, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);
    s = cos_put_bucket_versioning(dst_options, &dst_bucket, versioning, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);

    cos_pool_destroy(p);

    printf("test_bucket_replication ok\n");
    fprintf(stderr, "==========test_bucket_replication==========\n");
}

void test_bucket_website(CuTest *tc) {
    fprintf(stderr, "==========test_bucket_website==========\n");
    cos_pool_t *pool = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
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
    init_test_request_options(options, is_cname);
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

    s = cos_put_bucket_website(options, &bucket, website_params, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);

    website_result = cos_create_website_params(options->pool);
    s = cos_get_bucket_website(options, &bucket, website_result, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);

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

    s = cos_delete_bucket_website(options, &bucket, &resp_headers);
    CuAssertIntEquals(tc, 204, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);

    cos_pool_destroy(pool);

    printf("test_bucket_website ok\n");
    fprintf(stderr, "==========test_bucket_website==========\n");
}

void test_bucket_domain(CuTest *tc) {
    fprintf(stderr, "==========test_bucket_domain==========\n");
    cos_pool_t *pool = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
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
    cos_str_set(&domain_params->status, "DISABLED");
    cos_str_set(&domain_params->name, "csdktestut.ap-guangzhou.cos-test.cn");
    cos_str_set(&domain_params->type, "REST");
    cos_str_set(&domain_params->forced_replacement, "CNAME");

    s = cos_put_bucket_domain(options, &bucket, domain_params, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);

    domain_result = cos_create_domain_params(options->pool);
    s = cos_get_bucket_domain(options, &bucket, domain_result, &resp_headers);
    CuAssertPtrNotNull(tc, resp_headers);

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

    printf("test_bucket_domain ok\n");
    fprintf(stderr, "==========test_bucket_domain==========\n");
}

void test_bucket_logging(CuTest *tc) {
    fprintf(stderr, "==========test_bucket_logging==========\n");
    cos_pool_t *pool = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_logging_params_t  *params = NULL;
    cos_logging_params_t  *result = NULL;
    cos_table_t *resp_headers = NULL;
    cos_string_t bucket;

    //创建内存池
    cos_pool_create(&pool, NULL);

    //初始化请求选项
    options = cos_request_options_create(pool);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);

    //创建logging参数
    params = cos_create_logging_params(options->pool);
    cos_str_set(&params->target_bucket, TEST_BUCKET_NAME);
    cos_str_set(&params->target_prefix, "logging/");

    s = cos_put_bucket_logging(options, &bucket, params, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);

    result = cos_create_logging_params(options->pool);
    s = cos_get_bucket_logging(options, &bucket, result, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);

    //查看结果
    char *line = NULL;
    line = apr_psprintf(options->pool, "%.*s\n", result->target_bucket.len, result->target_bucket.data);
    printf("target bucket: %s", line);
    line = apr_psprintf(options->pool, "%.*s\n", result->target_prefix.len, result->target_prefix.data);
    printf("target prefix: %s", line);

    cos_pool_destroy(pool);

    printf("test_bucket_logging ok\n");
    fprintf(stderr, "==========test_bucket_logging==========\n");
}

void test_bucket_inventory(CuTest *tc) {
    fprintf(stderr, "==========test_bucket_inventory==========\n");
    cos_pool_t *pool = NULL;
    int is_cname = 0;
    int inum = 1, i, len;
    char buf[inum][32];
    char dest_bucket[128];
    cos_status_t *s = NULL;
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
        params->destination.encryption = 0;
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

        s = cos_put_bucket_inventory(options, &bucket, params, &resp_headers);
        CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
        CuAssertPtrNotNull(tc, resp_headers);
    }

    // get inventory
    get_params = cos_create_inventory_params(pool);
    cos_str_set(&get_params->id, buf[inum/2]);
    s = cos_get_bucket_inventory(options, &bucket, get_params, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);

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
    s = cos_list_bucket_inventory(options, &bucket, list_params, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);

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
        s = cos_delete_bucket_inventory(options, &bucket, &id, &resp_headers);
        CuAssertIntEquals(tc, 204, s->code);
    log_status(s);
        CuAssertPtrNotNull(tc, resp_headers);
    }

    cos_pool_destroy(pool);

    printf("test_bucket_inventory ok\n");
    fprintf(stderr, "==========test_bucket_inventory==========\n");
}

void test_bucket_tagging(CuTest *tc) {
    fprintf(stderr, "==========test_bucket_tagging==========\n");
    cos_pool_t *pool = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
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
    init_test_request_options(options, is_cname);
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

    s = cos_put_bucket_tagging(options, &bucket, params, &resp_headers);
    CuAssertIntEquals(tc, 204, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);

    // get tagging
    result = cos_create_tagging_params(pool);
    s = cos_get_bucket_tagging(options, &bucket, result, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);

    tag = NULL;
    cos_list_for_each_entry(cos_tagging_tag_t, tag, &result->node, node) {
        printf("taging key: %s\n", tag->key.data);
        printf("taging value: %s\n", tag->value.data);

    }

    // delete tagging
    s = cos_delete_bucket_tagging(options, &bucket, &resp_headers);
    CuAssertIntEquals(tc, 204, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);

    cos_pool_destroy(pool);

    printf("test_bucket_tagging ok\n");
    fprintf(stderr, "==========test_bucket_tagging==========\n");
}

void test_bucket_referer(CuTest *tc) {
    fprintf(stderr, "==========test_bucket_referer==========\n");
    cos_pool_t *pool = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_table_t *resp_headers = NULL;
    cos_string_t bucket;
    cos_referer_params_t *params = NULL;
    cos_referer_domain_t *domain = NULL;
    cos_referer_params_t *result = NULL;

    //创建内存池
    cos_pool_create(&pool, NULL);

    //初始化请求选项
    options = cos_request_options_create(pool);
    init_test_request_options(options, is_cname);
    cos_str_set(&bucket, TEST_BUCKET_NAME);

    // 替换为您的配置信息，可参见文档 https://cloud.tencent.com/document/product/436/32492
    params = cos_create_referer_params(pool);
    cos_str_set(&params->status, "Disabled");
    cos_str_set(&params->referer_type, "White-List");
    cos_str_set(&params->empty_refer_config, "Allow");
    domain = cos_create_referer_domain(pool);
    cos_str_set(&domain->domain, "www.qq.com");
    cos_list_add_tail(&domain->node, &params->domain_list);
    domain = cos_create_referer_domain(pool);
    cos_str_set(&domain->domain, "*.tencent.com");
    cos_list_add_tail(&domain->node, &params->domain_list);

    // put referer
    s = cos_put_bucket_referer(options, &bucket, params, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);

    // get referer
    result = cos_create_referer_params(pool);
    s = cos_get_bucket_referer(options, &bucket, result, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    //log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);

    cos_pool_destroy(pool);

    printf("test_bucket_referer ok\n");
    fprintf(stderr, "==========test_bucket_referer==========\n");
}

void test_bucket_intelligenttiering(CuTest *tc) {
    fprintf(stderr, "==========test_bucket_intelligenttiering==========\n");
    cos_pool_t *pool = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
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

    s = cos_put_bucket_intelligenttiering(options, &bucket, params, &resp_headers);
   // CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);

    // get intelligenttiering
    result = cos_create_intelligenttiering_params(pool);
    s = cos_get_bucket_intelligenttiering(options, &bucket, result, &resp_headers);
    CuAssertIntEquals(tc, 200, s->code);
    log_status(s);
    CuAssertPtrNotNull(tc, resp_headers);

    printf("status: %s\n", result->status.data);
    printf("days: %d\n", result->days);
    cos_pool_destroy(pool);

    printf("test_bucket_intelligenttiering ok\n");
    fprintf(stderr, "==========test_bucket_intelligenttiering==========\n");
}

CuSuite *test_cos_bucket() {
    CuSuite* suite = CuSuiteNew();

    SUITE_ADD_TEST(suite, test_bucket_setup);
    SUITE_ADD_TEST(suite, test_create_bucket);
    SUITE_ADD_TEST(suite, test_get_service);
    SUITE_ADD_TEST(suite, test_head_bucket);
    SUITE_ADD_TEST(suite, test_check_bucket_exist);
    SUITE_ADD_TEST(suite, test_check_bucket_exist_not_find);
    SUITE_ADD_TEST(suite, test_bucket_referer);
    SUITE_ADD_TEST(suite, test_bucket_website);
    SUITE_ADD_TEST(suite, test_bucket_intelligenttiering);
    SUITE_ADD_TEST(suite, test_bucket_domain);
    SUITE_ADD_TEST(suite, test_bucket_logging);
    SUITE_ADD_TEST(suite, test_bucket_inventory);
    SUITE_ADD_TEST(suite, test_bucket_tagging);
    SUITE_ADD_TEST(suite, test_put_bucket_acl);
    SUITE_ADD_TEST(suite, test_get_bucket_acl);
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
    SUITE_ADD_TEST(suite, test_bucket_versioning);
    SUITE_ADD_TEST(suite, test_bucket_replication);
    SUITE_ADD_TEST(suite, test_bucket_delete);

    return suite;
}
