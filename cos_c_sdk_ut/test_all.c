#include "CuTest.h"
#include "cos_log.h"
#include "cos_http_io.h"
#include "cos_config.h"

extern CuSuite *test_xml();
extern CuSuite *test_util();
extern CuSuite *test_file();
extern CuSuite *test_transport();
extern CuSuite *test_cos_bucket();
extern CuSuite *test_cos_object();
extern CuSuite *test_cos_multipart();
extern CuSuite *test_cos_progress();
extern CuSuite *test_cos_callback();
extern CuSuite *test_cos_util();
extern CuSuite *test_cos_xml();
extern CuSuite *test_cos_crc();
extern CuSuite *test_cos_sys();
extern CuSuite *test_cos_resumable();
extern CuSuite *test_cos_retry();

static const struct testlist {
    const char *testname;
    CuSuite *(*func)();
} tests[] = {
    {"test_cos_bucket", test_cos_bucket},
    {"test_cos_object", test_cos_object},
    {"test_cos_multipart", test_cos_multipart},
    {"test_cos_progress", test_cos_progress},
    {"test_cos_resumable", test_cos_resumable},
    {"test_cos_crc", test_cos_crc},
    {"test_cos_sys", test_cos_sys},
    {"test_cos_retry", test_cos_retry},
    {"LastTest", NULL}
};

int run_all_tests(int argc, char *argv[]) {
    int i;
    int exit_code;
    int list_provided = 0;
    CuSuite* suite = NULL;
    int j;
    int found;
    CuSuite *st = NULL;
    CuString *output = NULL;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v")) {
            continue;
        }
        if (!strcmp(argv[i], "-l")) {
            for (i = 0; tests[i].func != NULL; i++) {
                printf("%s\n", tests[i].testname);
            }
            exit(0);
        }
        if (argv[i][0] == '-') {
            fprintf(stderr, "invalid option: `%s'\n", argv[i]);
            exit(1);
        }
        list_provided = 1;
    }

    suite = CuSuiteNew();

    if (!list_provided) {
        /* add everything */
        for (i = 0; tests[i].func != NULL; i++) {
            st = tests[i].func();
            CuSuiteAddSuite(suite, st);
            CuSuiteFree(st);
        }
    } else {
        /* add only the tests listed */
        for (i = 1; i < argc; i++) {
            found = 0;
            if (argv[i][0] == '-') {
                continue;
            }
            for (j = 0; tests[j].func != NULL; j++) {
                if (!strcmp(argv[i], tests[j].testname)) {
                    CuSuiteAddSuite(suite, tests[j].func());
                    found = 1;
                }
            }
            if (!found) {
                fprintf(stderr, "invalid test name: `%s'\n", argv[i]);
                exit(1);
            }
        }
    }

    output = CuStringNew();
    CuSuiteRun(suite);
    CuSuiteSummary(suite, output);
    CuSuiteDetails(suite, output);
    printf("%s\n", output->buffer);

    exit_code = suite->failCount > 0 ? 1 : 0;

    CuSuiteFreeDeep(suite);
    CuStringFree(output);

    return exit_code;
}

int main(int argc, char *argv[]) {
    int exit_code = -1;

    TEST_COS_ENDPOINT = TEST_COS_ENDPOINT != NULL ?
                        TEST_COS_ENDPOINT : getenv("COS_TEST_ENDPOINT");
    TEST_ACCESS_KEY_ID = TEST_ACCESS_KEY_ID != NULL ?
                         TEST_ACCESS_KEY_ID : getenv("COS_TEST_ACCESS_KEY_ID");
    TEST_ACCESS_KEY_SECRET = TEST_ACCESS_KEY_SECRET != NULL ?
                             TEST_ACCESS_KEY_SECRET : getenv("COS_TEST_ACCESS_KEY_SECRET");
    //the cos bucket name, syntax: [bucket]-[appid], for example: mybucket-1253666666
    TEST_BUCKET_NAME = TEST_BUCKET_NAME != NULL ?
                       TEST_BUCKET_NAME : getenv("COS_TEST_BUCKET");
    TEST_APPID = TEST_APPID != NULL ?
                       TEST_APPID : getenv("COS_TEST_APPID");

    TEST_REGION = getenv("COS_TEST_REGION");
    TEST_UIN = getenv("COS_TEST_UIN");
    TEST_CI_ENDPOINT = getenv("COS_TEST_CI_ENDPOINT");

    if (cos_http_io_initialize(NULL, 0) != COSE_OK) {
        exit(1);
    }

    cos_log_set_level(COS_LOG_DEBUG);
    exit_code = run_all_tests(argc, argv);

    //cos_http_io_deinitialize last
    cos_http_io_deinitialize();

    return exit_code;
}
