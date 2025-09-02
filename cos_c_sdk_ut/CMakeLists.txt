project (cos_c_sdk_ut)

include_directories(${CMAKE_SOURCE_DIR})

configure_file (
  "${PROJECT_SOURCE_DIR}/test.h.in"
  "${PROJECT_SOURCE_DIR}/test.h"
)

set(SAMPLE_SOURCE_FILES CuTest.c cos_test_util.c cos_config.c test_cos_bucket.c 
    test_cos_object.c test_cos_multipart.c  
    test_cos_progress.c cjson_utils.c cjson.c
    test_cos_resumable.c test_cos_sys.c test_cos_crc.c test_cos_retry.c
    test_all.c)

# find_path(APR_INCLUDE_DIR apr-1/apr_time.h)
# find_path(APR_UTIL_INCLUDE_DIR apr/include/apr-1/apr_md5.h)
# find_path(MINIXML_INCLUDE_DIR mxml.h)
# find_path(CURL_INCLUDE_DIR curl/curl.h)

include_directories (${APR_INCLUDE_DIR})
include_directories (${APR_UTIL_INCLUDE_DIR})
include_directories (${MINIXML_INCLUDE_DIR})
include_directories (${CURL_INCLUDE_DIR})
include_directories ("${CMAKE_SOURCE_DIR}/cos_c_sdk")

find_library(APR_LIBRARY apr-1 PATHS /usr/local/apr/lib/)
find_library(APR_UTIL_LIBRARY aprutil-1 PATHS /usr/local/apr/lib/)
find_library(MINIXML_LIBRARY mxml)
find_library(CURL_LIBRARY curl)
find_library(PTHREAD_LIBRARY pthread)
find_library(MATH_LIBRARY m)
#find_library(SSL_LIBRARY ssl)
#find_library(IDN_LIBRARY idn)
find_library(RT_LIBRARY rt)
#find_library(COS_C_SDK_LIBRARY cos_c_sdk HINTS ${LIBRARY_OUTPUT_PATH})

add_executable(cos_c_sdk_ut ${SAMPLE_SOURCE_FILES})

target_link_libraries(cos_c_sdk_ut cos_c_sdk)
target_link_libraries(cos_c_sdk_ut ${APR_UTIL_LIBRARY})
target_link_libraries(cos_c_sdk_ut ${APR_LIBRARY})
target_link_libraries(cos_c_sdk_ut ${MINIXML_LIBRARY})
target_link_libraries(cos_c_sdk_ut ${CURL_LIBRARY})
target_link_libraries(cos_c_sdk_ut ${PTHREAD_LIBRARY})
target_link_libraries(cos_c_sdk_ut ${MATH_LIBRARY})
#target_link_libraries(cos_c_sdk_ut ${SSL_LIBRARY})
#target_link_libraries(cos_c_sdk_ut ${IDN_LIBRARY})
target_link_libraries(cos_c_sdk_ut ${RT_LIBRARY})
