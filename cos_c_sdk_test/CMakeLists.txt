project (cos_c_sdk_test)

include_directories(${CMAKE_SOURCE_DIR})

set(SAMPLE_SOURCE_FILES cos_demo.c)

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

add_executable(cos_c_sdk_test ${SAMPLE_SOURCE_FILES})

target_link_libraries(cos_c_sdk_test cos_c_sdk)
target_link_libraries(cos_c_sdk_test ${APR_UTIL_LIBRARY})
target_link_libraries(cos_c_sdk_test ${APR_LIBRARY})
target_link_libraries(cos_c_sdk_test ${MINIXML_LIBRARY})
target_link_libraries(cos_c_sdk_test ${CURL_LIBRARY})

