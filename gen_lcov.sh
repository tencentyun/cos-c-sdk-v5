#!/bin/sh
workspace=`pwd`
# EXTRACT="${workspace}/cos_c_sdk/cos_auth.c ${workspace}/cos_c_sdk/cos_bucket.c ${workspace}/cos_c_sdk/cos_buf.c ${workspace}/cos_c_sdk/cos_fstack.c ${workspace}/cos_c_sdk/cos_http_io.c ${workspace}/cos_c_sdk/cos_http_io.h ${workspace}/cos_c_sdk/cos_list.h ${workspace}/cos_c_sdk/cos_log.c ${workspace}/cos_c_sdk/cos_multipart.c ${workspace}/cos_c_sdk/cos_object.c ${workspace}/cos_c_sdk/cos_resumable.c ${workspace}/cos_c_sdk/cos_status.c ${workspace}/cos_c_sdk/cos_status.h ${workspace}/cos_c_sdk/cos_string.c ${workspace}/cos_c_sdk/cos_string.h ${workspace}/cos_c_sdk/cos_sys_util.c ${workspace}/cos_c_sdk/cos_transport.c ${workspace}/cos_c_sdk/cos_utility.c ${workspace}/cos_c_sdk/cos_xml.c ${workspace}/cos_c_sdk/cos_crc64.c"
EXTRACT="${workspace}/cos_c_sdk/* ${workspace}/cos_c_sdk_ut/*"

# clear
rm UTReport -rf
rm UTResport.tar
mkdir -p build
cd build
#cmake -DENABLE_COVERAGE=ON ..
cmake .. -DCMAKE_BUILD_TYPE=Coverage -DBUILD_UNITTEST=ON -DMOCK_IS_SHOULD_RETRY=ON
make

# init
cd ..

lcov -d build -z
lcov -d build -b . -no-external -initial -c -o arvinzhu_init.info

# run
cd build/build/Coverage/
./bin/cos_c_sdk_ut
# second
cd ../../..
lcov -d build -b . -no-external -c -o arvinzhu.info

# filt
lcov -extract arvinzhu_init.info ${EXTRACT} -o arvinzhu_init_filted.info
lcov -extract arvinzhu.info ${EXTRACT} -o arvinzhu_filted.info

REMOVE="${workspace}/cos_c_sdk_ut/cjson.c  ${workspace}/cos_c_sdk_ut/cjson_utils.c ${workspace}/cos_c_sdk_ut/test_all.c"
lcov -remove arvinzhu.info ${REMOVE} -o arvinzhu_filted.info

# genhtml and zip
genhtml -o UTReport -prefix=`pwd` arvinzhu_init_filted.info arvinzhu_filted.info
tar -cvf UTReport.tar UTReport
#rm arvinzhu_init.info
#rm arvinzhu_init_filted.info
#rm arvinzhu.info
#rm arvinzhu_filted.info
rm UTReport -rf


