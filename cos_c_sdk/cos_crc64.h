#ifndef COS_C_SDK_V5_COS_C_SDK_COS_CRC64_H_
#define COS_C_SDK_V5_COS_C_SDK_COS_CRC64_H_

#include "cos_sys_define.h"


COS_CPP_START

uint64_t cos_crc64(uint64_t crc, void *buf, size_t len);
uint64_t cos_crc64_combine(uint64_t crc1, uint64_t crc2, uintmax_t len2);
uint64_t cos_crc64_big(uint64_t crc, void *buf, size_t len);

COS_CPP_END

#endif  //  COS_C_SDK_V5_COS_C_SDK_COS_CRC64_H_
