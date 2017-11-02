#ifndef LIBCOS_CRC_H
#define LIBCOS_CRC_H

#include "cos_sys_define.h"


COS_CPP_START

uint64_t cos_crc64(uint64_t crc, void *buf, size_t len);
uint64_t cos_crc64_combine(uint64_t crc1, uint64_t crc2, uintmax_t len2);

COS_CPP_END

#endif
