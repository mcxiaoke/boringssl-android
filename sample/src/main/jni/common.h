#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

uint8_t* hex2bin(const char* in, int* len);

char* bin2hex(const uint8_t* data, const int data_len, int* len);

#ifdef __cplusplus
}
#endif

#endif
