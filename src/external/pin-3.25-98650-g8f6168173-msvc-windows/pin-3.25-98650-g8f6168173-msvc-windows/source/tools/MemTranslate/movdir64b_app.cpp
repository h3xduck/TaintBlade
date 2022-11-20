/*
 * Copyright (C) 2022-2022 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include <iostream>
#include <immintrin.h>
#include <string.h>
using namespace std;

/*
 * We duplicate the MOVDIR64B wrapper function so that the MOVDIR64B instruction would be
 * instrumented 3 different times
 */
extern "C" void Movdir64bWrap0(char* dst, char* src);
extern "C" void Movdir64bWrap1(char* dst, char* src);
extern "C" void Movdir64bWrap2(char* dst, char* src);

/*
 * This application is written for the movdir64b_rewrite test.
 * In this application we use the MOVDIR64B instruction to copy the contents
 * of string src to string dst.
 */

int main()
{
#if defined(TARGET_WINDOWS)
    __declspec(align(64)) char src1[64];
    __declspec(align(64)) char dst1[64];
    __declspec(align(64)) char src2[64];
    __declspec(align(64)) char dst2[64];
    __declspec(align(64)) char src3[64];
    __declspec(align(64)) char dst3[64];
#else
    char src1[64] __attribute__((aligned(64)));
    char dst1[64] __attribute__((aligned(64)));
    char src2[64] __attribute__((aligned(64)));
    char dst2[64] __attribute__((aligned(64)));
    char src3[64] __attribute__((aligned(64)));
    char dst3[64] __attribute__((aligned(64)));
#endif
    memset(src1, '1', 63);
    src1[63] = '\0';
    memset(dst1, 'i', 63);
    dst1[63] = '\0';
    memset(src2, '2', 63);
    src2[63] = '\0';
    memset(dst2, 'j', 63);
    dst2[63] = '\0';
    memset(src3, '3', 63);
    src3[63] = '\0';
    memset(dst3, 'k', 63);
    dst3[63] = '\0';
    // The target source address is src. However we pass src-1 to
    // the wrapper function so that the movdir64b instruction can
    // be encoded using an index (=1) and scale (=1) and not just
    // base register
    Movdir64bWrap0(dst1, src1 - 1);
    Movdir64bWrap1(dst2, src2 - 1);
    Movdir64bWrap2(dst3, src3 - 1);
    return 0;
}
