/*
 * Copyright (C) 2008-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

/*! @file
 *  Utilities for SMC tests. 
 */
#include "smc_util.h"

/* 
 CODE_SECTION(name)
 Names a section in which the following function will be allocated.
 Only one function definition is allowed inside the section. Nested sections are
 disallowed. 

 SECTION_END
 Designates the end of the most recent code section.

 Usage: 

 CODE_SECTION("mycode") 
 extern void MyFunc ()
 {
    ......
 }
 SECTION_END

*/
#if defined(TARGET_WINDOWS) && defined(_MSC_VER)
#define CODE_SECTION(name) __pragma(code_seg(name))
#define SECTION_END __pragma(code_seg())
#elif defined(TARGET_MAC) && defined(__GNUC__)
#define CODE_SECTION(name) __attribute__((section("__TEXT, " name)))
#define SECTION_END
#elif defined(TARGET_LINUX) && defined(__GNUC__)
#define CODE_SECTION(name) __attribute__((section(name)))
#define SECTION_END
#elif defined(TARGET_BSD) && defined(__GNUC__)
#define CODE_SECTION(name) __attribute__((section(name)))
#define SECTION_END
#endif

// Starting from gcc-12, vectorization is enabled at -O2 optimization level by default.
// This optimization causes some code to be not position independent, so we turn this
// optimize-option off for certain functions that needs to be compiled as PIC.
#if defined(__GNUC__) && (__GNUC__ >= 12)
#define NOOPT __attribute__((optimize("no-tree-vectorize")))
#else
#define NOOPT
#endif

/*!
 * Exit with the specified error message
 */
static void Abort(string msg)
{
    cerr << msg << endl;
    exit(1);
}

/*!
 * Position-independent routine. Copies "foo" string into the specified buffer.
 * To simplify calculation of the size of this function, it is placed in a special 
 * code section along with the immediately following fooEnd() function.
 */
CODE_SECTION("foo_code")
static NOOPT void foo(char* str)
{
    *str++ = 'f';
    *str++ = 'o';
    *str++ = 'o';
    *str   = 0;
}
SECTION_END

CODE_SECTION("foo_code")
static NOOPT void fooEnd(char* str) {}
SECTION_END

static size_t fooSize()
{
    const char* start = CastPtr< char >(foo);
    const char* end   = CastPtr< char >(fooEnd);

    if ((end <= start) || ((size_t)(end - start) > PI_FUNC::MAX_SIZE))
    {
        Abort("foo: Invalid code range");
    }
    return end - start;
}

FOO_FUNC::FOO_FUNC() : FOO_BAR_FUNC(foo, fooSize()) {}

/*!
 * Position-independent routine. Copies "bar" string into the specified buffer
 * To simplify calculation of the size of this function, it is placed in a special 
 * code section along with the immediately following barEnd() function.
 */
CODE_SECTION("bar_code")
static NOOPT void bar(char* str)
{
    *str++ = 'b';
    *str++ = 'a';
    *str++ = 'r';
    *str   = 0;
}
SECTION_END

CODE_SECTION("bar_code")
static NOOPT void barEnd(char* str) {}
SECTION_END

static size_t barSize()
{
    const char* start = CastPtr< char >(bar);
    const char* end   = CastPtr< char >(barEnd);

    if ((end <= start) || ((size_t)(end - start) > PI_FUNC::MAX_SIZE))
    {
        Abort("bar: Invalid code range");
    }
    return end - start;
}

BAR_FUNC::BAR_FUNC() : FOO_BAR_FUNC(bar, barSize()) {}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
