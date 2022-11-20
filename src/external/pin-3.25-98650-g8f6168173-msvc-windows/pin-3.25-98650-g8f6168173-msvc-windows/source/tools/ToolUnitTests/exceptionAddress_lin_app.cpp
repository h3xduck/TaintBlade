/*
 * Copyright (C) 2011-2022 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include <iostream>

using std::cerr;
using std::endl;

static void pinException() { cerr << "APP: in pinException" << endl; }

static void toolException() { cerr << "APP: in toolException" << endl; }

static int appException()
{
    cerr << "APP: in appException" << endl;

    // Declarations of 'one' and 'zero' are made for 2 reasons :
    // (1) Avoid getting a compiler warning of division by zero.
    // (2) Defining the variables as volatile to turn off optimization of "1/x" expression that is made by some compilers,
    //     since this optimization does not generate the desired divide-by-zero exception.
    volatile unsigned int zero = 0;
    volatile unsigned int one  = 1;

    return one / zero;
}

int main()
{
    // Cause a Pin exception via PIN_SafeCopyEx.
    pinException();

    // Cause a tool exception.
    toolException();

    // Cause an application exception (SIGFPE) - divide by zero.
    appException();

    return 0;
}
