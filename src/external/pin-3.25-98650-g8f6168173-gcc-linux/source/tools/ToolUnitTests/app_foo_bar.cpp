/*
 * Copyright (C) 2022-2022 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include <string.h>
#include <iostream>
#include "../Utils/threadlib.h"

#ifdef TARGET_WINDOWS
#include <windows.h>
#define gettid() GetCurrentThreadId()
#else
#include <unistd.h>
#include <sys/syscall.h>
#define gettid() syscall(SYS_gettid)
#endif

/*
 * This application exports functions foo() and bar() to allow a pintool to instrument or call those functions.
 * The application creates one thread, and that thread calls foo().
 * The pintool will instrument foo() and call bar().
 * The purpose of the test is to validate the proper destruction of the spill area, and so foo is called not by
 * the main thread but rather by the secondary thread because an explicit destruction of spill area happens for 
 * secondary threads and not the main application thread.
 */


extern "C" void bar() { std::cout << std::dec << "[ tid " << gettid() << " ] " << __FUNCTION__ << "()" << std::endl; }

extern "C" void foo() { std::cout << std::dec << "[ tid " << gettid() << " ] " << __FUNCTION__ << "()" << std::endl; }

void* thread_func(void* arg)
{
    std::cout << std::dec << "[ tid " << gettid() << " ] " << __FUNCTION__ << "()" << std::endl;
    std::cout << std::dec << "[ tid " << gettid() << " ] calling foo()" << std::endl;
    foo();
    return NULL;
}

int main(int argc, char* argv[])
{
    std::cout << std::dec << "[ tid " << gettid() << " ] " << __FUNCTION__ << "()" << std::endl;

    std::cout << std::dec << "[ tid " << gettid() << " ] Creating thread" << std::endl;
    THREAD_HANDLE handle;
    if (!CreateOneThread(&handle, thread_func, 0))
    {
        std::cerr << "Failed to create thread" << std::endl;
        return 1;
    }

    std::cout << std::dec << "[ tid " << gettid() << " ] Joining thread" << std::endl;
    if (!JoinOneThread(handle))
    {
        std::cerr << "Thread join failed" << std::endl;
        return 1;
    }

    return 0;
}
