/*
 * Copyright (C) 2022-2022 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

#define THREAD_NUM 8150 // Try to use almost 8192 threads

static HANDLE hReleaseAllThreads = NULL;
static HANDLE hThreadsSyncSem    = NULL;

int ThreadRoutine(LPVOID p_t_ordinal)
{
    DWORD dwReturn = ::WaitForSingleObject(hThreadsSyncSem, 0);

    fprintf(stderr, "Thread id=%d about to block\n", (int)p_t_ordinal);

    if (dwReturn == WAIT_OBJECT_0)
        ::WaitForSingleObject(hReleaseAllThreads, INFINITE);
    else if (dwReturn == WAIT_TIMEOUT)
        ::SetEvent(hReleaseAllThreads);

    fprintf(stderr, "Thread id=%d released\n", (int)p_t_ordinal);

    int i = 0;
    int x = 0;
    for (i = 0; i < 1000; i++)
    {
        x += i;
    }
    return 0;
}

int ThreadCreation()
{
    const unsigned long num_threads    = THREAD_NUM;
    static HANDLE aThreads[THREAD_NUM] = {0};
    unsigned long slot                 = 0;
    unsigned long cnt_th               = 0;
    unsigned long thread_ret           = 0;

    fprintf(stderr, "creating %d threads \n", num_threads);

    // Create non-signaled event with manual reset
    hReleaseAllThreads = ::CreateEvent(NULL, TRUE, FALSE, NULL);

    // Create semaphore with initial counter THREAD_NUM - 1
    hThreadsSyncSem = ::CreateSemaphore(NULL, THREAD_NUM - 1, THREAD_NUM, NULL);

    if ((hReleaseAllThreads == NULL) || (hThreadsSyncSem == NULL))
    {
        fprintf(stderr, "Sync objects creation failed\n");
        return 0;
    }

    for (cnt_th = 0; cnt_th < num_threads; cnt_th++)
    {
        aThreads[cnt_th] =
            CreateThread(NULL, 16 * 1024, (LPTHREAD_START_ROUTINE)ThreadRoutine, (LPVOID)cnt_th, 0, (LPDWORD)&thread_ret);
        fprintf(stderr, "Thread %d created\n", cnt_th);
    }

    while (cnt_th > 0)
    {
        slot = WaitForSingleObject(aThreads[cnt_th], INFINITE);
        GetExitCodeThread(aThreads[cnt_th], &thread_ret);
        CloseHandle(aThreads[cnt_th]);
        cnt_th--;
    }
    fprintf(stderr, "all %d threads terminated\n", num_threads);
    fflush(stderr);
    return 1;
}

int main()
{
    ThreadCreation();
    return 0;
}
