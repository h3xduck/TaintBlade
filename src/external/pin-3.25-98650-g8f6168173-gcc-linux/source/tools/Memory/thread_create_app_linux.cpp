/*
 * Copyright (C) 2022-2022 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include <sched.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#define NUMTHREADS 8000 // Try to use almost 8192 threads

int data[NUMTHREADS];
pthread_barrier_t barrier;

void* start(void* arg)
{
    pthread_barrier_wait(&barrier);
    int i = 0;
    int x = 0;
    for (i = 0; i < 1000; i++)
    {
        x += i;
    }
    return 0;
}

int main(int argc, char* argv[])
{
    pthread_barrier_init(&barrier, NULL, NUMTHREADS);
    pthread_t threads[NUMTHREADS];
    int i;
    printf("Creating %d threads\n", NUMTHREADS);

    for (i = 0; i < NUMTHREADS; i++)
    {
        printf("Creating thread %d\n", i);
        int res = pthread_create(&threads[i], 0, start, 0);
        if (res)
        {
            printf("Failed to create thread number %d, res = %d\n", i, res);
            pthread_barrier_destroy(&barrier);
            // Exit(0) so we don't get a failed test because of machine resources limit
            // We'd rather have a false positive than tests fail for machine's limitations
            exit(0);
        }
    }
    int j = 0;
    for (j = 0; j < i; j++)
    {
        pthread_join(threads[j], 0);
    }
    printf("All threads joined\n");
    return 0;
}
