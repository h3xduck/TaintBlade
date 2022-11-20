/*
 * Copyright (C) 2022-2022 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

/*
 * This application calls for clone3() with several arguments and parameters.
 *
 * The clone3() system call provides a superset of the functionality of the older clone() interface.
 * It also provides a number of API improvements, including: space for additional flags bits, cleaner
 * separation in the use of various arguments, and the ability to specify the size of the child's stack area.
 *
 * As with fork() and clone() system calls, clone3() returns in both the parent and the child.
 * It returns 0 in the child process and returns the PID of the child in the parent.
 *
 */

#define _GNU_SOURCE
#include <errno.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sched.h>
#include <stdbool.h>

// Indicator for tests success/failure
bool test_failed = false;

// If clone3 syscall number is not defined set it with an error value
#ifndef __NR_clone3
#define __NR_clone3 -1
struct clone_args
{
    __aligned_u64 flags;
    __aligned_u64 pidfd;
    __aligned_u64 child_tid;
    __aligned_u64 parent_tid;
    __aligned_u64 exit_signal;
    __aligned_u64 stack;
    __aligned_u64 stack_size;
    __aligned_u64 tls;
    __aligned_u64 set_tid;
    __aligned_u64 set_tid_size;
    __aligned_u64 cgroup;
};
#endif

#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x00001000
#endif

// Stack size for cloned child
#define STACK_SIZE (1024 * 1024)

// Conversion from pointer to UINT64 (for setting clone_args members)
#define ptr_to_u64(ptr) ((__u64)((uintptr_t)(ptr)))

static int testCounter = 0;

static bool is_clone3_supported() { return (__NR_clone3 > 0); }

static pid_t sys_clone3(struct clone_args* args, size_t size)
{
    fflush(stdout);
    fflush(stderr);
    return syscall(__NR_clone3, args, size);
}

static int call_clone3(uint64_t flags)
{
    pid_t pid  = -1;
    pid_t ctid = -1;
    pid_t ptid = -1;
    int pidfd  = -1;
    int status;

    // set clone 3 arguments (extract?)
    struct clone_args args = {0};
    args.flags             = flags;
    args.exit_signal       = SIGCHLD;
    args.child_tid         = ptr_to_u64(&ctid);
    args.parent_tid        = ptr_to_u64(&ptid);
    args.pidfd             = ptr_to_u64(&pidfd);

    //    // Allocate stack for child
    //	__aligned_u64 stack = (__aligned_u64)malloc(STACK_SIZE);
    //    if (stack == 0)
    //    {
    //    	printf("*** Failed to allocate stack to clone3()\n", strerror(errno));
    //    	return -1;
    //    }
    //
    //    args.stack = stack;
    //    args.stack_size = STACK_SIZE;

    pid = sys_clone3(&args, sizeof(struct clone_args));

    // check syscall success
    if (pid < 0)
    {
        printf("*** failed to create new process - %s ***", strerror(errno));
        return -errno;
    }

    if (pid == 0)
    {
        // child process
        printf("child created successfully with pid %d", getpid());
        exit(EXIT_SUCCESS);
    }

    // parent process - wait for child to terminate (function returns child pid)
    if (waitpid(pid, &status, __WALL) < 0)
    {
        printf("waitpid() on child %d returned error %s", pid, strerror(errno));
        return -errno;
    }

    // check child exit status
    if (WEXITSTATUS(status))
    {
        printf("child returned error, status = %d", status);
        return WEXITSTATUS(status);
    }

    return 0;
}

static void test_clone3_success(uint64_t flags, int expected)
{
    int ret;

    printf("\nTest Case #%d : calling clone3() from parent [pid %d] with flags = 0x%08x... ", ++testCounter, getpid(), flags);

    ret = call_clone3(flags);

    if (ret != expected)
    {
        printf(" =>  *** [FAIL] ***\n", ret, expected);
    }
    else
    {
        printf(" => [OK]\n");
    }
}

static void test_clone3_failure(uint64_t flags, uint64_t exit_signal)
{
    // set clone3 arguments
    struct clone_args args = {0};
    args.flags             = flags;
    args.exit_signal       = exit_signal;
    char* exit_signal_str  = (exit_signal == SIGCHLD) ? "SIGCHLD" : "-1";

    printf("\nTest Case #%d : calling clone3()  with flags = 0x%08x and exit signal = %s, syscall should fail... ", ++testCounter,
           flags, exit_signal_str);

    int ret = sys_clone3(&args, sizeof(struct clone_args));

    if (ret != -1)
    {
        test_failed = true;
        printf("syscall succeeded => *** [FAIL] ***\n");
    }
    else
    {
        printf("syscall failed => [OK]\n");
    }
}

int main(int argc, char* argv[])
{
    pid_t pid;
    uid_t uid = getuid();

    if (!is_clone3_supported())
    {
        printf("\nclone3() syscall is not supported.\n");
        printf("Test application finished successfully.\n\n");
        exit(EXIT_SUCCESS);
    }

    // ------------------------
    // clone3 success scenarios
    // ------------------------

    test_clone3_success(0, 0);

    test_clone3_success(CLONE_VFORK, 0);

    test_clone3_success(CLONE_PIDFD | CLONE_CHILD_SETTID | CLONE_PARENT_SETTID, 0);

    // -------------------------
    // clone3 failures scenarios
    // -------------------------

    // Invalid exit signal (-1)
    test_clone3_failure(0, -1);

    // Invalid flags mix (1)
    test_clone3_failure(CLONE_PIDFD | CLONE_THREAD, SIGCHLD);

    // Invalid flags mix (2)
    test_clone3_failure(CLONE_PIDFD | CLONE_PARENT_SETTID, SIGCHLD);

    // Invalid flags mix (3)
    test_clone3_failure(CLONE_PIDFD | CLONE_DETACHED, SIGCHLD);

    if (test_failed)
    {
        printf("\nTest application failed.\n\n");
        return EXIT_FAILURE;
    }

    printf("\nTest application finished successfully.\n\n");
    return EXIT_SUCCESS;
}
