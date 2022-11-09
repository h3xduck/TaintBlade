/*
 * Copyright (C) 2022-2022 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include <iostream>
#include <unistd.h>
#include <cerrno>
#include <cstring>
using namespace std;

int main()
{
    pid_t pid = getpid();
    cout << hex << "return = 0x" << getsid(pid) << endl;
    getsid(pid);
    cout << "errno = " << strerror(errno) << endl;
    return 0;
}
