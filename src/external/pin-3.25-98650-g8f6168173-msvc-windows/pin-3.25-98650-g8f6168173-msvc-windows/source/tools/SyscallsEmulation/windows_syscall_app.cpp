/*
 * Copyright (C) 2022-2022 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include <windows.h>

int main()
{
    NTSTATUS Status;
    SIZE_T Size = 500;
    // Calling an emulated syscall
    LPVOID VirtualMemory = VirtualAlloc(0, Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    OFSTRUCT _buffer     = {0}; // Create an OFSTRUCT structure local variable and initialize it to zero.
    // Calling a directly dispatched syscall
    HFILE _hfile_ = OpenFile("", &_buffer, OF_READ);
    return 0;
}