#ifndef _H_SYSCALL_
#define _H_SYSCALL_


#include "pin.H"
#include <iostream>
//#include <syscall.h>

class SyscallParser
{
public:
    static void printSyscallAttempt(std::ostream* outstream, ADDRINT syscall_number, ADDRINT syscall_args[]);
};


#endif