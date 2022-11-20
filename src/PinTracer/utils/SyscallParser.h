#ifndef _H_SYSCALL_
#define _H_SYSCALL_


#include "pin.H"
#include <iostream>
//#include <syscall.h>

using namespace std;

class SyscallParser
{
    public:
        void print_syscall_attempt(std::ostream* outstream, ADDRINT syscall_number, ADDRINT syscall_args[]);
};


#endif