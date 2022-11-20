#include "SyscallParser.h"

void SyscallParser::print_syscall_attempt(std::ostream* outstream, ADDRINT syscall_number, ADDRINT syscall_args[])
{
    if(syscall_number == 1)
    {
        std::cerr << "Detected SYS_WRITE of length "<< (int)syscall_args[2] << std::endl;
        char* buf = (char*)syscall_args[1];
        
        for(int ii=0; ii<(int)syscall_args[2]; ii++)
        {
            *outstream << static_cast<char>(*(buf+ii));
        }
        *outstream << std::endl;
    }
    else if(syscall_number == 44)
    {
        std::cerr << "Detected SYS_SENDTO of length "<< (int)syscall_args[2] << std::endl;
        char* buf = (char*)syscall_args[1];
        
        for(int ii=0; ii<(int)syscall_args[2]; ii++)
        {
            *outstream << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(*(buf+ii));
        }
        *outstream << std::endl;
    }
    return;
}