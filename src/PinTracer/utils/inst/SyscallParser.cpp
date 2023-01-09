#include "SyscallParser.h"

void SyscallParser::printSyscallAttempt(std::ostream* outstream, ADDRINT syscallNumber, ADDRINT syscallArgs[])
{
    if(syscallNumber == 1)
    {
        std::cerr << "Detected SYS_WRITE of length "<< (int)syscallArgs[2] << std::endl;
        char* buf = (char*)syscallArgs[1];
        
        for(int ii=0; ii<(int)syscallArgs[2]; ii++)
        {
            *outstream << static_cast<char>(*(buf+ii));
        }
        *outstream << std::endl;
    }
    else if(syscallNumber == 44)
    {
        std::cerr << "Detected SYS_SENDTO of length "<< (int)syscallArgs[2] << std::endl;
        char* buf = (char*)syscallArgs[1];
        
        for(int ii=0; ii<(int)syscallArgs[2]; ii++)
        {
            *outstream << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(*(buf+ii));
        }
        *outstream << std::endl;
    }
    return;
}
