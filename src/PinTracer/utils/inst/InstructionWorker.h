#ifndef _H_INSTRUCTION_WORKER_
#define _H_INSTRUCTION_WORKER_

#include "pin.H"
#include <iostream>
#include <cstdio>
#include <typeinfo>

namespace InstructionWorker
{
	ADDRINT getBaseAddress(ADDRINT addr);

	std::string getDllFromAddress(ADDRINT addr);

	std::string getFunctionNameFromAddress(ADDRINT addr);

	std::wstring printFunctionArgument(void* arg);

	std::string getStringFromArg(void* arg);

}

UINT64 getBufferStringLengthUTF8(void* buf);

UINT64 getBufferStringLengthUTF16(void* buf);

#endif