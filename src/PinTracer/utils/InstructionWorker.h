#ifndef _H_INSTRUCTION_WORKER_
#define _H_INSTRUCTION_WORKER_

#include "pin.H"
#include <iostream>

class InstructionWorker
{
public:
	static ADDRINT getBaseAddress(ADDRINT addr);

	static std::string getDllFromAddress(ADDRINT addr);

	static std::string getFunctionNameFromAddress(ADDRINT addr);
};

#endif