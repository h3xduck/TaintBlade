#ifndef _H_INSTRUCTION_WORKER_
#define _H_INSTRUCTION_WORKER_

#include "pin.H"
#include <iostream>
#include <cstdio>
#include <typeinfo>
#include "../io/log.h"

namespace InstructionWorker
{
	ADDRINT getBaseAddress(ADDRINT addr);

	std::string getDllFromAddress(ADDRINT addr);

	std::string getFunctionNameFromAddress(ADDRINT addr);

	/**
	* Returns a wstring of a maximum length, independently on the format of the referenced value.
	* No added metadata to the result.
	*/
	//std::wstring getMemoryValueOfLength(void* addr);

	/**
	* Returns a wstring with the function argument value, with added metadata ready to be printed, 
	* independently on the format (unicode, string, wstring)
	*/
	std::wstring printFunctionArgument(void* arg);

	std::string getStringFromArg(void* arg);

	/**
	Returns a string of length len representing the bytes at memAddr. No extra info.
	*/
	std::string getMemoryValue(ADDRINT memAddr, int len);

	/**
	Returns a string representing the bytes at memAddr with length len.
	Shown as a string of hexadecimal values (e.g.: FF29878289)
	*/

}

UINT64 getBufferStringLengthUTF8(void* buf);

UINT64 getBufferStringLengthUTF16(void* buf);

#endif