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
	Shown as a string of hexadecimal values (e.g.: FF29878289)
	IMPORTANT: Requires locking the PIN client.
	*/
	std::string getMemoryValueHexString(ADDRINT memAddr, int len);

	/**
	Returns an vector of chars of length len representing the bytes at memAddr. No extra info.
	IMPORTANT: Requires locking the PIN client.
	*/
	std::vector<char> getMemoryValue(ADDRINT memAddr, int len);

	/**
	Puts into valBuffer the value of a register given an instrumentation context (the value at that point)
	Must pass a buffer valBuffer. Normal call to getContextReg does not work for some reason in PIN
	If we select resultBigEndian=true it reorders the bytes LSB --> MSB, otherwise the returned vector goes MSB --> LSB
	*/
	void getRegisterValue(LEVEL_VM::CONTEXT *lctx, LEVEL_BASE::REG reg, UINT8* valBuffer, bool resultBigEndian = false);

}

UINT64 getBufferStringLengthUTF8(void* buf);

UINT64 getBufferStringLengthUTF16(void* buf);

#endif