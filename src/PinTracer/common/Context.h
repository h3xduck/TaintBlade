#ifndef _CONTEXT_H_
#define _CONTEXT_H_

#include "pin.H"
#include "../reversing/core/RevContext.h"

class Context {
private:
	ADDRINT currentInstruction;
	std::string lastMemoryValue;
	int lastMemoryLength;
	RevContext revContext;

public:
	ADDRINT getCurrentInstruction();
	std::string getLastMemoryValue();
	int getLastMemoryLength();

	void updateCurrentInstruction(ADDRINT instAddr);
	void updateLastMemoryValue(std::string value, int len);

	/**
	Get RevContext object
	*/
	RevContext* getRevContext();
};

#endif
