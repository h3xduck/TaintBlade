#ifndef _CONTEXT_H_
#define _CONTEXT_H_

#include "pin.H"
#include "../reversing/core/RevContext.h"

class Context {
private:
	ADDRINT currentInstruction;
	xed_iclass_enum_t currentinstructionClass;
	std::string lastMemoryValue;
	int lastMemoryLength;
	RevContext revContext;

public:
	ADDRINT getCurrentInstruction();
	xed_iclass_enum_t getCurrentInstructionClass();
	std::string getLastMemoryValue();
	int getLastMemoryLength();

	void updateCurrentInstruction(ADDRINT instAddr);
	void updateCurrentInstructionClass(xed_iclass_enum_t instClass);
	void updateLastMemoryValue(std::string value, int len);

	/**
	Get RevContext object
	*/
	RevContext* getRevContext();
};

#endif
