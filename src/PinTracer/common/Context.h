#ifndef _CONTEXT_H_
#define _CONTEXT_H_

#include "pin.H"

class Context {
private:
	ADDRINT currentInstruction;
	std::string lastMemoryValue;
	int lastMemoryLength;

public:
	ADDRINT getCurrentInstruction();
	std::string getLastMemoryValue();
	int getLastMemoryLength();

	void updateCurrentInstruction(ADDRINT inst_addr);
	void updateLastMemoryValue(std::string value, int len);
};

#endif
