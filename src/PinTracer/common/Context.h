#ifndef _CONTEXT_H_
#define _CONTEXT_H_

#include "pin.H"

class Context {
private:
	ADDRINT currentInstruction;

public:
	ADDRINT getCurrentInstruction();
	void updateCurrentInstruction(ADDRINT inst_addr);
};

#endif
