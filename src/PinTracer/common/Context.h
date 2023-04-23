#ifndef _CONTEXT_H_
#define _CONTEXT_H_

#include "pin.H"
#include "../reversing/core/RevContext.h"
#include "../utils/trace/TraceManager.h"

class Context {
private:
	ADDRINT currentInstruction;
	std::string lastMemoryValue;
	int lastMemoryLength;
	RevContext revContext;
	UTILS::TRACE::TraceManager traceManager;

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
	
	UTILS::TRACE::TraceManager& getTraceManager();
};

#endif
