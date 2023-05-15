#ifndef _CONTEXT_H_
#define _CONTEXT_H_

#include "pin.H"
#include "../reversing/core/RevContext.h"
#include "../utils/trace/TraceManager.h"
#include "../utils/exec/ExecutionManager.h"
#include "../utils/io/CommandCenter.h"

class Context {
private:
	ADDRINT currentBaseInstruction;
	std::string lastMemoryValue;
	int lastMemoryLength;
	RevContext revContext;
	UTILS::TRACE::TraceManager traceManager;
	UTILS::EXEC::ExecutionManager executionManager;

public:
	ADDRINT getCurrentBaseInstruction();
	std::string getLastMemoryValue();
	int getLastMemoryLength();

	void updateCurrentBaseInstruction(ADDRINT instAddr);
	void updateLastMemoryValue(std::string value, int len);

	/**
	Get RevContext object
	*/
	RevContext* getRevContext();
	
	UTILS::TRACE::TraceManager& getTraceManager();
	UTILS::EXEC::ExecutionManager& getExecutionManager();
};

#endif
