#include "Context.h"

Context ctx;

ADDRINT Context::getCurrentBaseInstruction()
{
	return this->currentBaseInstruction;
}

std::string Context::getLastMemoryValue()
{
	return this->lastMemoryValue;
}

int Context::getLastMemoryLength()
{
	return this->lastMemoryLength;
}

RevContext* Context::getRevContext()
{
	return &(this->revContext);
}

UTILS::TRACE::TraceManager& Context::getTraceManager()
{
	return this->traceManager;
}

UTILS::EXEC::ExecutionManager& Context::getExecutionManager()
{
	return this->executionManager;
}


void Context::updateCurrentBaseInstruction(ADDRINT inst_addr)
{
	this->currentBaseInstruction = inst_addr;
}

void Context::updateLastMemoryValue(std::string value, int len) 
{
	this->lastMemoryValue = value;
	this->lastMemoryLength = len;
}