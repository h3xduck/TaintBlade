#include "Context.h"

Context ctx;

ADDRINT Context::getCurrentInstruction()
{
	return this->currentInstruction;
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


void Context::updateCurrentInstruction(ADDRINT inst_addr)
{
	this->currentInstruction = inst_addr;
}

void Context::updateLastMemoryValue(std::string value, int len) 
{
	this->lastMemoryValue = value;
	this->lastMemoryLength = len;
}