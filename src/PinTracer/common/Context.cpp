#include "Context.h"

Context ctx;

ADDRINT Context::getCurrentInstruction()
{
	return this->currentInstruction;
}

xed_iclass_enum_t Context::getCurrentInstructionClass()
{
	return this->currentinstructionClass;
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


void Context::updateCurrentInstruction(ADDRINT inst_addr)
{
	this->currentInstruction = inst_addr;
}

void Context::updateCurrentInstructionClass(xed_iclass_enum_t instClass)
{
	this->currentinstructionClass = instClass;
}

void Context::updateLastMemoryValue(std::string value, int len) 
{
	this->lastMemoryValue = value;
	this->lastMemoryLength = len;
}