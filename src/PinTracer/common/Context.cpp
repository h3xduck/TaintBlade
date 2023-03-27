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



void Context::updateCurrentInstruction(ADDRINT inst_addr)
{
	this->currentInstruction = inst_addr;
}

void Context::updateLastMemoryValue(std::string value, int len) 
{
	this->lastMemoryValue = value;
	this->lastMemoryLength = len;
}