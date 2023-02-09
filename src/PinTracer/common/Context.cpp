#include "Context.h"

Context ctx;

ADDRINT Context::getCurrentInstruction()
{
	return this->currentInstruction;
}

void Context::updateCurrentInstruction(ADDRINT inst_addr)
{
	this->currentInstruction = inst_addr;
}