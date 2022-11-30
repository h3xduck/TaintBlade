#include "InstructionWorker.h"

ADDRINT InstructionWorker::getBaseAddress(ADDRINT addr)
{
	IMG module = IMG_FindByAddress(addr);
	ADDRINT base = IMG_LoadOffset(module);
	if (base == 0)
	{
		base = IMG_LowAddress(module);
		if (base == 0)
		{
			base = GetPageOfAddr(addr);
		}
	}

	ADDRINT baseAddr = addr - base;

	return baseAddr;
}

std::string InstructionWorker::getDllFromAddress(ADDRINT addr)
{
	IMG module = IMG_FindByAddress(addr);
	if (!IMG_Valid(module))
	{
		return NULL;
	}
	std::string dllName = IMG_Name(module);

	return dllName;
}

std::string InstructionWorker::getFunctionNameFromAddress(ADDRINT addr)
{
	IMG module = IMG_FindByAddress(addr);
	if (!IMG_Valid(module))
	{
		return NULL;
	}

	RTN routine = RTN_FindByAddress(addr);


	std::string routineName = RTN_FindNameByAddress(addr);

	return routineName;
}
