#include "DllImageLoad.h"

UTILS::EXEC::DllImageLoad::DllImageLoad(std::string dllName, ADDRINT dynamicLoadAdddress)
{
	PIN_LockClient();
	this->dllName = dllName;
	this->dynamicLoadAddress = dynamicLoadAdddress;
	this->baseLoadAddress = InstructionWorker::getBaseAddress(dynamicLoadAdddress);
	PIN_UnlockClient();
}

std::string UTILS::EXEC::DllImageLoad::getName()
{
	return this->dllName;
}

ADDRINT UTILS::EXEC::DllImageLoad::getBaseLoadAddress()
{
	return this->baseLoadAddress;
}

ADDRINT UTILS::EXEC::DllImageLoad::getDynamicLoadAddress()
{
	return this->dynamicLoadAddress;
}