#include "NopSection.h"

UTILS::EXEC::NopSection::NopSection(std::string dllName, ADDRINT start, ADDRINT end)
{
	this->dllName = dllName;
	this->baseStartAddress = start;
	this->baseEndAddress = end;
}

void UTILS::EXEC::NopSection::setBaseStartAddress(ADDRINT addr)
{
	this->baseStartAddress = addr;
}

ADDRINT UTILS::EXEC::NopSection::getBaseStartAddress()
{
	return this->baseStartAddress;
}

void UTILS::EXEC::NopSection::setBaseEndAddress(ADDRINT addr)
{
	this->baseEndAddress = addr;
}

ADDRINT UTILS::EXEC::NopSection::getBaseEndAddress()
{
	return this->baseEndAddress;
}

void UTILS::EXEC::NopSection::setDynamicStartAddress(ADDRINT addr)
{
	this->dynamicStartAddress = addr;
}

ADDRINT UTILS::EXEC::NopSection::getDynamicStartAddress()
{
	return this->dynamicStartAddress;
}

void UTILS::EXEC::NopSection::setDynamicEndAddress(ADDRINT addr)
{
	this->dynamicEndAddress = addr;
}

ADDRINT UTILS::EXEC::NopSection::getDynamicEndAddress()
{
	return this->dynamicEndAddress;
}

void UTILS::EXEC::NopSection::setDllName(std::string name)
{
	this->dllName = name;
}

std::string UTILS::EXEC::NopSection::getDllName()
{
	return this->dllName;
}

void UTILS::EXEC::NopSection::setUserAssemblyLines(std::vector<std::string> lines)
{
	this->userAssemblyLines = lines;
}

std::vector<std::string> UTILS::EXEC::NopSection::getUserAssemblyLines()
{
	return this->userAssemblyLines;
}