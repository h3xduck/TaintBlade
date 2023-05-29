#include "ExecutionManager.h"

void UTILS::EXEC::ExecutionManager::addImage(IMG img)
{
	PIN_LockClient();

	//First we get the image values
	std::string dllName = IMG_Name(img);
	const ADDRINT entryAddr = IMG_LowAddress(img);
	//tolower
	std::transform(dllName.begin(), dllName.end(), dllName.begin(), [](unsigned char c) { return std::tolower(c); });
	
	//Add found image to internal registry
	DllImageLoad dllImageLoad(dllName, entryAddr);
	this->imageVector.push_back(dllImageLoad);

	//Now, if we have any NopSection registered, we store the actual runtime address at which the offsets specified 
	//by the ranges refer inside the image
	ADDRINT dynamicStart = 0, dynamicEnd = 0;
	for (NopSection &section: this->nopSectionVector)
	{
		if (section.getDllName() == dllName)
		{
			section.setDynamicStartAddress(section.getBaseStartAddress() + dllImageLoad.getDynamicLoadAddress());
			section.setDynamicEndAddress(section.getBaseEndAddress() + dllImageLoad.getDynamicLoadAddress());
			LOG_DEBUG("Loaded NOP section dynamic values in DLL " << dllName << ", starting at " << entryAddr);
		}
	}

	PIN_UnlockClient();
}

void UTILS::EXEC::ExecutionManager::registerNopSection(std::string dllName, ADDRINT rangeStart, ADDRINT rangeEnd, std::vector<std::string> userAssemblyLines)
{
	NopSection nopSection(dllName, rangeStart, rangeEnd);
	nopSection.setUserAssemblyLines(userAssemblyLines);
	this->nopSectionVector.push_back(nopSection);
	LOG_DEBUG("Registered a NOP Section at " << dllName << " between " << rangeStart << " and " << rangeEnd << " with " << userAssemblyLines.size() << " user assembly lines");
}


bool UTILS::EXEC::ExecutionManager::isInNopSection(INS ins)
{
	const ADDRINT address = INS_Address(ins);
	for (NopSection nopSection : this->nopSectionVector)
	{
		if (nopSection.getDynamicStartAddress() <= address && nopSection.getDynamicEndAddress() >= address)
		{
			return true;
		}
		//LOG_INFO("FAILED NOP [" << address << "] B[" << nopSection.baseStartAddress << ", " << nopSection.baseEndAddress << "]" << " | D[" << nopSection.dynamicStartAddress << ", " << nopSection.dynamicEndAddress << "]");
	}

	return false;
}

void UTILS::EXEC::ExecutionManager::instrumentNopSection(INS ins)
{
	ADDRINT address = INS_Address(ins);
	for (NopSection nopSection : this->nopSectionVector)
	{
		if (nopSection.getDynamicStartAddress() <= address && nopSection.getDynamicEndAddress() >= address)
		{
			//If the user specified that we need to set some registers to some value, now it is the time
			std::vector<std::string> userAssemblyLines = nopSection.getUserAssemblyLines();
			for (std::string assemblyLine : userAssemblyLines)
			{
				LOG_INFO("Executing user assembly line: " << assemblyLine);
				PseudoAssemblyParser::instrumentAssemblyLine(ins, assemblyLine);
			}

			//Instrument the instruction so that it does not get executed
			//Jump to the end of the NOP section
			INS_InsertDirectJump(ins, IPOINT_BEFORE, nopSection.getDynamicEndAddress() + 1);
			LOG_INFO("Instrumented NOP section at DLL " << nopSection.getDllName() << " B[" << nopSection.getBaseStartAddress() << ", " << nopSection.getBaseEndAddress() << "]" << " | D[" << nopSection.getDynamicStartAddress() << ", " << nopSection.getDynamicEndAddress() << "]");
			return;
		}
	}
}