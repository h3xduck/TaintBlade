#include "TaintManager.h"

TaintManager taintManager;

TaintManager::TaintManager()
{ 
	LOG_INFO("TaintManager initialized");
}

void TaintManager::registerTaintSource(const std::string& dllName, const std::string& funcName)
{
	//Select handler depending on function
	VOID(*enterHandler)() = NULL;
	VOID(*exitHandler)() = NULL;
	if (dllName == "wsock32.dll" && funcName == "recv")
	{
		enterHandler = TaintSource::wsockRecvEnter;
		exitHandler = TaintSource::wsockRecvExit;
	}
	else
	{
		std::string logLine = "Received request to register unknown taint source: ";
		logLine += "DllName = " + dllName + " FuncName = " + funcName;
		LOG_ERR(logLine.c_str());
	}


	TaintSource taintSource(dllName, funcName, enterHandler, exitHandler);
	const std::tr1::unordered_map<std::string, std::vector<TaintSource>>::iterator taintIt = this->taintFunctionMap.find(dllName);
	
	if (taintIt == this->taintFunctionMap.end())
	{
		//DLLname is new
		std::vector<TaintSource> taintVector;
		taintVector.push_back(taintSource);
		this->taintFunctionMap.insert(std::pair<std::string, std::vector<TaintSource>>(dllName, taintVector));
		
		std::string logLine = "Registered a new taintSource: NEW DllName =  " + dllName + " FuncName = " + funcName;
		LOG_DEBUG(logLine.c_str());
	}
	else
	{
		//DLLname already exists
		taintIt->second.push_back(taintSource);

		std::string logLine = "Registered a new taintSource: DllName =  " + dllName + " FuncName = " + funcName;
		LOG_DEBUG(logLine.c_str());
	}
}

void TaintManager::unregisterTaintSource(const std::string& dllName, const std::string& funcName)
{
	const std::tr1::unordered_map<std::string, std::vector<TaintSource>>::const_iterator taintIt = this->taintFunctionMap.find(dllName);
	if (taintIt == this->taintFunctionMap.end())
	{
		LOG_ERR("Tried to unregister inexistent taint source");
	}
	else
	{
		this->taintFunctionMap.erase(taintIt);

		std::string logLine = "Unregistered a taintSource: DllName =  " + dllName + " FuncName = " + funcName;
		LOG_DEBUG(logLine);
	}
}

void TaintManager::taintMemoryNewColor(const ADDRINT memAddr, const UINT32 bytes)
{
	ADDRINT memIt = memAddr;
	const UINT16 newColor = this->tagMap.taintMemNew(memIt);
	for (int ii = 0; ii < bytes-1; ii++)
	{
		this->tagMap.taintMem(memIt, newColor);
		memIt += 8;
	}
}

void TaintManager::taintMemWithMem(const ADDRINT destMem, const UINT32 destBytes, const ADDRINT srcMem, const UINT32 srcBytes)
{
	//src and dest should be of the same size
	//If destMem is tainted, then colors are mixed
	ADDRINT srcMemIt = srcMem;
	ADDRINT destMemIt = destMem;
	std::vector<UINT16> srcMemColor;
	for (int ii = 0; ii < destBytes; ii++)
	{
		const UINT16 colorSrc = this->tagMap.getTaintColorMem(srcMemIt);
		const UINT16 colorDest = this->tagMap.getTaintColorMem(destMemIt);
		if (colorDest == EMPTY_COLOR)
		{
			this->tagMap.taintMem(destMemIt, colorSrc);
		}
		else
		{
			this->tagMap.mixTaintMem(destMemIt, destMemIt, srcMemIt);
		}

		srcMemIt += 8;
		destMemIt += 8;
	}
}

void TaintManager::taintMemWithReg(const ADDRINT destMem, const UINT32 destBytes, const LEVEL_BASE::REG srcReg)
{
	//TODO: Check if destBytes and srcRegLength are the same
	const UINT32 srcRegLength = this->tagMap.tReg.getTaintLength(srcReg);
	LOG_DEBUG("M2R --> M:" << std::hex << destMem << "(len:" << std::dec << destBytes << ")  R:" << REG_StringShort(srcReg)<<"(code:"<<srcReg<<")");
	LOG_DEBUG("Length of register: "<<srcRegLength << " | length of memory: "<<destBytes);
	ADDRINT destMemIt = destMem;
	std::vector<Tag> srcRegColorVector = this->tagMap.getTaintColorReg(srcReg);

	for (int ii = 0; ii < destBytes; ii++)
	{
		const UINT16 colorDest = this->tagMap.getTaintColorMem(destMemIt);
		if (colorDest == EMPTY_COLOR)
		{
			UINT16 color = srcRegColorVector[ii].color;
			LOG_DEBUG("Empty color, tainting " << destMemIt << " with color " << color << " from reg " << REG_StringShort(srcReg));
			this->tagMap.taintMem(destMemIt, srcRegColorVector.at(ii).color);
		}
		else
		{
			LOG_DEBUG("Mixing colors");
			this->tagMap.mixTaintMemReg(destMemIt, destBytes, destMemIt, srcReg);
		}

		destMemIt += 8;
	}

}

//TODO: Think about taking the byte complexity of TagMap out to this functions
//like in the taintregwithmem
void TaintManager::taintRegNewColor(const LEVEL_BASE::REG reg)
{
	this->tagMap.taintRegNew(reg);
}

void TaintManager::taintRegWithReg(const LEVEL_BASE::REG destReg, LEVEL_BASE::REG srcReg)
{
	this->tagMap.mixTaintReg(destReg, destReg, srcReg);
}

void TaintManager::taintRegWithMem(const LEVEL_BASE::REG destReg, const LEVEL_BASE::REG src1Reg, const ADDRINT src2Mem, const UINT32 src2Bytes)
{
	const UINT32 destRegLength = this->tagMap.tReg.getTaintLength(destReg);
	const UINT16 colorSrc2Mem = this->tagMap.getTaintColorMem(src2Mem);

	for (int ii = 0; ii < destRegLength; ii++)
	{
		UINT16 colorReg = this->tagMap.getTaintColorReg(src1Reg).at(0).color;
		
		this->tagMap.mixTaintRegByte(destReg, ii, colorReg, colorSrc2Mem);
	}
	
}

void TaintManager::printTaint()
{
	this->tagMap.printMemTaintComplete();
	this->tagMap.printRegTaintComplete();
}