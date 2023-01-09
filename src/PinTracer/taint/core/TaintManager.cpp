#include "TaintManager.h"

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
		
	}


	TaintSource taintSource(dllName, funcName, enterHandler, exitHandler);
	const std::tr1::unordered_map<std::string, std::vector<TaintSource>>::iterator taintIt = this->taintFunctionMap.find(dllName);
	if (taintIt == this->taintFunctionMap.end())
	{
		//DLLname is new
		std::vector<TaintSource> taintVector;
		taintVector.push_back(taintSource);
		this->taintFunctionMap.insert(std::pair<std::string, std::vector<TaintSource>>(dllName, taintVector));
	}
	else
	{
		//DLLname already exists
		taintIt->second.push_back(taintSource);
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
	}
}