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