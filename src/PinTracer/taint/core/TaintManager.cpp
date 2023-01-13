#include "TaintManager.h"

TaintManager taintManager;

TaintManager::TaintManager()
{
	LOG_INFO("TaintManager initialized");
}


TaintController TaintManager::getController()
{
	return this->taintController;
}

void TaintManager::routineLoadedEvent(RTN rtn, const std::string& dllName, const std::string& funcName)
{
	//Check if it is registered as a taint source
	const std::tr1::unordered_map<std::string, std::vector<TaintSource>>::const_iterator taintIt = this->taintFunctionMap.find(dllName);
	if (taintIt != this->taintFunctionMap.end())
	{
		//DLLname found with some taint-sourced functions
		std::vector<TaintSource> taintVector = taintIt->second;
		for (TaintSource taintSource : taintVector)
		{
			if (taintSource.funcName == funcName || taintSource.funcName == ANY_FUNC_IN_DLL)
			{
				//The routine is registered as a taint source
				INS_CALL_RTN_TAINT(rtn, taintSource.numArgs, taintSource.enterHandler, taintSource.exitHandler);
				LOG_DEBUG("Routine taint source activated: DllName = " + dllName + " FuncName = " + funcName);
				return;
			}
		}
	}
}

void TaintManager::registerTaintSource(const std::string& dllName, const std::string& funcName, int numArgs)
{
	//Select handler depending on function
	VOID(*enterHandler)() = NULL;
	VOID(*exitHandler)() = NULL;
	if (dllName == "wsock32.dll" && funcName == "recv")
	{
		enterHandler = TaintSource::wsockRecvEnter;
		exitHandler = TaintSource::wsockRecvExit;
	}
	else if (dllName == "C:\\Users\\Marcos\\source\\repos\\h3xduck\\TFM\\samples\\hello_world.exe" && funcName == ANY_FUNC_IN_DLL)
	{
		enterHandler = TaintSource::mainEnter;
		exitHandler = TaintSource::mainExit;
	}
	else
	{
		std::string logLine = "Received request to register unknown taint source: ";
		logLine += "DllName = " + dllName + " FuncName = " + funcName;
		LOG_ERR(logLine.c_str());
	}


	TaintSource taintSource(dllName, funcName, numArgs, enterHandler, exitHandler);
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