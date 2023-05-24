#include "TaintManager.h"

TaintManager taintManager;
extern DataDumper dataDumper;

TaintManager::TaintManager()
{
	LOG_INFO("TaintManager initialized");
}


TaintController& TaintManager::getController()
{
	return taintController;
}

void TaintManager::routineLoadedEvent(RTN rtn, std::string dllName, std::string funcName)
{
	//Check if it is registered as a taint source
	const std::tr1::unordered_map<std::string, std::vector<TaintSource>>::const_iterator taintIt = this->taintFunctionMap.find(dllName);
	if (taintIt != this->taintFunctionMap.end())
	{
		//DLLname found with some taint-sourced functions
		std::vector<TaintSource> taintVector = taintIt->second;
		for (int ii=0; ii<taintVector.size(); ii++)
		{
			TaintSource taintSource = taintVector[ii];
			if (taintSource.funcName == funcName)
			{
				//The routine is registered as a taint source
				INS_CALL_RTN_TAINT(rtn, dllName, funcName, taintSource.numArgs, taintSource.enterHandler, taintSource.exitHandler);				
				LOG_DEBUG("Routine taint source activated at IP: " << RTN_Address(rtn) <<" DllName = " <<dllName<< " FuncName = " << funcName << " NumArgs: "<<taintSource.numArgs);
				return;
			}
			//Unsure whether to keep this
			else if(taintSource.funcName == ANY_FUNC_IN_DLL)
			{
				//The routine is registered as a taint source, only once
				INS_CALL_RTN_TAINT(rtn, dllName, funcName, taintSource.numArgs, taintSource.enterHandler, taintSource.emptyHandler);
				LOG_DEBUG("Wildcard routine taint source activated: DllName = " + dllName + " FuncName = " + funcName);
				taintVector.erase(taintVector.begin()+ii);
			}
		}
	}

	//Manage taint sinks
	if ((dllName == KERNEL32_DLL || dllName == KERNEL32_DLL_x86) && funcName == CREATE_PROCESS_A_FUNC)
	{
		INS_CALL_RTN_TAINT(rtn, dllName, funcName, 10, TAINT::CORE::TAINT_SINK::createProcessAEnter, NULL);
	}
	else if ((dllName == KERNEL32_DLL || dllName == KERNEL32_DLL_x86) && funcName == CREATE_PROCESS_W_FUNC)
	{
		INS_CALL_RTN_TAINT(rtn, dllName, funcName, 10, TAINT::CORE::TAINT_SINK::createProcessWEnter, NULL);
	}
	else if ((/*(dllName == KERNEL32_DLL || dllName == KERNEL32_DLL_x86) ||*/ (dllName == KERNELBASE_DLL || dllName == KERNELBASE_DLL_x86)) && funcName == MULTI_BYTE_TO_WIDE_CHAR_FUNC)
	{
		INS_CALL_RTN_TAINT(rtn, dllName, funcName, 6, TAINT::CORE::TAINT_SINK::MultiByteToWideCharEnter, TAINT::CORE::TAINT_SINK::MultiByteToWideCharExit);
	}

}

void TaintManager::registerTaintSource(const std::string &dllName, const std::string &funcName, int numArgs)
{
	//Select handler depending on function
	VOID(*enterHandler)(ADDRINT retIp, VOID * dllName, VOID * funcName, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6) = NULL;
	VOID(*exitHandler)(ADDRINT retVal, VOID* dllName, VOID* funcName) = NULL;

	if ((dllName == WS2_32_DLL || dllName == WS2_32_DLL_x86) && funcName == RECV_FUNC)
	{
		LOG_DEBUG("Registered function handlers for recv in ws2_32");
		enterHandler = TaintSource::wsockRecvEnter;
		exitHandler = TaintSource::wsockRecvExit;
	}
	else if ((dllName == WSOCK32_DLL || dllName == WSOCK32_DLL_x86) && funcName == RECV_FUNC)
	{
		LOG_DEBUG("Registered function handlers for recv in wsock32");
		enterHandler = TaintSource::wsockRecvEnter;
		exitHandler = TaintSource::wsockRecvExit;
	}
	else if ((dllName == WININET_DLL || dllName == WININET_DLL_x86) && funcName == INTERNET_READ_FILE_FUNC)
	{
		LOG_DEBUG("Registered function handlers for InternetReadFile in wininet");
		enterHandler = TaintSource::wininetInternetReadFileEnter;
		exitHandler = TaintSource::wininetInternetReadFileExit;
	}
	else if (dllName == HELLO_WORLD_PROG && funcName == ANY_FUNC_IN_DLL)
	{
		LOG_DEBUG("Registered function handlers for main");
		enterHandler = TaintSource::mainEnter;
		exitHandler = TaintSource::mainExit;
	}
	else if (dllName == TEST1_PROG && funcName == ANY_FUNC_IN_DLL)
	{
		LOG_DEBUG("Registered function handlers for main");
		enterHandler = TaintSource::mainEnter;
		exitHandler = TaintSource::mainExit;
	}
	/*else if (dllName == "C:\\Users\\Marcos\\source\\repos\\h3xduck\\TFM\\samples\\tcp_client.exe" && funcName == ANY_FUNC_IN_DLL)
	{
		enterHandler = TaintSource::mainEnter;
		exitHandler = TaintSource::mainExit;
	}*/
	else
	{
		//The DLL + FUNC combination was not registered in our system
		LOG_ERR("Received request to register unknown taint source: DllName = " << dllName << " FuncName = " << funcName);
		return;
	}


	TaintSource taintSource(dllName, funcName, numArgs, enterHandler, exitHandler);
	const std::tr1::unordered_map<std::string, std::vector<TaintSource>>::iterator taintIt = this->taintFunctionMap.find(dllName);
	
	if (taintIt == this->taintFunctionMap.end())
	{
		//DLLname is new
		std::vector<TaintSource> taintVector;
		taintVector.push_back(taintSource);
		this->taintFunctionMap.insert(std::pair<std::string, std::vector<TaintSource>>(dllName, taintVector));
		
		LOG_INFO("Registered a new taintSource: NEW DllName =  " << dllName << " FuncName = " << funcName);
	}
	else
	{
		//DLLname already exists
		if (std::find(taintIt->second.begin(), taintIt->second.end(), taintSource) != taintIt->second.end())
		{
			//Function already in map
			LOG_ALERT("Tried to register an already registered taint source: DllName =  " << dllName << " FuncName = " << funcName);
		}
		else
		{
			//New function for existing DLL
			taintIt->second.push_back(taintSource);
			LOG_INFO("Registered a taintSource in a known DLL: DllName =  " << dllName << " FuncName = " << funcName);
		}
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