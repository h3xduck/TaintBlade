#include "TraceManager.h"

UTILS::TRACE::TraceManager::TraceManager() {};

void UTILS::TRACE::TraceManager::addTracePoint(const std::string& dllName, const std::string& funcName, const int numArgs)
{
	TracePoint tp(dllName, funcName, numArgs);
	this->traceVector.push_back(tp);
}

void UTILS::TRACE::TraceManager::traceFunction(const std::string& dllName, const std::string& funcName)
{
	for (TracePoint& tp : this->traceVector)
	{
		if (tp.getDllName() == dllName && tp.getFuncName() == funcName)
		{
			//Function was set to be traced
		}
	}
}

void UTILS::TRACE::TraceManager::traceTracePoint(TracePoint& tp)
{
	//TODO 
}