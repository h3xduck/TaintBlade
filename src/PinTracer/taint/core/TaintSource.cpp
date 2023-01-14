#include "TaintSource.h"

void TaintSource::taintSourceLogAll()
{
	LOG_INFO("TAINT_SOURCE PRINT START");
	std::string logLine = "";
	logLine += "DLLNAME: " + this->dllName + " ";
	logLine += "FUNCNAME: " + this->funcName + " ";

	LOG_INFO(logLine.c_str());
	LOG_INFO("TAINT_SOURCE PRINT END");
}

TaintSource::TaintSource(const std::string& dllName, const std::string& funcName, int numArgs, VOID(*enter)(int, ...), VOID(*exit)(int, ...))
{
	this->dllName = dllName;
	this->funcName = funcName;
	this->numArgs = numArgs;
	this->enterHandler = enter;
	this->exitHandler = exit;
	LOG_DEBUG("TaintSource initiated");
};

