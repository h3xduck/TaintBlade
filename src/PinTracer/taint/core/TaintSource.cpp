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
