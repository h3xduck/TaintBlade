#include "TaintSource.h"

void TaintSource::taintSourceLogAll()
{
	LOG("TAINT_SOURCE PRINT START");
	std::string logLine = "";
	logLine += "DLLNAME: " + this->dllName + " ";
	logLine += "FUNCNAME: " + this->funcName + " ";

	LOG(logLine.c_str());
	LOG("TAINT_SOURCE PRINT END");
}
