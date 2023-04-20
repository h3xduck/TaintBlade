#include "TracePoint.h"

UTILS::TRACE::TracePoint::TracePoint(std::string dllName, std::string funcName, int numArgs)
{
	this->dllName = dllName;
	this->funcName = funcName;
	this->numArgs = numArgs;
}

std::string& UTILS::TRACE::TracePoint::getDllName()
{
	return this->dllName;
}
std::string& UTILS::TRACE::TracePoint::getFuncName()
{
	return this->funcName;
}
int UTILS::TRACE::TracePoint::getNumArgs()
{
	return numArgs;
}