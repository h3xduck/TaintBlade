#include "TracePoint.h"

UTILS::TRACE::TracePoint::TracePoint(std::string dllName, std::string funcName, int numArgs)
{
	this->dllName = dllName;
	this->funcName = funcName;
	this->numArgs = numArgs;
}

std::string UTILS::TRACE::TracePoint::getDllName()
{
	return this->dllName;
}
std::string UTILS::TRACE::TracePoint::getFuncName()
{
	return this->funcName;
}
int UTILS::TRACE::TracePoint::getNumArgs()
{
	return numArgs;
}

std::vector<std::string>& UTILS::TRACE::TracePoint::getArgsPre()
{
	return this->argsPre;
}

void UTILS::TRACE::TracePoint::setArgsPre(std::vector<std::string> vec)
{
	this->argsPre = vec;
}

std::vector<void*> UTILS::TRACE::TracePoint::getArgsPrePtr()
{
	return this->argsPrePtr;
}

void UTILS::TRACE::TracePoint::setArgsPrePtr(std::vector<void*> vec)
{
	this->argsPrePtr = vec;
}

std::vector<std::string>& UTILS::TRACE::TracePoint::getArgsPost()
{
	return this->argsPost;
}

void UTILS::TRACE::TracePoint::setArgsPost(std::vector<std::string> vec)
{
	this->argsPost = vec;
}