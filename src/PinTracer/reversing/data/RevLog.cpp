#include "RevLog.h"

RevLog::RevLog() {}

void RevLog::cleanLog()
{
	this->revLogVector.clear();
}

void RevLog::insertAtomInLog(RevAtom value)
{
	this->revLogVector.push_back(value);
}

std::vector<RevAtom> RevLog::getLogVector()
{
	return this->revLogVector;
}