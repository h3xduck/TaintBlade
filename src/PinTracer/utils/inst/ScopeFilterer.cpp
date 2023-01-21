#include "ScopeFilterer.h"

ScopeFilterer::ScopeFilterer(std::string name)
{
	this->mainExecutableName = name;
}


BOOL ScopeFilterer::isMainExecutable(ADDRINT ip)
{
	IMG img = IMG_FindByAddress(ip);
	if (!IMG_Valid(img))
	{
		return FALSE;
	}

	if (IMG_IsMainExecutable(img))
	{
		this->mainExecutableName = IMG_Name(img);
		return TRUE;
	}

	return FALSE;
}

BOOL ScopeFilterer::isMainExecutable(INS ins)
{
	return isMainExecutable(INS_Address(ins));
}

BOOL ScopeFilterer::wasMainExecutableReached()
{
	return this->mainExecutableName != "";
}

BOOL ScopeFilterer::hasMainExecutableExited()
{
	return this->mainExecutableExited;
}

VOID ScopeFilterer::markMainExecutableFinished()
{
	this->mainExecutableExited = TRUE;
}