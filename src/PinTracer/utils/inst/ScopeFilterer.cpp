#include "ScopeFilterer.h"

ScopeFilterer::ScopeFilterer(std::string name)
{
	LOG_DEBUG("Restricting instrumentation via ScopeFilterer to main image " << name);
	this->mainExecutableName = name;
}


BOOL ScopeFilterer::isMainExecutable(ADDRINT ip)
{
	IMG img = IMG_FindByAddress(ip);
	if (!IMG_Valid(img))
	{
		//LOG_DEBUG("Not valid");
		return FALSE;
	}

	if (IMG_IsMainExecutable(img))
	{
		this->mainExecutableName = IMG_Name(img);
		return TRUE;
	}
	//LOG_DEBUG("No: " << IMG_Name(img));
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

void ScopeFilterer::addScopeImage(IMG img)
{
	this->scopeImages.push_back(IMG_Name(img));
}

bool ScopeFilterer::isScopeImage(IMG img)
{
	return std::find(this->scopeImages.begin(), this->scopeImages.end(), IMG_Name(img)) != this->scopeImages.end();
}

bool ScopeFilterer::isScopeImage(INS ins)
{
	const ADDRINT addr = INS_Address(ins);
	const IMG img = IMG_FindByAddress(addr);
	return this->isScopeImage(img);
}

bool ScopeFilterer::isScopeImage(ADDRINT ip)
{
	IMG img = IMG_FindByAddress(ip);
	if (!IMG_Valid(img))
	{
		return false;
	}

	return this->isScopeImage(img);
}