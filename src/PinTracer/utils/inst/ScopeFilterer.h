#ifndef _SCOPE_FILTERER_H_
#define _SCOPE_FILTERER_H_

#include "pin.H"
#include "InstructionWorker.h"

class ScopeFilterer
{
private:
	std::string mainExecutableName = "";
	BOOL mainExecutableExited = FALSE;

public:
	ScopeFilterer() {};
	ScopeFilterer(std::string name);

	BOOL isMainExecutable(ADDRINT ip);
	BOOL isMainExecutable(INS ins);
	BOOL wasMainExecutableReached();
	BOOL hasMainExecutableExited();

	//Note: not working. This should be true when the main executable returns, but it is more difficult to do than it sounds
	VOID markMainExecutableFinished();
};


#endif

