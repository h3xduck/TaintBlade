#ifndef _SCOPE_FILTERER_H_
#define _SCOPE_FILTERER_H_

#include "pin.H"
#include "InstructionWorker.h"

class ScopeFilterer
{
private:
	std::string mainExecutableName = "";
	BOOL mainExecutableExited = FALSE;

	//Images that, apart from the main one, are selected to be instrumented
	std::vector<std::string> scopeImages; 

public:
	ScopeFilterer() {};
	ScopeFilterer(std::string name);

	BOOL isMainExecutable(ADDRINT ip);
	BOOL isMainExecutable(INS ins);
	BOOL wasMainExecutableReached();
	BOOL hasMainExecutableExited();

	/**
	Adds a new image to the list of scoped images, so that all instructions on it are instrumented from that point onwards
	*/
	void addScopeImage(IMG img);

	/**
	Returns whether the name of the image / instruction / IP is included in the list of images to instrument
	*/
	bool isScopeImage(IMG img);
	bool isScopeImage(INS ins);
	bool isScopeImage(ADDRINT ip);

	//Note: not working. This should be true when the main executable returns, but it is more difficult to do than it sounds
	VOID markMainExecutableFinished();
};


#endif

