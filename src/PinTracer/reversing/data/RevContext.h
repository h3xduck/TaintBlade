#ifndef _REV_CONTEXT_H_
#define _REV_CONTEXT_H_

#include "RevLog.h"
#include "RevAtom.h"

class RevContext
{
private:
	RevLog<RevAtom> revLog;
public:
	RevContext();
	void insertRevLog();
};

#endif