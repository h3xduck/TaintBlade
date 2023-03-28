#ifndef _REV_LOG_H_
#define _REV_LOG_H_

#include <iostream>
#include <vector>
#include "RevAtom.h"

class RevLog
{
private:
	std::vector<RevAtom> revLogVector;
public:

	RevLog();

	void cleanLog();
	void insertAtomInLog(RevAtom value);
	std::vector<RevAtom> getLogVector();
};

#endif
