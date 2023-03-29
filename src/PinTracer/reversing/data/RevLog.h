#ifndef _REV_LOG_H_
#define _REV_LOG_H_

#include <iostream>
#include <vector>
#include "RevAtom.h"
#include "../heuristics/HLComparison.h"

template <typename T> 
class RevLog
{
private:
	std::vector<T> revLogVector;

public:
	RevLog();

	void cleanLog();
	void logInsert(T value);
	std::vector<T> getLogVector();
};

#endif
