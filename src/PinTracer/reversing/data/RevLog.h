#ifndef _REV_LOG_H_
#define _REV_LOG_H_

#include <iostream>
#include <vector>
#include "RevAtom.h"
#include "../heuristics/HLComparison.h"
#include "../heuristics/HLPointerField.h"

template <typename T> 
class RevLog
{
private:
	/**
	Vector of reversing components of type T
	*/
	std::vector<T> revLogVector;

	/**
	Vector that stores at which instruction did an heuristic last found a match.
	example:
	[3, 9]
	- Means that heuristic 0, e.g. an heuristic with 1 atom, last found one instruction
		belonging to it at instruction 3.
	- Heuristic 9, e.g. an heuristic with 2 atoms, last found a full match at instruction 9.
	*/
	std::vector<int> lastHeuristicHits;

public:
	RevLog();

	void cleanLog();
	void cleanFirstX(int x);
	void logInsert(T value);
	std::vector<T> getLogVector();

	/**
	Returns the index of the instruction at which an heuristic last found a match
	*/
	int getHeuristicLastHitIndex(int heuristicIndex);

	/**
	Sets the index of the instruction at which an heuristic last found a match
	*/
	void setHeutisticLastHit(int heuristicIndex, int instructionHitIndex);
};

#endif
