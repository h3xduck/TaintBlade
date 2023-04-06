#ifndef _HLCOMPARISON_H_
#define _HLCOMPARISON_H_

#include <vector>
#include <memory>
#include <iostream>
#include <xed-category-enum.h>
#include "../data/RevAtom.h"
#include "../data/RevLog.h"
#include "../data/RevHeuristicAtom.h"
#include "RevHeuristic.h"
#include "../../utils/io/log.h"

class HLComparison
{
private:
	/**
	Vector of RevAtoms of which the HLComparison is made of
	*/
	std::vector<RevAtom> revAtomVector;

	/**
	Specifies whether an heuristic was met
	*/
	int heuristicMet = 0;

	/**
	Common heuristic that defines a HL comparison operation
	*/
	static RevHeuristic revHeuristic[];

	/**
	Number of posibilities inside the heuristic
	*/
	static const int revHeuristicNumber;

public:
	HLComparison() {};

	HLComparison(std::vector<RevAtom> &atomVec);

	/**
	Initializes the array of heuristics, must be called at least once before using them
	*/
	static void initializeRevHeuristic();

	int isHeuristicMet();

	void setHeuristicMet(int state);

	static RevHeuristic* getInternalRevHeuristic();

	static const int getRevHeuristicNumber();

	/**
	Returns a vector of strings describing the instructions which compound the heuristic
	*/
	std::vector<std::string> getInstructionVector();
};


#endif
