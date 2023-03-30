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
	Common heuristic that defines a HL comparison operation
	*/
	static RevHeuristic revHeuristic[];

	/**
	Numeber of posibilities inside the heuristic
	*/
	static const int revHeuristicNumber;

public:

	/**
	Initializes the array of heuristics, must be called at least once before using them
	*/
	static void initializeRevHeuristic();

	/**
	Returns a HLComparison instance if the vector corresponds to one of the heuristics
	describing a high-level comparison instruction. Otherwise, null
	*/
	static int checkValidity(std::vector<RevAtom> revLog);
};


#endif
