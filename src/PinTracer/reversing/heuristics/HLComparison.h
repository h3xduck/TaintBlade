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

	/**
	Algorithm for checking an heuristic
	- For all instructions in the RevLog (N)
	- - For all heuristics in the list of heuristics (R)
	- - - Check if RevAtom of instruction = RevHeuristicAtom of instruction in heuristic (S)
	
	Returns vector of RevAtoms found to belong to the RevHeuristic (ignoring any
	RevAtom not included in the heuristic). If heuristic not met, returns empty vector.
	*/
	static std::vector<RevAtom> checkHeuristicAlgNRS(std::vector<RevAtom> revLog);

public:
	HLComparison() {};

	HLComparison(std::vector<RevAtom> &atomVec);

	/**
	Initializes the array of heuristics, must be called at least once before using them
	*/
	static void initializeRevHeuristic();

	/**
	Returns a HLComparison instance if the vector corresponds to one of the heuristics
	describing a high-level comparison instruction. Otherwise, null
	*/
	static HLComparison checkValidity(std::vector<RevAtom> revLog);

	int isHeuristicMet()
	{
		return this->heuristicMet;
	}

	/**
	Returns a vector of strings describing the instructions which compound the heuristic
	*/
	std::vector<std::string> getInstructionVector();
};


#endif
