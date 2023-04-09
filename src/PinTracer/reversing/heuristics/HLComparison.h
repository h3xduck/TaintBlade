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
	Pointer to a vector of bytes, where the first operand (operand 0, dest) values can be found
	*/
	std::vector<UINT8> *comparisonValueFirst;

	/**
	Pointer to a vector of bytes, where the second operand (operand 1, src) values can be found
	*/
	std::vector<UINT8> *comparisonValueSecond;

	/**
	Result of the comparison. Just 0 if false, or 1 if true.
	*/
	int comparisonResult;

public:
	HLComparison() {};

	/**
	Constructor, based on a vector of RevAtoms. Incorporates the computation of the comparisonValue and result
	*/
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

	/**
	Returns full vector of atoms that make up the heuristic
	*/
	std::vector<RevAtom> getFullAtomVector();

	/**
	Returns the vector of bytes describing the value with which the comparison was made
	*/

	/**
	Returns the first value to which the comparison was made (first operand, dest)
	*/
	std::vector<UINT8>* getComparisonValueFirst();

	/**
	Returns the second value to which the comparison was made (second operand, src)
	*/
	std::vector<UINT8>* getComparisonValueSecond();

	/**
	Returns the result of the comparison
	*/
	int getComparisonResult();

	/**
	Takes the loaded vector of RevAtoms and calculates the comparison result and src and dest values.
	*/
	void calculateComparisonFromLoadedAtoms();
};


#endif
