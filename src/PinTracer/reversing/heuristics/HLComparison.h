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
	Pointer to a vector of colors, where each color is of one byte
	from the first operand (operand 0, dest)
	*/
	std::vector<UINT16> *comparisonColorsFirst;

	/**
	Pointer to a vector of colors, where each color is of one byte
	from the second operand (operand 1, src)
	*/
	std::vector<UINT16> *comparisonColorsSecond;

	/**
	Pointer to a vector of bytes, where each byte is the value of one byte
	from the first operand (operand 0, dest)
	*/
	std::vector<UINT8>* comparisonValuesFirst;

	/**
	Pointer to a vector of bytes, where each byte is the value of one byte
	from the second operand (operand 1, src)
	*/
	std::vector<UINT8>* comparisonValuesSecond;

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
	Returns the first colors vector of the operand to which the comparison was made (first operand, dest)
	*/
	std::vector<UINT16>* getComparisonColorsFirst();

	/**
	Returns the second colors vector of the operand to which the comparison was made (second operand, src)
	*/
	std::vector<UINT16>* getComparisonColorsSecond();

	/**
	Returns the first values vector of the operand to which the comparison was made (first operand, dest)
	*/
	std::vector<UINT8>* getComparisonValuesFirst();

	/**
	Returns the second values vector of the operand to which the comparison was made (second operand, src)
	*/
	std::vector<UINT8>* getComparisonValuesSecond();

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
