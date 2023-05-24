#ifndef _HLOPERATION_H_
#define _HLOPERATION_H_

#include <vector>
#include <memory>
#include <iostream>
#include <xed-category-enum.h>
#include "../data/RevAtom.h"



class HLOperation
{
protected:
	/**
	Vector of RevAtoms of which the HLOperation is made of
	*/
	std::vector<RevAtom> revAtomVector;

	/**
	Specifies whether an heuristic was met
	*/
	int heuristicMet = 0;

public:
	int isHeuristicMet();

	void setHeuristicMet(int state);

	/**
	Returns full vector of atoms that make up the heuristic
	*/
	std::vector<RevAtom> getFullAtomVector();

	/**
	Returns a vector of strings describing the instructions which compound the heuristic
	*/
	std::vector<std::string> getInstructionVector();

	/**
	Takes the loaded vector of RevAtoms and calculates the heuristic result and result values depending on the HL operation.
	*/
	virtual void calculateHLOperationFromLoadedAtoms() = 0;
};


#endif