#ifndef _HLPOINTERFIELD_H_
#define _HLPOINTERFIELD_H_

#include "HLOperation.h"
#include "../data/RevLog.h"
#include "../data/RevHeuristicAtom.h"
#include "RevHeuristic.h"
#include "../../utils/io/log.h"

class HLPointerField : public HLOperation
{
private:
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
	from the value the pointer field is made of
	*/
	std::vector<UINT16> comparisonColorsPointer;

	/**
	Pointer to a vector of colors, where each color is of one byte
	from the value of the element that is pointed to by the pointer field
	*/
	std::vector<UINT16> comparisonColorsPointed;

	/**
	Pointer to a vector of bytes, where each color is of one byte
	from the value the pointer field is made of
	*/
	std::vector<UINT8> comparisonValuesPointer;

	/**
	Pointer to a vector of bytes, where each color is of one byte
	from the value of the element that is pointed to by the pointer field
	*/
	std::vector<UINT8> comparisonValuesPointed;


public:
	HLPointerField() {};

	/**
	Constructor, based on a vector of RevAtoms
	*/
	HLPointerField(std::vector<RevAtom>& atomVec);

	/**
	Initializes the array of heuristics, must be called at least once before using them
	*/
	static void initializeRevHeuristic();

	static RevHeuristic* getInternalRevHeuristic();

	static const int getRevHeuristicNumber();

	virtual void calculateHLOperationFromLoadedAtoms();
};

#endif