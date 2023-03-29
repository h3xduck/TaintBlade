#ifndef _REVHEURISTIC_H_
#define _REVHEURISTIC_H_

/**
Determines the fields of a RevAtom which should be tainted for the instruction
to be considered part of a heuristic.
*/
class RevHeuristic
{
public:
	int instType;
	bool memSrc;
	bool memDest;
	bool regSrc;
	bool regDest;

	//For LEA operations
	bool leaBase;
	bool leaIndex;

	RevHeuristic(int instType, bool memSrc, bool memDest, bool regSrc, 
		bool regDest, bool leaBase, bool leaIndex)
	{
		this->instType = instType;
		this->memSrc = memSrc;
		this->memDest = memDest;
		this->regSrc = regSrc;
		this->regDest = regDest;
		this->leaBase = leaBase;
		this->leaIndex = leaIndex;
	}
};

#endif
