#ifndef _REVHEURISTICATOM_H_
#define _REVHEURISTICATOM_H_

#include "../../utils/io/log.h"

/**
Determines the fields of a RevAtom which should be tainted for the instruction
to be considered part of a heuristic.
*/
class RevHeuristicAtom
{
public:
	int instType = 0;
	bool memSrcTainted = 0;
	bool memDestTainted = 0;
	bool regSrcTainted = 0;
	bool regDestTainted = 0;
	bool immSrcTainted = 0;

	//For LEA operations
	bool leaBaseTainted = 0;
	bool leaIndexTainted = 0;

	RevHeuristicAtom() {};

	RevHeuristicAtom(int instType, bool memSrcTainted, bool memDestTainted, 
		bool regSrcTainted, bool regDestTainted, bool leaBaseTainted, 
		bool leaIndexTainted, bool immSrcTainted)
	{
		this->instType = instType;
		this->memSrcTainted = memSrcTainted;
		this->memDestTainted = memDestTainted;
		this->regSrcTainted = regSrcTainted;
		this->regDestTainted = regDestTainted;
		this->leaBaseTainted = leaBaseTainted;
		this->leaIndexTainted = leaIndexTainted;
		this->immSrcTainted = immSrcTainted;
	}

	/**
	Returns whether an heuristic atom (this) is containted on another (other).
	For this to be true, the instructions must be the same, and the tainted elements on (other)
	must always be present on (this).
	*/
	bool containtedIn(const RevHeuristicAtom& other)
	{
		if (this->instType != other.instType)
		{
			return false;
		}

		if ((other.immSrcTainted && !this->immSrcTainted) ||
			(other.leaBaseTainted && !this->leaBaseTainted) || 
			(other.leaIndexTainted && !this->leaIndexTainted) || 
			(other.memDestTainted && !this->memDestTainted) || 
			(other.memSrcTainted && !this->memSrcTainted) || 
			(other.regDestTainted && !this->regDestTainted) || 
			(other.regSrcTainted && !this->regSrcTainted))
		{
			return false;
		}

		return true;
	}
};

#endif
