#ifndef _REVHEURISTIC_H_
#define _REVHEURISTIC_H_

/**
Determines the fields of a RevAtom which should be tainted for the instruction
to be considered part of a heuristic.
*/
class RevHeuristic
{
public:
	int instTypeTainted = 0;
	bool memSrcTainted = 0;
	bool memDestTainted = 0;
	bool regSrcTainted = 0;
	bool regDestTainted = 0;
	bool immSrcTainted = 0;

	//For LEA operations
	bool leaBaseTainted = 0;
	bool leaIndexTainted = 0;

	RevHeuristic() {};

	RevHeuristic(int instTypeTainted, bool memSrcTainted, bool memDestTainted, 
		bool regSrcTainted, bool regDestTainted, bool leaBaseTainted, 
		bool leaIndexTainted, bool immSrcTainted)
	{
		this->instTypeTainted = instTypeTainted;
		this->memSrcTainted = memSrcTainted;
		this->memDestTainted = memDestTainted;
		this->regSrcTainted = regSrcTainted;
		this->regDestTainted = regDestTainted;
		this->leaBaseTainted = leaBaseTainted;
		this->leaIndexTainted = leaIndexTainted;
		this->immSrcTainted = immSrcTainted;
	}
};

#endif
