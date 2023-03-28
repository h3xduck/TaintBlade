#ifndef _REV_ATOM_H_
#define _REV_ATOM_H_

#include "pin.H"
#include <xed-category-enum.h>

/**
A RevAtom is a single instruction that may be part of a comparison high-level instruction

*/
class RevAtom
{
private:
	int instType = XED_ICLASS_INVALID_DEFINED;
	int comparisonLength = 0;
	std::string comparisonBytes;

public:
	RevAtom(int instType, int comparisonLength, std::string comparisonBytes);
	int getInstType();
};

#endif