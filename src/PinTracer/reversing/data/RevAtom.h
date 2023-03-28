#ifndef _REV_ATOM_H_
#define _REV_ATOM_H_

#include "pin.H"
#include <xed-category-enum.h>

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