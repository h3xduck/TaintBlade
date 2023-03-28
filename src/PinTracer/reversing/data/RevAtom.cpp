#include "RevAtom.h"

RevAtom::RevAtom(int instType, int comparisonLength, std::string comparisonBytes)
{
	this->instType = instType;
	this->comparisonLength = comparisonLength;
	this->comparisonBytes = comparisonBytes;
}

int RevAtom::getInstType()
{
	return this->instType;
}