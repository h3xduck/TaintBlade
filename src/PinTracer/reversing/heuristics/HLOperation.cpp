#include "HLOperation.h"

int HLOperation::isHeuristicMet()
{
	return this->heuristicMet;
}

void HLOperation::setHeuristicMet(int state)
{
	this->heuristicMet = state;
}

std::vector<RevAtom> HLOperation::getFullAtomVector()
{
	return this->revAtomVector;
}

std::vector<std::string> HLOperation::getInstructionVector()
{
	std::vector<std::string> resVec;

	for (auto& elem : this->revAtomVector)
	{
		resVec.push_back(xed_iclass_enum_t2str((xed_iclass_enum_t)elem.getInstType()));
	}

	return resVec;
}