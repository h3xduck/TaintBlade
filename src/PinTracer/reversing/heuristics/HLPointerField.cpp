#include "HLPointerField.h"

std::vector<RevHeuristic> HLPointerField::revHeuristic = std::vector<RevHeuristic>();

HLPointerField::HLPointerField(std::vector<RevAtom>& atomVec)
{
	this->revAtomVector = atomVec;
}

void HLPointerField::initializeRevHeuristic()
{
	if (!HLPointerField::revHeuristic.empty())
	{
		return;
	}

	std::vector<RevHeuristicAtom> atoms;
	int ii = 0;

	//TODO - Write the heuristics 

}

std::vector<RevHeuristic> HLPointerField::getInternalRevHeuristic()
{
	return HLPointerField::revHeuristic;
}

const int HLPointerField::getRevHeuristicNumber()
{
	return HLPointerField::revHeuristic.size();
}

void HLPointerField::calculateHLOperationFromLoadedAtoms()
{
	//TODO - TO BE IMPLEMENTED


}