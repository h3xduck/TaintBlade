#include "HLPointerField.h"

/**
IMPORTANT: Set here the number of heuristics
*/
const int HLPointerField::revHeuristicNumber = 6;
RevHeuristic HLPointerField::revHeuristic[revHeuristicNumber] = {};

HLPointerField::HLPointerField(std::vector<RevAtom>& atomVec)
{
	this->revAtomVector = atomVec;
}

void HLPointerField::initializeRevHeuristic()
{
	if (!HLPointerField::revHeuristic->getAtomVector().empty())
	{
		return;
	}

	std::vector<RevHeuristicAtom> atoms;
	int ii = 0;

	//TODO - Write the heuristics 

}

void HLPointerField::calculateHLOperationFromLoadedAtoms()
{
	//TODO - TO BE IMPLEMENTED


}