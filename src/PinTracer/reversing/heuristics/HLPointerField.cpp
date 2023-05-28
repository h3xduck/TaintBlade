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

	REVERSING::HEURISTICS::OPERATORS::OpPointerArithmetic opPArith = REVERSING::HEURISTICS::OPERATORS::OpPointerArithmetic();
	for (std::vector<RevHeuristicAtom>& vec : opPArith.getVectorOfAtomVectors())
	{
		HLPointerField::revHeuristic.push_back(RevHeuristic(vec, HLOperation::HLPointerField));
	}

}

std::vector<RevHeuristic> HLPointerField::getInternalRevHeuristic()
{
	return HLPointerField::revHeuristic;
}

const int HLPointerField::getRevHeuristicNumber()
{
	if (HLPointerField::getInternalRevHeuristic().empty())
	{
		HLPointerField::initializeRevHeuristic();
		//LOG_DEBUG("Heuristics for HLPointerField initialized");
	}
	return HLPointerField::revHeuristic.size();
}

void HLPointerField::calculateHLOperationFromLoadedAtoms()
{
	//TODO - TO BE IMPLEMENTED


}