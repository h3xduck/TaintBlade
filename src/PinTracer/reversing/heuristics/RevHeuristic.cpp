#include "RevHeuristic.h"

RevHeuristic::RevHeuristic()
{

}

RevHeuristic::RevHeuristic(std::vector<RevHeuristicAtom> atoms, HLOperation::HL_operation_type_t opType)
{
	for (auto& elem : atoms)
	{
		this->atomVector.push_back(elem);
	}
	this->heuristicType() = opType;
}

std::vector<RevHeuristicAtom> RevHeuristic::getAtomVector()
{
	return this->atomVector;
}