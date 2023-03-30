#include "RevHeuristic.h"

RevHeuristic::RevHeuristic()
{

}

RevHeuristic::RevHeuristic(std::vector<RevHeuristicAtom> atoms)
{
	for (auto& elem : atoms)
	{
		this->atomVector.push_back(elem);
	}
}

std::vector<RevHeuristicAtom> RevHeuristic::getAtomVector()
{
	return this->atomVector;
}