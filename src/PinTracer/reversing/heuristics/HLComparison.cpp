#include "HLComparison.h"

const int HLComparison::revHeuristicNumber = 1;
RevHeuristic HLComparison::revHeuristic[revHeuristicNumber] = {};

void HLComparison::initializeRevHeuristic()
{
	if (!HLComparison::revHeuristic->getAtomVector().empty())
	{
		return;
	}

	//Hardcoded heuristics
	//CMP
	std::vector<RevHeuristicAtom> atoms;
	atoms.push_back(RevHeuristicAtom(
		XED_ICLASS_CMP, 0, 0, 0, 0, 0, 0, 0
	));
	HLComparison::revHeuristic[0] = RevHeuristic(
		atoms
	);
	atoms.clear();
}

int HLComparison::checkValidity(std::vector<RevAtom> revLog)
{
	if (HLComparison::revHeuristic->getAtomVector().empty())
	{
		HLComparison::initializeRevHeuristic();
		LOG_DEBUG("Heuristics for HLComparison initialized");
	}

	//We must check whether the revLog corresponds to any of the hardcoded heuristics
	size_t size = revLog.size();
	
	for (int ii = HLComparison::revHeuristicNumber; ii > 0; ii--)
	{
		for (int jj = size-1; jj >=0; jj--)
		{
			RevAtom atom = revLog.at(jj);
			RevHeuristic heuristic = HLComparison::revHeuristic[ii-1];
			std::vector<RevHeuristicAtom> atomHeuristicVector = heuristic.getAtomVector();

			//LOG_DEBUG("V: " << atom.getInstType() << " H: "<< atomHeuristicVector.back().instType);
			
			if (atom.getInstType() == atomHeuristicVector.back().instType)
			{
				//Found possible start of heuristic in building block
				//We now go back checking for continuation of heuristic
				int reverseTraversed = 0;
				int heuristicMet = 1;
				for (int kk = atomHeuristicVector.size() - 1; kk >= 0; kk--)
				{
					if (jj - reverseTraversed < 0)
					{
						//The heuristic is not fully met
						heuristicMet = 0;
						break;
					}

					if (atomHeuristicVector.at(kk).instType != revLog.at(jj - reverseTraversed).getInstType())
					{
						heuristicMet = 0;
						break;
					}
				}

				//We now check if we met the heuristic
				if (heuristicMet == 1)
				{
					//TODO check other things apart from instType and return more stuff.
					LOG_DEBUG("Heuristic met!");
					return 1;
				}
			}
		}
	}

	return 0;
}