#include "OpPointerArithmetic.h"

std::vector<std::vector<RevHeuristicAtom>> REVERSING::HEURISTICS::OPERATORS::OpPointerArithmetic::vectorOfAtomVectors = std::vector<std::vector<RevHeuristicAtom>>();

REVERSING::HEURISTICS::OPERATORS::OpPointerArithmetic::OpPointerArithmetic()
{
	if (OpPointerArithmetic::vectorOfAtomVectors.empty())
	{
		//Initialize vector of atomvectors for opcomparison

		//LEA(destreg --> MEM, [(leabase+leadis) --> MEM, leaindex --> MEM, leascale])
		//meaning that:
		//destreg's value points to a tainted mem
		//leabase+leadis points to a tainted mem
		//leaindex points to a tainted mem
		std::vector<RevHeuristicAtom> vec;
		vec.push_back(RevHeuristicAtom(
			XED_ICLASS_LEA, RevHeuristicAtom::MEM2REG_LEA, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0
		));
		OpPointerArithmetic::vectorOfAtomVectors.push_back(vec);
	}
}

std::vector<std::vector<RevHeuristicAtom>> REVERSING::HEURISTICS::OPERATORS::OpPointerArithmetic::getVectorOfAtomVectors()
{
	return OpPointerArithmetic::vectorOfAtomVectors;
}
