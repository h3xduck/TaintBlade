#include "OpComparison.h"

std::vector<std::vector<RevHeuristicAtom>> REVERSING::HEURISTICS::OPERATORS::OpComparison::vectorOfAtomVectors = std::vector<std::vector<RevHeuristicAtom>>();

REVERSING::HEURISTICS::OPERATORS::OpComparison::OpComparison()
{
	if (OpComparison::vectorOfAtomVectors.empty())
	{
		//Initialize vector of atomvectors for opcomparison

		//CMP(MEM, imm)
		std::vector<RevHeuristicAtom> vec;
		vec.push_back(RevHeuristicAtom(
			XED_ICLASS_CMP, RevHeuristicAtom::IMM2MEM, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0
		));
		OpComparison::vectorOfAtomVectors.push_back(vec);
		vec.clear();

		//CMP(REG, reg)
		vec.push_back(RevHeuristicAtom(
			XED_ICLASS_CMP, RevHeuristicAtom::REG2REG, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0
		));
		OpComparison::vectorOfAtomVectors.push_back(vec);
		vec.clear();

		//CMP(reg, REG)
		vec.push_back(RevHeuristicAtom(
			XED_ICLASS_CMP, RevHeuristicAtom::REG2REG, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0
		));
		OpComparison::vectorOfAtomVectors.push_back(vec);
		vec.clear();

		//CMP(MEM, reg)
		vec.push_back(RevHeuristicAtom(
			XED_ICLASS_CMP, RevHeuristicAtom::REG2MEM, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0
		));
		OpComparison::vectorOfAtomVectors.push_back(vec);
		vec.clear();

		//CMP(REG, mem)
		vec.push_back(RevHeuristicAtom(
			XED_ICLASS_CMP, RevHeuristicAtom::MEM2REG, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0
		));
		OpComparison::vectorOfAtomVectors.push_back(vec);
		vec.clear();

		//CMP(REG, imm)
		vec.push_back(RevHeuristicAtom(
			XED_ICLASS_CMP, RevHeuristicAtom::IMM2REG, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0
		));
		OpComparison::vectorOfAtomVectors.push_back(vec);
		vec.clear();
	}
}

std::vector<std::vector<RevHeuristicAtom>> REVERSING::HEURISTICS::OPERATORS::OpComparison::getVectorOfAtomVectors()
{
	return OpComparison::vectorOfAtomVectors;
}
