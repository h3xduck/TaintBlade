#include "HLComparison.h"

const int HLComparison::revHeuristicNumber = 1;
RevHeuristic HLComparison::revHeuristic[revHeuristicNumber] = {};

HLComparison::HLComparison(std::vector<RevAtom> &atomVec)
{
	this->revAtomVector = atomVec;
}


void HLComparison::initializeRevHeuristic()
{
	if (!HLComparison::revHeuristic->getAtomVector().empty())
	{
		return;
	}

	//Hardcoded heuristics. 
	/** 
	********************************* HEURISTIC RULES **********************************************
	If an instruction appears in the heuristic, it must appear in the executed instruction.
	Any instruction in the log has at least 1 tainted element.
	REG or MEM in upper case means that element must be tainted, otherwise the heuristic is rejected.
	More than the mandatory elements may be tainted.
	If any instruction not meeting the heuristic is found in the RevLog, it is skipped and the heuristic
	may still be met.
	The tainted elements in a heuristic must be the same color or derived from it:
	EXAMPLE:
		Tainted RAX
		cmp rax, rbx
		mov rax, rcx
		cmp rax, rbx
		Does not meet an heuristic CMP(REG, reg), CMP(REG, reg), since rax lost its color

		Tainted RAX
		cmp rax, rbx
		mov rdx, rcx
		cmp rax, rbx
		Meets an heuristic CMP(REG, reg), CMP(REG, reg), since rax maintains its color, 
		and the second instruction is skipped.
	*/

	std::vector<RevHeuristicAtom> atoms;
	int ii = 0;

	//CMP(mem, REG)
	/*atoms.push_back(RevHeuristicAtom(
		XED_ICLASS_CMP, 0, 0, 1, 0, 0, 0, 0
	));
	HLComparison::revHeuristic[ii++] = RevHeuristic(atoms);
	atoms.clear();*/

	//CMP(MEM, imm), CMP(mem, REG)
	atoms.push_back(RevHeuristicAtom(
		XED_ICLASS_CMP, 0, 1, 0, 0, 0, 0, 1
	));
	HLComparison::revHeuristic[ii++] = RevHeuristic(atoms);
	atoms.clear();
}

std::vector<std::string> HLComparison::getInstructionVector()
{
	std::vector<std::string> resVec;

	for (auto& elem : this->revAtomVector)
	{
		resVec.push_back(xed_iclass_enum_t2str((xed_iclass_enum_t)elem.getInstType()));
	}

	return resVec;
}

int HLComparison::isHeuristicMet()
{
	return this->heuristicMet;
}

void HLComparison::setHeuristicMet(int state)
{
	this->heuristicMet = state;
}

RevHeuristic* HLComparison::getInternalRevHeuristic()
{
	return HLComparison::revHeuristic;
}

const int HLComparison::getRevHeuristicNumber()
{
	return HLComparison::revHeuristicNumber;
}

std::vector<RevAtom> HLComparison::getFullAtomVector()
{
	return this->revAtomVector;
}