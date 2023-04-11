#include "HLComparison.h"

/**
IMPORTANT: Set here the number of heuristics
*/
const int HLComparison::revHeuristicNumber = 2;
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

	//CMP(MEM, imm)
	atoms.push_back(RevHeuristicAtom(
		XED_ICLASS_CMP, RevHeuristicAtom::IMM2MEM, 0, 1, 0, 0, 0, 0, 1
	));
	HLComparison::revHeuristic[ii++] = RevHeuristic(atoms);
	atoms.clear();

	//CMP(REG, reg)
	atoms.push_back(RevHeuristicAtom(
		XED_ICLASS_CMP, RevHeuristicAtom::REG2REG, 0, 0, 0, 1, 0, 0, 0
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

std::vector<UINT16>& HLComparison::getComparisonColorsFirst()
{
	return this->comparisonColorsFirst;
}

std::vector<UINT16>& HLComparison::getComparisonColorsSecond()
{
	return this->comparisonColorsSecond;
}

std::vector<UINT8>& HLComparison::getComparisonValuesFirst()
{
	return this->comparisonValuesFirst;
}

std::vector<UINT8>& HLComparison::getComparisonValuesSecond()
{
	return this->comparisonValuesSecond;
}

int HLComparison::getComparisonResult()
{
	return this->comparisonResult;
}

void HLComparison::calculateComparisonFromLoadedAtoms()
{
	//First we will find which element of the atom has the comparison
	//NOTE: Add here the calculation for other types of heuristics

	//Heuristic CMP(REG, reg)
	for (RevAtom& atom : this->revAtomVector)
	{
		RevHeuristicAtom* hAtom = atom.getRevHeuristicAtom();
		RevColorAtom* colorAtom = atom.getRevColorAtom();
		RevDataAtom* dataAtom = atom.getRevDataAtom();
		if (atom.getInstType() == XED_ICLASS_CMP && atom.getOperandsType() == RevHeuristicAtom::REG2REG && hAtom->regDestTainted && !hAtom->memSrcTainted && !hAtom->hasImmSrc)
		{
			LOG_DEBUG("Calculating values for heuristic CMP(REG, reg)");
			this->comparisonColorsFirst = colorAtom->getRegDestColor();
			this->comparisonColorsSecond = colorAtom->getRegSrcColor();
			this->comparisonValuesFirst = dataAtom->getRegDestValue();
			this->comparisonValuesSecond = dataAtom->getRegSrcValue();
			//ZF is set to 1 if the values checked via CMP were equal
			this->comparisonResult = dataAtom->getFlagsValue().at(6);
			LOG_DEBUG("Result of the comparison: " << this->comparisonResult);
			LOG_DEBUG("Colors of the DEST of the comparison (length: " << this->comparisonColorsFirst.size() << "):");
			for (int ii = 0; ii < this->comparisonColorsFirst.size(); ii++)
			{
				LOG_DEBUG(ii << ": " << this->comparisonColorsFirst.at(ii));
			}
			LOG_DEBUG("Values used in the comparison (length: " << this->comparisonValuesSecond.size() << "):");
			for (int ii = 0; ii < this->comparisonValuesSecond.size(); ii++)
			{
				LOG_DEBUG(ii << ": " << this->comparisonValuesSecond.at(ii));
			}
		}
		else
		{
			LOG_DEBUG("Requested to calculate values for an heuristic but the rules to do so are not loaded. Ignoring")
		}
	}


}