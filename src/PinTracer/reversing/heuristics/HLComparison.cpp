#include "HLComparison.h"

/**
IMPORTANT: Set here the number of heuristics
*/
const int HLComparison::revHeuristicNumber = 6;
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
		XED_ICLASS_CMP, RevHeuristicAtom::IMM2MEM, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0
	));
	HLComparison::revHeuristic[ii++] = RevHeuristic(atoms);
	atoms.clear();

	//CMP(REG, reg)
	atoms.push_back(RevHeuristicAtom(
		XED_ICLASS_CMP, RevHeuristicAtom::REG2REG, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0
	));
	HLComparison::revHeuristic[ii++] = RevHeuristic(atoms);
	atoms.clear();

	//CMP(reg, REG)
	atoms.push_back(RevHeuristicAtom(
		XED_ICLASS_CMP, RevHeuristicAtom::REG2REG, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0
	));
	HLComparison::revHeuristic[ii++] = RevHeuristic(atoms);
	atoms.clear();

	//CMP(MEM, reg)
	atoms.push_back(RevHeuristicAtom(
		XED_ICLASS_CMP, RevHeuristicAtom::REG2MEM, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0
	));
	HLComparison::revHeuristic[ii++] = RevHeuristic(atoms);
	atoms.clear();

	//CMP(REG, mem)
	atoms.push_back(RevHeuristicAtom(
		XED_ICLASS_CMP, RevHeuristicAtom::MEM2REG, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0
	));
	HLComparison::revHeuristic[ii++] = RevHeuristic(atoms);
	atoms.clear();

	//CMP(REG, imm)
	atoms.push_back(RevHeuristicAtom(
		XED_ICLASS_CMP, RevHeuristicAtom::IMM2REG, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0
	));
	HLComparison::revHeuristic[ii++] = RevHeuristic(atoms);
	atoms.clear();

	//REPNE SCAS[MEM]
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

		//CMP(REG, reg)
		if (atom.getInstType() == XED_ICLASS_CMP && atom.getOperandsType() == RevHeuristicAtom::REG2REG && hAtom->regDestTainted)
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
				LOG_DEBUG(ii << ": " << InstructionWorker::byteToHexValueString(this->comparisonValuesSecond.at(ii)));
			}
		}

		//CMP(reg, REG)
		else if (atom.getInstType() == XED_ICLASS_CMP && atom.getOperandsType() == RevHeuristicAtom::REG2REG && hAtom->regSrcTainted)
		{
			//The protocol will be reversed considering that the comparison is made of the first argument to the second, so we will
			//reverse the order of the arguments (the second one is the tainted one, and we care about the value of the first)
			LOG_DEBUG("Calculating values for heuristic CMP(reg, REG)");
			this->comparisonColorsFirst = colorAtom->getRegSrcColor();
			this->comparisonColorsSecond = colorAtom->getRegDestColor();
			this->comparisonValuesFirst = dataAtom->getRegSrcValue();
			this->comparisonValuesSecond = dataAtom->getRegDestValue();
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
				LOG_DEBUG(ii << ": " << InstructionWorker::byteToHexValueString(this->comparisonValuesSecond.at(ii)));
			}
		}

		//CMP(MEM, imm)
		else if (atom.getInstType() == XED_ICLASS_CMP && atom.getOperandsType() == RevHeuristicAtom::IMM2MEM && hAtom->memDestTainted)
		{
			LOG_DEBUG("Calculating values for heuristic CMP(MEM, imm)");
			this->comparisonColorsFirst = colorAtom->getMemDestColor();
			this->comparisonColorsSecond = colorAtom->getImmSrcColorVector();
			this->comparisonValuesFirst = dataAtom->getMemDestValueBytes();
			this->comparisonValuesSecond = dataAtom->getImmSrcValue();
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
				LOG_DEBUG(ii << ": " << InstructionWorker::byteToHexValueString(this->comparisonValuesSecond.at(ii)));
			}
		}
		//CMP(MEM, reg)
		else if (atom.getInstType() == XED_ICLASS_CMP && atom.getOperandsType() == RevHeuristicAtom::REG2MEM && hAtom->memDestTainted)
		{
			LOG_DEBUG("Calculating values for heuristic CMP(MEM, reg)");
			this->comparisonColorsFirst = colorAtom->getMemDestColor();
			this->comparisonColorsSecond = colorAtom->getRegSrcColor();
			this->comparisonValuesFirst = dataAtom->getMemDestValueBytes();
			this->comparisonValuesSecond = dataAtom->getRegSrcValue();
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
				LOG_DEBUG(ii << ": " << InstructionWorker::byteToHexValueString(this->comparisonValuesSecond.at(ii)));
			}
		}
		//CMP(REG, mem)
		else if (atom.getInstType() == XED_ICLASS_CMP && atom.getOperandsType() == RevHeuristicAtom::MEM2REG && hAtom->regDestTainted)
		{
			LOG_DEBUG("Calculating values for heuristic CMP(REG, mem)");
			this->comparisonColorsFirst = colorAtom->getRegDestColor();
			this->comparisonColorsSecond = colorAtom->getMemSrcColor();
			this->comparisonValuesFirst = dataAtom->getRegDestValue();
			this->comparisonValuesSecond = dataAtom->getMemSrcValueBytes();
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
				LOG_DEBUG(ii << ": " << InstructionWorker::byteToHexValueString(this->comparisonValuesSecond.at(ii)));
			}
		}
		//CMP(REG, imm)
		else if (atom.getInstType() == XED_ICLASS_CMP && atom.getOperandsType() == RevHeuristicAtom::IMM2REG && hAtom->regDestTainted)
		{
			LOG_DEBUG("Calculating values for heuristic CMP(REG, imm)");
			this->comparisonColorsFirst = colorAtom->getRegDestColor();
			this->comparisonColorsSecond = colorAtom->getImmSrcColorVector();
			this->comparisonValuesFirst = dataAtom->getRegDestValue();
			this->comparisonValuesSecond = dataAtom->getImmSrcValue();
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
				LOG_DEBUG(ii << ": " << InstructionWorker::byteToHexValueString(this->comparisonValuesSecond.at(ii)));
			}
		}
		else
		{
			LOG_DEBUG("Requested to calculate values for an heuristic but the rules to do so are not loaded. Ignoring")
		}
	}


}