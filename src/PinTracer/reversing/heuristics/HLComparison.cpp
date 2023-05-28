#include "HLComparison.h"

std::vector<RevHeuristic> HLComparison::revHeuristic = std::vector<RevHeuristic>();

HLComparison::HLComparison(std::vector<RevAtom> &atomVec)
{
	this->revAtomVector = atomVec;
}


void HLComparison::initializeRevHeuristic()
{
	if (!HLComparison::revHeuristic.empty())
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

	//A comparison covers all possibilities of CMP operation. See OpComparison.
	REVERSING::HEURISTICS::OPERATORS::OpComparison opComparison = REVERSING::HEURISTICS::OPERATORS::OpComparison();
	for (std::vector<RevHeuristicAtom>& vec : opComparison.getVectorOfAtomVectors())
	{
		HLComparison::revHeuristic.push_back(RevHeuristic(vec, HLOperation::HL_operation_type_t::HLComparison));
	}
	
}

std::vector<RevHeuristic> HLComparison::getInternalRevHeuristic()
{
	return HLComparison::revHeuristic;
}

const int HLComparison::getRevHeuristicNumber()
{
	if (HLComparison::getInternalRevHeuristic().empty())
	{
		HLComparison::initializeRevHeuristic();
		//LOG_DEBUG("Heuristics for HLComparison initialized");
	}
	return HLComparison::revHeuristic.size();
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

void HLComparison::calculateHLOperationFromLoadedAtoms()
{
	//First we will find which element of the atom has the comparison
	//NOTE: Add here the calculation for other types of heuristics

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
			//NOTE: The vectors from the registers is inverted so that it can be compared with the memory
			LOG_DEBUG("Calculating values for heuristic CMP(MEM, reg)");
			this->comparisonColorsFirst = colorAtom->getMemDestColor();
			this->comparisonColorsSecond = colorAtom->getRegSrcColor();
			std::reverse(this->comparisonColorsSecond.begin(), this->comparisonColorsSecond.end());
			this->comparisonValuesFirst = dataAtom->getMemDestValueBytes();
			this->comparisonValuesSecond = dataAtom->getRegSrcValue();
			std::reverse(this->comparisonValuesSecond.begin(), this->comparisonValuesSecond.end());
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
			//NOTE: The vectors from the registers are inverted so that it can be compared with the memory
			LOG_DEBUG("Calculating values for heuristic CMP(REG, mem)");
			this->comparisonColorsFirst = colorAtom->getRegDestColor();
			std::reverse(this->comparisonColorsFirst.begin(), this->comparisonColorsFirst.end());
			this->comparisonColorsSecond = colorAtom->getMemSrcColor();
			this->comparisonValuesFirst = dataAtom->getRegDestValue();
			std::reverse(this->comparisonValuesFirst.begin(), this->comparisonValuesFirst.end());
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
			LOG_DEBUG("Requested to calculate values for a comparison heuristic but the rules to do so are not loaded. Ignoring")
		}
	}


}