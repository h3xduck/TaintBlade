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
	for (RevAtom& atom : this->revAtomVector)
	{
		RevHeuristicAtom* hAtom = atom.getRevHeuristicAtom();
		RevColorAtom* colorAtom = atom.getRevColorAtom();
		RevDataAtom* dataAtom = atom.getRevDataAtom();

		//see OpPointerArithmetic
		//LEA(destreg --> MEM, [(leabase+leadis) --> MEM, leaindex --> MEM, leascale])
		if (atom.getInstType() == XED_ICLASS_LEA && atom.getOperandsType() == RevHeuristicAtom::MEM2REG_LEA && hAtom->leaIndirectTaint)
		{
			LOG_DEBUG("Calculating values for heuristic LEA(destreg --> MEM, [(leabase+leadis) --> MEM, leaindex --> MEM, leascale])");
			this->comparisonColorsPointer() = colorAtom->leaIndexColor;
			this->comparisonColorsPointed() = colorAtom->getMemDestColor();
			this->comparisonValuesPointer() = dataAtom->getLeaIndexValue();
			this->comparisonValuesPointed() = dataAtom->getRegDestValue();
			LOG_DEBUG("Colors of the DEST of the pointer field (length: " << this->comparisonColorsPointed().size() << "):");
			for (int ii = 0; ii < this->comparisonColorsPointed().size(); ii++)
			{
				LOG_DEBUG(ii << ": " << this->comparisonColorsPointed().at(ii));
			}
			LOG_DEBUG("Colors of the POINTER of the pointer field (length: " << this->comparisonColorsPointer().size() << "):");
			for (int ii = 0; ii < this->comparisonColorsPointer().size(); ii++)
			{
				LOG_DEBUG(ii << ": " << this->comparisonColorsPointer().at(ii));
			}
			LOG_DEBUG("Value of the POINTER to the pointed field (length: " << this->comparisonValuesPointer().size() << "):");
			for (int ii = 0; ii < this->comparisonValuesPointer().size(); ii++)
			{
				LOG_DEBUG(ii << ": " << InstructionWorker::byteToHexValueString(this->comparisonValuesPointer().at(ii)));
			}
		}
		else
		{
			LOG_DEBUG("Requested to calculate values for a pointer field heuristic but the rules to do so are not loaded. Ignoring");
		}

	}
}