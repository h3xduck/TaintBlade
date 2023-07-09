#include "RevContext.h"
#include "../heuristics/HeuristicsValidator.h"

extern TestEngine globalTestEngine;

RevContext::RevContext()
{
	this->revLogCurrent.cleanLog();
	this->revLogComparisonHeuristics.cleanLog();
	this->revLogPointerFieldHeuristics.cleanLog();
	this->currentRevAtom = RevAtom();
}

void RevContext::insertRevLog(RevAtom atom)
{
	this->revLogCurrent.logInsert(atom);
}

void RevContext::operateRevLog()
{
	//Try to get whether it is a comparison HL inst.
	std::pair<HLOperation*, HLOperation::HL_operation_type_t> heuristicFound = REVERSING::HEURISTICS::checkValidity(&(this->revLogCurrent));

	if (heuristicFound.second == HLOperation::HLUnknown)
	{
		//We did not get any heuristic met
		return;
	}

	
	if (heuristicFound.second == HLOperation::HLComparison)
	{
		HLComparison* heuristic = static_cast<HLComparison*>(heuristicFound.first);
		if (heuristic->isHeuristicMet())
		{
			LOG_DEBUG("Logging comparison heuristic that was met");
			//Logging the found heuristic
			this->revLogComparisonHeuristics.logInsert(*heuristic);

			//LOG_DEBUG("CHECKPOINT REVLOGHEURISTICS[last]: " << this->revLogHeuristics.getLogVector().back().getComparisonColorsFirst().at(0));

			//For tests relying on heuristics
			HeuristicMilestone testMilestone = HeuristicMilestone(heuristic->getInstructionVector(), TestMilestone::HEURISTIC);
			globalTestEngine.logMilestone(&testMilestone);
			delete heuristic;
		}
	}
	else if (heuristicFound.second == HLOperation::HLPointerField)
	{
		HLPointerField* heuristic = static_cast<HLPointerField*>(heuristicFound.first);
		if (heuristic->isHeuristicMet())
		{
			LOG_DEBUG("Logging pointer field heuristic that was met");
			//Logging the found heuristic
			this->revLogPointerFieldHeuristics.logInsert(*heuristic);

			//LOG_DEBUG("CHECKPOINT REVLOGHEURISTICS[last]: " << this->revLogHeuristics.getLogVector().back().getComparisonColorsFirst().at(0));

			//For tests relying on heuristics
			HeuristicMilestone testMilestone = HeuristicMilestone(heuristic->getInstructionVector(), TestMilestone::HEURISTIC);
			globalTestEngine.logMilestone(&testMilestone);
			delete heuristic;
		}
	}
}

void RevContext::printRevLogCurrent()
{
	std::cerr << "CURRENT REV LOG VECTOR PRINT START" << std::endl;
	for (auto elem : this->revLogCurrent.getLogVector())
	{
		std::cerr << elem.getInstType() << "\n\tMS: " << elem.getMemSrc() << ":" << elem.getMemSrcLen() <<
			"\n\tMD: " << elem.getMemDest() << ":" << elem.getMemDestLen() << 
			"\n\tRS: " << elem.getRegSrc() <<
			"\n\tRD: " << elem.getRegDest() << "\n";
	}
	std::cerr << "CURRENT REV LOG VECTOR PRINT END" << std::endl;
}

void RevContext::cleanRevLogCurrent()
{
	this->revLogCurrent.cleanLog();
}

void RevContext::cleanRangeRevLogCurrent(int x)
{
	this->revLogCurrent.cleanFirstX(x);
}

void RevContext::printRevLogHeuristics()
{
	//TODO
}

RevAtom* RevContext::getCurrentRevAtom()
{
	return &(this->currentRevAtom);
}

void RevContext::cleanCurrentRevAtom()
{
	this->currentRevAtom = RevAtom();
}

int RevContext::getRevLogCurrentLength()
{
	return this->revLogCurrent.getLogVector().size();
}

void RevContext::dumpFoundHeuristics()
{
	for (HLComparison& c : this->revLogComparisonHeuristics.getLogVector())
	{
		ctx.getDataDumper().writeRevHeuristicDumpLine(c);
	}
	for (HLPointerField& c : this->revLogPointerFieldHeuristics.getLogVector())
	{
		ctx.getDataDumper().writeRevHeuristicDumpLine(c);
	}
}

RevLog<HLComparison>& RevContext::getComparisonHeuristicsVector()
{
	return this->revLogComparisonHeuristics;
}

RevLog<HLPointerField>& RevContext::getPointerFieldHeuristicsVector()
{
	return this->revLogPointerFieldHeuristics;
}