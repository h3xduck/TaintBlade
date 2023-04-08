#include "RevContext.h"
#include "../heuristics/HeuristicsValidator.h"

extern TestEngine globalTestEngine;
extern DataDumper dataDumper;

RevContext::RevContext()
{
	this->revLogCurrent.cleanLog();
	this->revLogHeuristics.cleanLog();
	this->currentRevAtom = RevAtom();
}

void RevContext::insertRevLog(RevAtom atom)
{
	this->revLogCurrent.logInsert(atom);
}

void RevContext::operateRevLog()
{
	//Try to get whether it is a comparison HL inst.
	HLComparison heuristicFound = REVERSING::HEURISTICS::checkValidity(&(this->revLogCurrent));

	if (heuristicFound.isHeuristicMet())
	{
		LOG_DEBUG("Logging test milestone");
		//Logging the found heuristic
		this->revLogHeuristics.logInsert(heuristicFound);

		//For tests relying on heuristics
		HeuristicMilestone testMilestone = HeuristicMilestone(heuristicFound.getInstructionVector(), TestMilestone::HEURISTIC);
		globalTestEngine.logMilestone(&testMilestone);
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
	for (HLComparison& c : this->revLogHeuristics.getLogVector())
	{
		dataDumper.writeRevHeuristicDumpLine(c);
	}
}

RevLog<HLComparison> RevContext::getHeuristicsVector()
{
	return this->revLogHeuristics;
}