#include "RevContext.h"

RevContext::RevContext()
{
	this->revLogCurrent.cleanLog();
	this->revLogParsed.cleanLog();
	this->currentRevAtom = RevAtom();
}

void RevContext::insertRevLog(RevAtom atom)
{
	this->revLogCurrent.logInsert(atom);
}

void RevContext::operateRevLog()
{
	//Try to get whether it is a comparison HL inst.
	HLComparison heuristicFound = HLComparison::checkValidity(this->revLogCurrent.getLogVector());

	if (heuristicFound.isHeuristicMet())
	{
		this->cleanRevLogCurrent();
		this->cleanCurrentRevAtom();
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

void RevContext::printRevLogParsed()
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