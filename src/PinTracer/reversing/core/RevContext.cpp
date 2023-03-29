#include "RevContext.h"

RevContext::RevContext()
{
	this->revLogCurrent.cleanLog();
	this->revLogParsed.cleanLog();
}

void RevContext::insertRevLog(RevAtom atom)
{
	this->revLogCurrent.logInsert(atom);
}

void RevContext::operateRevLog()
{
	//Try to get whether it is a comparison HL inst.
	HLComparison::checkValidity(this->revLogCurrent.getLogVector());
}

void RevContext::printRevLogCurrent()
{
	std::cerr << "CURRENT REV LOG VECTOR PRINT START" << std::endl;
	for (auto elem : this->revLogCurrent.getLogVector())
	{
		std::cerr << "{" << elem.getInstType() << "\n\tMS: " << elem.getMemSrc() << ":" << elem.getMemSrcLen() <<
			"\n\tMD: " << elem.getMemDest() << ":" << elem.getMemDestLen() << 
			"\n\tRS: " << elem.getRegSrc() <<
			"\n\tRD: " << elem.getRegDest() << "\n }\n";
	}
	std::cerr << "CURRENT REV LOG VECTOR PRINT END" << std::endl;
}

void RevContext::printRevLogParsed()
{
	//TODO
}
