#include "RevAtom.h"

RevAtom::RevAtom(
	ADDRINT insAddress, int instType, 
	RevHeuristicAtom::atom_operands_type_t operandsType, ADDRINT memSrc,
	INT32 memSrcLen, ADDRINT memDest,
	INT32 memDestLen, REG regSrc,
	REG regDest, REG leaBase,
	REG leaIndex, UINT32 leaScale,
	UINT32 leaDis, ADDRINT immSrc
)
{
	PIN_LockClient();
	this->baseAddress = InstructionWorker::getBaseAddress(insAddress);
	PIN_UnlockClient();
	this->insAddress = insAddress;
	this->instType = instType;
	this->memSrc = memSrc;
	this->memDest = memDest;
	this->regSrc = regSrc;
	this->regDest = regDest;
	this->memSrcLen = memSrcLen;
	this->memDestLen = memDestLen;
	this->leaBase = leaBase;
	this->leaIndex = leaIndex;
	this->leaScale = leaScale;
	this->leaDis = leaDis;
	this->immSrc = immSrc;

	//this->revColorAtom = RevColorAtom();
	//this->revDataAtom = RevDataAtom();
	//this->revHeuristicAtom = RevHeuristicAtom();
}

ADDRINT RevAtom::getBaseAddress()
{
	return this->baseAddress;
}

ADDRINT RevAtom::getInstAddress()
{
	return this->insAddress;
}

void RevAtom::setInstAddress(ADDRINT address)
{
	PIN_LockClient();
	this->insAddress = address;
	this->baseAddress = InstructionWorker::getBaseAddress(insAddress);
	PIN_UnlockClient();
}

int RevAtom::getInstType()
{
	return this->instType;
}

void RevAtom::setInstType(int instType)
{
	this->instType = instType;
	this->getRevHeuristicAtom()->instType = instType;
}

RevHeuristicAtom::atom_operands_type_t RevAtom::getOperandsType()
{
	return this->getRevHeuristicAtom()->operandsType;
}

void RevAtom::setOperandsType(RevHeuristicAtom::atom_operands_type_t operandsType)
{
	this->getRevHeuristicAtom()->operandsType = operandsType;
}

ADDRINT RevAtom::getMemSrc()
{
	return this->memSrc;
}

void RevAtom::setMemSrc(ADDRINT memSrc)
{
	this->memSrc = memSrc;
	this->getRevHeuristicAtom()->memSrcTainted = true;
}

ADDRINT RevAtom::getMemDest()
{
	return this->memDest;
}

void RevAtom::setMemDest(ADDRINT memDest)
{
	this->memDest = memDest;
	this->getRevHeuristicAtom()->memDestTainted = true;
}

REG RevAtom::getRegSrc()
{
	return this->regSrc;
}

void RevAtom::setRegSrc(REG regSrc)
{
	this->regSrc = regSrc;
	this->getRevHeuristicAtom()->regSrcTainted = true;
}

REG RevAtom::getRegDest()
{
	return this->regDest;
}

void RevAtom::setRegDest(REG regDest)
{
	this->regDest = regDest;
	this->getRevHeuristicAtom()->regDestTainted = true;
}

INT32 RevAtom::getMemSrcLen()
{
	return this->memSrcLen;
}

void RevAtom::setMemSrcLen(INT32 memSrcLen)
{
	this->memSrcLen = memSrcLen;
}

INT32 RevAtom::getMemDestLen()
{
	return this->memDestLen;
}

void RevAtom::setMemDestLen(INT32 memDestLen)
{
	this->memDestLen = memDestLen;
}

REG RevAtom::getLeaBase()
{
	return this->leaBase;
}

void RevAtom::setLeaBase(REG leaBase)
{
	this->leaBase = leaBase;
	this->getRevHeuristicAtom()->leaBaseTainted = true;
}

REG RevAtom::getLeaIndex()
{
	return this->leaIndex;
}

void RevAtom::setLeaIndex(REG leaIndex)
{
	this->leaIndex = leaIndex;
	this->getRevHeuristicAtom()->leaIndexTainted = true;
}

ADDRINT RevAtom::getImmSrc()
{
	return this->immSrc;
}

void RevAtom::setImmSrc(ADDRINT immSrc)
{
	this->immSrc = immSrc;
	this->getRevHeuristicAtom()->hasImmSrc = true;
}

RevHeuristicAtom* RevAtom::getRevHeuristicAtom()
{
	return &(this->revHeuristicAtom);
}

RevColorAtom* RevAtom::getRevColorAtom()
{
	return &(this->revColorAtom);
}

RevDataAtom* RevAtom::getRevDataAtom()
{
	return &(this->revDataAtom);
}

void RevAtom::addDetectedHeuristic(int index)
{
	this->detectedHeuristics.push_back(index);
}

bool RevAtom::isDetectedHeuristic(int index)
{
	return std::find(this->detectedHeuristics.begin(), this->detectedHeuristics.end(), index) != this->detectedHeuristics.end();
}