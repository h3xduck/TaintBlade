#include "RevAtom.h"

RevAtom::RevAtom(
	int instType, ADDRINT memSrc,
	INT32 memSrcLen, ADDRINT memDest,
	INT32 memDestLen, REG regSrc,
	REG regDest, REG leaBase,
	REG leaIndex, UINT32 leaScale,
	UINT32 leaDis, UINT64 immSrc
)
{
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

ADDRINT RevAtom::getMemSrc()
{
	return this->memSrc;
}

void RevAtom::setMemSrc(ADDRINT memSrc)
{
	this->memSrc = memSrc;
	this->getRevHeuristicAtom()->immSrcTainted = true;
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

UINT64 RevAtom::getImmSrc()
{
	return this->immSrc;
}

void RevAtom::setImmSrc(UINT64 immSrc)
{
	this->immSrc = immSrc;
	this->getRevHeuristicAtom()->immSrcTainted = true;
}

RevHeuristicAtom* RevAtom::getRevHeuristicAtom()
{
	return &(this->revHeuristicAtom);
}

RevColorAtom* RevAtom::getRevColorAtom()
{
	return &(this->revColorAtom);
}