#include "RevAtom.h"

RevAtom::RevAtom(
	int instType, ADDRINT memSrc,
	INT32 memSrcLen, ADDRINT memDest,
	INT32 memDestLen, REG regSrc,
	REG regDest, REG leaBase,
	REG leaIndex, UINT32 leaScale,
	UINT32 leaDis
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
}

int RevAtom::getInstType()
{
	return this->instType;
}

void RevAtom::setInstType(int instType)
{
	this->instType = instType;
}

ADDRINT RevAtom::getMemSrc()
{
	return this->memSrc;
}

void RevAtom::setMemSrc(ADDRINT memSrc)
{
	this->memSrc = memSrc;
}

ADDRINT RevAtom::getMemDest()
{
	return this->memDest;
}

void RevAtom::setMemDest(ADDRINT memDest)
{
	this->memDest = memDest;
}

REG RevAtom::getRegSrc()
{
	return this->regSrc;
}

void RevAtom::setRegSrc(REG regSrc)
{
	this->regSrc = regSrc;
}

REG RevAtom::getRegDest()
{
	return this->regDest;
}

void RevAtom::setRegDest(REG regDest)
{
	this->regDest = regDest;
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
