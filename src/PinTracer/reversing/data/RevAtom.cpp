#include "RevAtom.h"

RevAtom::RevAtom(
	ADDRINT insAddress, int instType, 
	RevHeuristicAtom::atom_operands_type_t operandsType, ADDRINT memSrc,
	INT32 memSrcLen, ADDRINT memDest,
	INT32 memDestLen, REG regSrc,
	REG regDest, REG leaBase,
	REG leaIndex, UINT32 leaScale,
	UINT32 leaDis, ADDRINT immSrc,
	ADDRINT scasMem, INT32 scasMemLen, REG regScasXAX, REG regScasXCX,
	REG regScasXDI, bool REPNE, bool REPE
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
	this->scasMem = scasMem;
	this->scasMemLen = scasMemLen;
	this->regScasXAX = regScasXAX;
	this->regScasXCX = regScasXCX;
	this->regScasXDI = regScasXDI;
	this->REPNE = REPNE;
	this->REPE = REPE;

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

void RevAtom::setLeaScale(UINT32 leaScale)
{
	this->leaScale = leaScale;
}

UINT32 RevAtom::getLeaScale()
{
	return this->leaScale;
}

void RevAtom::setLeaDis(UINT32 leaDis)
{
	this->leaDis = leaDis;
}

UINT32 RevAtom::getLeaDis() {
	return this->leaDis;
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

//REPE/REPNE SCAS
ADDRINT RevAtom::getScasMem()
{
	return this->scasMem;
}
void RevAtom::setScasMem(ADDRINT mem)
{
	this->scasMem = mem;
}
INT32 RevAtom::getScasMemLen()
{
	return this->scasMemLen;
}
void RevAtom::setScasMemLen(INT32 len)
{
	this->scasMemLen = len;
}
REG RevAtom::getRegScasXAX()
{
	return this->regScasXAX;
}
void RevAtom::setRegScasXAX(REG reg)
{
	this->regScasXAX = reg;
}
REG RevAtom::getRegScasXCX()
{
	return this->regScasXCX;
}
void RevAtom::setRegScasXCX(REG reg)
{
	this->regScasXCX = reg;
}
REG RevAtom::getRegScasXDI()
{
	return this->regScasXDI;
}
void RevAtom::setRegScasXDI(REG reg)
{
	this->regScasXDI = reg;
}
bool RevAtom::isREPNE()
{
	return this->REPNE;
}
void RevAtom::setREPNE(bool val)
{
	this->REPNE = val;
}
bool RevAtom::isREPE()
{
	return this->REPE;
}
void RevAtom::setREPE(bool val)
{
	this->REPE = val;
}