#ifndef _REV_ATOM_H_
#define _REV_ATOM_H_

#include "pin.H"
#include <xed-category-enum.h>
#include "RevHeuristicAtom.h"
#include "RevColorAtom.h"
#include "RevDataAtom.h"
#include "../../utils/inst/InstructionWorker.h"

/**
A RevAtom is a single instruction that may be part of a sequence representing a
high-level operation (such as a comparison).
*/
class RevAtom
{
private:
	//Stores info about which elements are tainted or not
	RevHeuristicAtom revHeuristicAtom;

	//Stores colors of tainted elements in the atom
	RevColorAtom revColorAtom;

	//Stores actual values of the memory addresses and registers that are tainted
	RevDataAtom revDataAtom;

	//Basic information found in most binary operations
	int instType;
	ADDRINT memSrc;
	ADDRINT memDest;
	REG regSrc;
	REG regDest;
	INT32 memSrcLen;
	INT32 memDestLen;

	//For LEA operations
	REG leaBase;
	REG leaIndex; 
	UINT32 leaScale;
	UINT32 leaDis;
	//leaDest is contained in regDest
	//memDest will contain the memory address stored as a pointer in regDest

	//For instructions with immediate as operand
	ADDRINT immSrc;

	//Stores list of heuristics (its index) that have already detected this heuristic
	std::vector<int> detectedHeuristics;

	//Instruction address
	ADDRINT insAddress;

	//Base address (in the image)
	ADDRINT baseAddress;

	//For REPE/REPNE SCAS operations
	ADDRINT scasMem;
	INT32 scasMemLen;
	REG regScasXAX;
	REG regScasXCX;
	REG regScasXDI;
	bool REPNE; //true if REPNE
	bool REPE; //true if REPE

public:
	RevAtom(
		ADDRINT insAddress = 0, int instType = XED_ICLASS_INVALID_DEFINED, 
		RevHeuristicAtom::atom_operands_type_t operandsType = RevHeuristicAtom::INVALID, ADDRINT memSrc = 0,
		INT32 memSrcLen = 0, ADDRINT memDest = 0, 
		INT32 memDestLen = 0, REG regSrc = REG_INVALID_, 
		REG regDest = REG_INVALID_, REG leaBase = REG_INVALID_,	
		REG leaIndex = REG_INVALID_, UINT32 leaScale = 0, 
		UINT32 leaDis = 0, ADDRINT immSrc = 0,
		ADDRINT scasMem = 0, INT32 scasMemLen = 0, REG regScasXAX = REG::REG_INVALID_, REG regScasXCX = REG::REG_INVALID_,
		REG regScasXDI = REG::REG_INVALID_, bool REPNE = false, bool REPE = false
	);

	//Setters and getters
	ADDRINT getBaseAddress();
	ADDRINT getInstAddress();
	void setInstAddress(ADDRINT address);
	int getInstType();
	void setInstType(int instType);
	RevHeuristicAtom::atom_operands_type_t getOperandsType();
	void setOperandsType(RevHeuristicAtom::atom_operands_type_t operandsType);
	ADDRINT getMemSrc();
	void setMemSrc(ADDRINT memSrc);
	ADDRINT getMemDest();
	void setMemDest(ADDRINT memDest);
	REG getRegSrc();
	void setRegSrc(REG regSrc);
	REG getRegDest();
	void setRegDest(REG regDest);
	INT32 getMemSrcLen();
	void setMemSrcLen(INT32 memSrcLen);
	INT32 getMemDestLen();
	void setMemDestLen(INT32 memDestLen);
	void setLeaBase(REG leaBase);
	REG getLeaBase();
	void setLeaIndex(REG leaIndex);
	REG getLeaIndex();
	void setLeaScale(UINT32 leaScale);
	UINT32 getLeaScale();
	void setLeaDis(UINT32 leaDis);
	UINT32 getLeaDis();
	ADDRINT getImmSrc();
	void setImmSrc(ADDRINT immSrc);

	//REPE/REPNE SCAS
	ADDRINT getScasMem();
	void setScasMem(ADDRINT mem);
	INT32 getScasMemLen();
	void setScasMemLen(INT32 len);
	REG getRegScasXAX();
	void setRegScasXAX(REG reg);
	REG getRegScasXCX();
	void setRegScasXCX(REG reg);
	REG getRegScasXDI();
	void setRegScasXDI(REG reg);
	bool isREPNE(); 
	void setREPNE(bool val);
	bool isREPE();
	void setREPE(bool val);

	RevHeuristicAtom* getRevHeuristicAtom();
	RevColorAtom* getRevColorAtom();
	RevDataAtom* getRevDataAtom();

	void addDetectedHeuristic(int index);
	bool isDetectedHeuristic(int index);
};

#endif