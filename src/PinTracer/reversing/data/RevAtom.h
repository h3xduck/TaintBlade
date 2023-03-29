#ifndef _REV_ATOM_H_
#define _REV_ATOM_H_

#include "pin.H"
#include <xed-category-enum.h>

/**
A RevAtom is a single instruction that may be part of a sequence representing a
high-level operation (such as a comparison).
*/
class RevAtom
{
private:
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

public:
	RevAtom(
		int instType = XED_ICLASS_INVALID_DEFINED, ADDRINT memSrc = 0,
		INT32 memSrcLen = 0, ADDRINT memDest = 0, 
		INT32 memDestLen = 0, REG regSrc = REG_INVALID_, 
		REG regDest = REG_INVALID_, REG leaBase = REG_INVALID_,	
		REG leaIndex = REG_INVALID_, UINT32 leaScale = 0, 
		UINT32 leaDis = 0
	);

	int getInstType();
	void setInstType(int instType);
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
};

#endif