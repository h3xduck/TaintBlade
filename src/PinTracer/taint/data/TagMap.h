#ifndef _TAGMAP_H_
#define _TAGMAP_H_

/*
	TagMaps describe shadow memory, incorporating taint data.

	16 taint colors are supported, taint is applied at byte level.

	The architecture is based on that of libdft, incorporating a STAB (Segment Translation Table)
	which contains one entry for each memory page, allowing for allocating shadow memory on demand
	for each new virtual memory allocated by the program.
*/

#include "pin.H"
#include "../../../external/pin-3.25-98650-g8f6168173-msvc-windows/pin-3.25-98650-g8f6168173-msvc-windows/extras/stlport/include/unordered_map"
#include "../../utils/io/log.h"
#include "Tag.h"
#include <iostream>
#include <cstdio>
#include "TRegister.h"

#define PAGE_SIZE 4096
#define COLOR_BYTES 2

/*
	Two main structures for storing the taint during its propagation. Granularity = bytes.
	
	memTaintField --> Taint on memory bytes.
	Implemented as hash maps for fastest insert and lookup time even with lots of entries.
	Each byte is tainted using an array of COLOR_BYTES bytes.

	regTaintField --> Taint on CPU registers.
	Implemented as an array of Tags, one for each register byte. Tainted registers:
	- General purpose registers: rax to r15, rsi and rdi, and including rsp and rbp. All bytes tainted.
	- Taint EFLAGS or other insts? //TODO: Decide later. Needed for CMP.
	Order: 
		rax, rbx, rcx, rdx,
		rsi, rdi,
		r8, r9, r10, r11, r12, r13, r14, r15,
		rsp, rbp
*/

const int REG_TAINT_FIELD_LEN = 128;

class TagMap
{
public:
	TReg tReg;

	TagMap();

	//Memory tainting, byte-level
	std::tr1::unordered_map<ADDRINT, Tag> memTaintField;

	//Register tainting
	// 2 COLOR_BYTES * 8 bytes per register * 16 registers
	Tag regTaintField[REG_TAINT_FIELD_LEN];

	//TODO -- Right now a new color is generated for each new mix
	//Collection of mixed colors and results in Tags
	//std::tr1::unordered_map< Tag> memTaintField;

	//These are to be used from the Taint Manager, and not directly from instrumentation functions
	size_t tagMapCount();
	UINT16 taintMemNew(ADDRINT addr);
	void taintMem(ADDRINT addr, UINT16 color);
	void untaintMem(ADDRINT addr);
	UINT16 getTaintColorMem(ADDRINT addr);
	Tag mixTaintMem(ADDRINT dest, ADDRINT src1, ADDRINT src2);

	UINT16 taintRegNew(LEVEL_BASE::REG reg);
	void taintReg(LEVEL_BASE::REG reg, UINT16 color);
	void untaintReg(LEVEL_BASE::REG reg);
	std::vector<Tag> getTaintColorReg(LEVEL_BASE::REG reg);
	void mixTaintReg(LEVEL_BASE::REG dest, LEVEL_BASE::REG src1, LEVEL_BASE::REG src2);

	void mixTaintRegColors(LEVEL_BASE::REG dest, UINT32 length, std::vector<UINT16> colorV1, std::vector<UINT16> colorV2);
	void mixTaintRegByte(LEVEL_BASE::REG dest, UINT32 byteIndex, UINT16 colorV1, UINT16 colorV2);
	void mixTaintMemRegAllBytes(ADDRINT dest, UINT32 length, ADDRINT src1, LEVEL_BASE::REG src2);

	UINT16 getNextTagColor();

	/*Debug: Dumps whole mem map, expensive*/
	void printMemTaintComplete();
	void printRegTaintComplete();

};


#endif