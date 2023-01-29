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
#include "../../utils/io/format.h"
#include "Tag.h"
#include <iostream>
#include <cstdio>
#include "TRegister.h"
#include "TagLog.h"

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
	TagLog tagLog;

	TagMap();

	//Memory tainting, byte-level
	std::tr1::unordered_map<ADDRINT, Tag> memTaintField;

	//Register tainting
	// 2 COLOR_BYTES * 8 bytes per register * 16 registers
	Tag regTaintField[REG_TAINT_FIELD_LEN];

	//These are to be used from the Taint Manager, and not directly from instrumentation functions
	size_t tagMapCount();
	
	/**
	Taints single memory byte with a color = Tag::lastColor,
	then increments Tag::lastColor.
	*/
	UINT16 taintMemNew(ADDRINT addr);

	/**
	Taints single memory byte with color=color.
	If memory is already tainted, it will only update Tag color in memory map.
	*/
	void taintMem(ADDRINT addr, UINT16 color);

	/**
	Removes single memory byte from memory map.
	*/
	void untaintMem(ADDRINT addr);

	/**
	Returns color of Tag corresponding to memory at memory map.
	If not found in map, returns empty color.
	*/
	UINT16 getTaintColorMem(ADDRINT addr);

	/**
	Mixes colors src1 and src2 into dest.
	src1 and dest are expected to be the same element: Binary ops only!
	Introduces mix in taglog if generated.
	*/
	Tag mixTaintMem(ADDRINT dest, ADDRINT src1, ADDRINT src2);

	/**
	Taints all bytes of register with a new color corresponding
	to Tag::lastColor. Increments Tag::lastColor.
	Colors of all bytes are all the same.
	*/
	void taintRegNew(LEVEL_BASE::REG reg);

	/**
	Taints all bytes of a register with the specified color.
	If color > Tag::lastColor, then Tag::lastColor = color.
	Colors of all bytes are all the same.
	*/
	void taintReg(LEVEL_BASE::REG reg, UINT16 color);

	/**
	Untaints a byte indicated by byteIndex of a register by writing the empty_color.
	*/
	void untaintReg(LEVEL_BASE::REG reg, int byteIndex);

	/**
	Returns a vector of tags corresponding to each byte of the register
	in the register field.
	*/
	std::vector<Tag> getTaintColorReg(LEVEL_BASE::REG reg);

	/**
	Mixes register colors of src1 and src2 into dest.
	dest, src1 and src2 MUST be of the same size.
	src1 and dest are expected to be the same register. Only binary opcs!
	Introduces mix in taglog if generated.
	*/
	void mixTaintReg(LEVEL_BASE::REG dest, LEVEL_BASE::REG src1, LEVEL_BASE::REG src2);


	/**
	Same as mixTaintReg, but if src reg is smaller than dest, then the full dest register
	is tainted using the LSB of the src register	
	*/
	void mixTaintRegWithExtension(LEVEL_BASE::REG dest, LEVEL_BASE::REG src1, LEVEL_BASE::REG src2);

	/**
	DEPRECATED -- Best to leave byte complexity to taintcontroller
	*/
	void mixTaintRegColors(LEVEL_BASE::REG dest, UINT32 length, std::vector<UINT16> colorV1, std::vector<UINT16> colorV2);
	
	/**
	Mixes two colors at register byte indicated by byteIndex. Only one byte.
	dest's color and color1 MUST be the same --> only binary opcs supported!
	Introduces mix in taglog if generated.
	*/
	void mixTaintRegByte(LEVEL_BASE::REG dest, UINT32 byteIndex, UINT16 colorV1, UINT16 colorV2);
	
	/**
	Mixes the color at memory dest=src1 and that of register src2.
	dest = src1
	length = bytes of reg src2
	Introduces mix in taglog if generated
	*/
	void mixTaintMemRegAllBytes(ADDRINT dest, UINT32 length, ADDRINT src1, LEVEL_BASE::REG src2);

	/**
	Returns color of Tag::lastColor, increments Tag::lastColor.
	*/
	UINT16 getNextTagColor();

	/**
	Returns vector with tainted mem and color
	*/
	std::vector<std::pair<ADDRINT, UINT16>> getTaintedMemoryVector();

	/**
	Returns vector with original colors
	*/
	std::vector<std::pair<UINT16, std::pair<std::string, std::string>>> getOriginalColorsVector();

	/**
	Returns vector with color transformations
	*/
	std::vector<Tag> getColorTransVector();

	/*Debug: Dumps whole mem map, expensive*/
	void printMemTaintComplete();
	void printRegTaintComplete();
	void dumpTaintLog();
	void dumpTaintLogPrettified(UINT16 startColor);
	void dumpTagLogOriginalColors();

};


#endif