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


#define PAGE_SIZE 4096
#define COLOR_BYTES 2

/*
	Two main structures for storing the taint during its propagation. Granularity = bytes.
	
	memTaintField --> Taint on memory bytes.
	Implemented as hash maps for fastest insert and lookup time even with lots of entries.
	Each byte is tainted using an array of COLOR_BYTES bytes.

	regTaintField --> Taint on CPU registers.
	Implemented as a large contiguous set of memory bytes. Tainted registers:
	- General purpose registers: rax to r15, including rsp and rbp. All bytes tainted.
	- Taint EFLAGS? //TODO: Decide later. Needed for CMP.
	Each byte is tainted using an array of COLOR_BYTES bytes. These bytes are put sequentially.
	e.g.:
	rax: 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 <-- 8 bytes in rax, 2 COLOR_BYTES
	rbx: 0000 0000 ...
	...
	r15: 0000 0000 ...
*/

namespace TAGMAP
{


	typedef struct MemTaintInfo
	{
		//2 COLOR_BYTES
		UINT16 bytes;
	};

	extern std::tr1::unordered_map<ADDRINT, MemTaintInfo> memTaintField;

	// 2 COLOR_BYTES * 8 bytes per register * 16 registers
	//char regTaintField[256] = { 0 };

	int tagmapInit();

}


#endif