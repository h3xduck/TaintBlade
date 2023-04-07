#ifndef _DATA_DUMPER_H_
#define _DATA_DUMPER_H_

#include "../../config/GlobalConfig.h"
#include "log.h"
#include <iostream>
#include <fstream>  
#include "../inst/InstructionWorker.h"
#include "../../taint/data/Tag.h"
#include "../../common/Context.h"
#include "../../utils/io/format.h"

class DataDumper
{
private:
	std::ofstream memDumpFile;
	std::ofstream orgColorsDumpFile;
	std::ofstream colorTransDumpFile;
	std::ofstream funcDllNamesDumpFile;
	std::ofstream memColorEventDumpFile;
	std::ofstream heuristicsResultsDumpFile;

	int lastRoutineDumpIndex;

	//Hash for last dumped vector of currently tainted memory colors
	//We store the hash to compare it before dumping a new one
	size_t hashLastMemDump;
	size_t lastMemDumpVecSize;

public:
	typedef struct extended_data_dump_line_t
	{
		int funcDllIndex;
		char positionContext; //0 if entry arg, 1 if exit arg, 2 if somewhere else
		ADDRINT memAddrRangeFirst;
		ADDRINT memAddrRangeLast;
	};

	typedef struct org_colors_dump_line_t
	{
		UINT16 color;
	};

	typedef struct func_dll_names_dump_line_t
	{
		std::string dllFrom;
		std::string funcFrom;
		ADDRINT memAddrFrom;
		std::string dllTo;
		std::string funcTo;
		ADDRINT memAddrTo;
		void* arg0;
		void* arg1;
		void* arg2;
		void* arg3;
		void* arg4;
		void* arg5;
	};

	typedef enum memory_color_event
	{
		UNDEFINED,  //Undefined
		UNTAINT,	//Untainted memory location
		TAINT,		//Tainted new memory location (happens naturally at the program, not manual by a rule)
		CHANGE,		//Changed the color of an already tainted memrory location, no mix
		MIX,		//Mixed two colors into a new one, or reutilized a previous mix
		TAINTGEN,	//Explicitely tainted a memory location because of a rule specified at a function
		CHANGEGEN,  //Explicitely changed the taint of a memory location because of a rule specified at a function
	};

	typedef struct memory_color_event_line_t
	{
		memory_color_event eventType = UNDEFINED;
		ADDRINT memAddr = 0;
		UINT16 color = 0;
	};

	DataDumper();

	void writeOriginalColorDump(std::vector<std::pair<UINT16, std::pair<std::string, std::string>>> &colorVec);
	void writeMemoryColorEventDump(memory_color_event_line_t event);
	void writeColorTransformationDump(std::vector<Tag>);
	void writeRoutineDumpLine(struct func_dll_names_dump_line_t data);
	void writeCurrentTaintedMemoryDump(ADDRINT ip, std::vector<std::pair<ADDRINT, UINT16>>);
	void writeRevHeuristicDumpLine(HLComparison log);


	void resetDumpFiles();

};


#endif