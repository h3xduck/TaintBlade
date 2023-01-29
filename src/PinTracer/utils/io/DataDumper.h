#ifndef _DATA_DUMPER_H_
#define _DATA_DUMPER_H_

#include "../../config/GlobalConfig.h"
#include "log.h"
#include <iostream>
#include <fstream>  
#include "../inst/InstructionWorker.h"

class DataDumper
{
private:
	std::ofstream memDumpFile;
	std::ofstream orgColorsDumpFile;
	std::ofstream colorTransDumpFile;
	std::ofstream funcDllNamesDumpFile;

	int lastRoutineDumpIndex;
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


	DataDumper();

	void writeOriginalColorDump(std::vector<UINT16> &colorVec);
	void writeColorTransformationDump(char* str);
	void writeRoutineDumpLine(struct func_dll_names_dump_line_t data);
	void writeCurrentTaintedMemoryDump(ADDRINT ip, std::vector<std::pair<ADDRINT, UINT16>>);

	void resetDumpFiles();

};


#endif