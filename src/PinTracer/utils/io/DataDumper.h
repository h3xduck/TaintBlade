#ifndef _DATA_DUMPER_H_
#define _DATA_DUMPER_H_

#include "../../config/GlobalConfig.h"
#include "log.h"
#include <iostream>
#include <fstream>  

class DataDumper
{
private:
	std::ofstream dumpFile;
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
		ADDRINT arg0;
		ADDRINT arg1;
		ADDRINT arg2;
		ADDRINT arg3;
		ADDRINT arg4;
		ADDRINT arg5;
	};


	DataDumper();

	void writeDataDumpLine(char* str);
	void writeOriginalColorDump(char* str);
	void writeColorTransformationDump(char* str);
	void writeRoutineDumpLine(struct func_dll_names_dump_line_t data);

	void resetDumpFiles();

};


#endif