#ifndef _DATA_DUMPER_H_
#define _DATA_DUMPER_H_

#include "../../config/GlobalConfig.h"
#include "log.h"
#include <iostream>
#include <fstream>  
#include "../inst/InstructionWorker.h"
#include "../../taint/data/Tag.h"
#include "../../taint/data/TagLog.h"
#include "../../utils/io/format.h"
#include "../../reversing/protocol/Protocol.h"
#include "../trace/TracePoint.h"
#include "../db/DatabaseManager.h"
#include "../../reversing/heuristics/HLPointerField.h"
#include "DataDumpLine.h"
#include "../inst/PerformanceOperator.h"

class DataDumper
{
private:
	std::ofstream memDumpFile;
	std::ofstream orgColorsDumpFile;
	std::ofstream colorTransDumpFile;
	std::ofstream funcDllNamesDumpFile;
	std::ofstream memColorEventDumpFile;
	std::ofstream heuristicsResultsDumpFile;
	std::ofstream protocolResultsDumpFile;
	std::ofstream traceResultsDumpFile;
	std::ofstream taintRoutinesDumpFile;

	int lastRoutineDumpIndex;

	//Hash for last dumped vector of currently tainted memory colors
	//We store the hash to compare it before dumping a new one
	size_t hashLastMemDump;
	size_t lastMemDumpVecSize;

public:
	DataDumper();

	void writeTracedProcessDump(std::string mainImageName);
	void writeOriginalColorDump(std::vector<std::pair<UINT16, TagLog::original_color_data_t>> &colorVec);
	void writeMemoryColorEventDump(UTILS::IO::DataDumpLine::memory_color_event_line_t event);
	void writeColorTransformationDump(std::vector<Tag>);
	void writeRoutineDumpLine(struct UTILS::IO::DataDumpLine::func_dll_names_dump_line_t data);
	void writeCurrentTaintedMemoryDump(ADDRINT ip, std::vector<std::pair<ADDRINT, UINT16>>);
	void writeRevHeuristicDumpLine(HLComparison log);
	void writeRevHeuristicDumpLine(HLPointerField log);
	void writeProtocolDump(REVERSING::PROTOCOL::Protocol protocol);
	void writeTraceDumpLine(UTILS::TRACE::TracePoint& tp);
	void writeTaintRoutineDumpLine(UTILS::IO::DataDumpLine::taint_routine_dump_line_t &data);

	void resetDumpFiles();

};


#endif