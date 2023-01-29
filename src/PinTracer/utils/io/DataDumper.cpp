#include "DataDumper.h"

DataDumper dataDumper;

DataDumper::DataDumper()
{
	this->memDumpFile.open(CURRENT_TAINTED_MEMORY_DUMP_FILE);
	this->orgColorsDumpFile.open(ORG_COLORS_DUMP_FILE);
	this->colorTransDumpFile.open(COLOR_TRANS_DUMP_FILE);
	this->funcDllNamesDumpFile.open(FUNC_DLL_NAMES_DUMP_FILE);
}

void DataDumper::writeRoutineDumpLine(struct func_dll_names_dump_line_t data)
{
	this->funcDllNamesDumpFile << this->lastRoutineDumpIndex << DUMP_INTER_SEPARATOR << 
		data.dllFrom.c_str() << DUMP_INTER_SEPARATOR << data.funcFrom.c_str() << 
		DUMP_INTER_SEPARATOR << data.memAddrFrom << DUMP_INTER_SEPARATOR << 
		data.dllTo.c_str() << DUMP_INTER_SEPARATOR << data.funcTo.c_str() <<
		DUMP_INTER_SEPARATOR << data.memAddrTo << DUMP_INTER_SEPARATOR <<
		(ADDRINT)data.arg0 << DUMP_INTER_SEPARATOR <<
		(ADDRINT)data.arg1 << DUMP_INTER_SEPARATOR <<
		(ADDRINT)data.arg2 << DUMP_INTER_SEPARATOR <<
		(ADDRINT)data.arg3 << DUMP_INTER_SEPARATOR <<
		(ADDRINT)data.arg4 << DUMP_INTER_SEPARATOR <<
		(ADDRINT)data.arg5 << DUMP_OUTER_SEPARATOR;
	this->lastRoutineDumpIndex++;
}

void DataDumper::writeCurrentTaintedMemoryDump(ADDRINT ip, std::vector<std::pair<ADDRINT, UINT16>> vec)
{
	this->memDumpFile << ip << DUMP_INTER_SEPARATOR;
	for (auto it : vec)
	{
		this->memDumpFile << it.first << DUMP_INTER_SEPARATOR << it.second;
	}
	this->memDumpFile << DUMP_OUTER_SEPARATOR;
}

void DataDumper::resetDumpFiles()
{
	if (remove(CURRENT_TAINTED_MEMORY_DUMP_FILE) != 0)
	{
		LOG_ERR("Error deleting data dump file");
	}
	else
	{
		LOG_DEBUG("Data dump file successfully deleted");
	}

	if (remove(ORG_COLORS_DUMP_FILE) != 0)
	{
		LOG_ERR("Error deleting original colors dump file");
	}
	else
	{
		LOG_DEBUG("Original colors dump file successfully deleted");
	}

	if (remove(COLOR_TRANS_DUMP_FILE) != 0)
	{
		LOG_ERR("Error deleting colors transformation dump file");
	}
	else
	{
		LOG_DEBUG("Colors transformation dump file successfully deleted");
	}
}