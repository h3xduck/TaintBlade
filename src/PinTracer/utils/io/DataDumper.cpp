#include "DataDumper.h"

DataDumper dataDumper;

DataDumper::DataDumper()
{
	this->dumpFile.open(EXTENDED_DATA_DUMP_FILE);
	this->orgColorsDumpFile.open(ORG_COLORS_DUMP_FILE);
	this->colorTransDumpFile.open(COLOR_TRANS_DUMP_FILE);
	this->funcDllNamesDumpFile.open(FUNC_DLL_NAMES_DUMP_FILE);
}

void DataDumper::writeDataDumpLine(char* str)
{
	dumpFile << str;
}

void DataDumper::writeRoutineDumpLine(struct func_dll_names_dump_line_t data)
{
	this->funcDllNamesDumpFile << this->lastRoutineDumpIndex << DUMP_INTER_SEPARATOR << data.dllFrom.c_str() << DUMP_INTER_SEPARATOR << data.funcFrom.c_str() << DUMP_INTER_SEPARATOR << data.memAddrFrom << DUMP_INTER_SEPARATOR << data.dllTo.c_str() << DUMP_INTER_SEPARATOR << data.funcTo.c_str() << DUMP_INTER_SEPARATOR << data.memAddrTo << DUMP_OUTER_SEPARATOR;
}

void DataDumper::resetDumpFiles()
{
	if (remove(EXTENDED_DATA_DUMP_FILE) != 0)
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