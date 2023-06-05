#ifndef _DATABASE_MANAGER_H_
#define _DATABASE_MANAGER_H_

#include "../../utils/db/sqlite3.h"
#include "../../config/GlobalConfig.h"
#include "../io/log.h"
#include <vector>
#include "../../taint/data/TagLog.h"
#include "../io/DataDumpLine.h"
#include <cstdio>
#include "../trace/TracePoint.h"

namespace UTILS
{
	namespace DB
	{
		class DatabaseManager
		{
		private:
			sqlite3* dbSession;
			bool databaseOpened_ = false;
			bool dumpFuncCallsArgs_ = false;

		public:
			DatabaseManager();

			/**
			Opens a session in the internal sqlite database
			*/
			void openDatabase();

			/**
			Creates all tables of the database, once opened
			*/
			void createDatabase();

			/**
			Drops all tables in the database, emptying it
			*/
			void emptyDatabase();

			//SQL 
			/**
			Returns the index in the DLLnames table of the DLL name. Returns -1 if not found
			*/
			int getDLLIndex(std::string dllName);
			void insertDLLName(std::string dllName);
			void insertOriginalColorRecord(UINT16 &color, TagLog::original_color_data_t &data, int routineIndex);
			void insertTaintEventRecord(UTILS::IO::DataDumpLine::memory_color_event_line_t event, int routineIndex);
			void insertFunctionCallsRecord(struct UTILS::IO::DataDumpLine::func_dll_names_dump_line_t event, int routineIndex);
			void insertTaintRoutineRecord(struct UTILS::IO::DataDumpLine::taint_routine_dump_line_t &data);
			void insertTraceFunctionRecord(UTILS::TRACE::TracePoint& tp);

			//setters and getters
			bool& databaseOpened() { return this->databaseOpened_; };
			bool& dumpFuncCallsArgs() { return this->dumpFuncCallsArgs_; };
		};
	}
}


#endif // !_DATABASE_MANAGER_H_
