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
#include "../../reversing/protocol/Protocol.h"

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

			/**
			Returns the auto-incremented index of the last inserted element in any table. Returns -1 if not found
			*/
			int getLastInsertedIndex();
			
			/**
			Inserts an indirect taint routine based on the data stored in the global context.
			NOTE: This must be called right after the INSERT, otherwise the index is lost. May not work if we implement multithreading too.
			*/
			void insertIndirectTaintRoutineRecordFromContextData();

			/**
			Returns the index that the next taint routine that will be inserted will have.
			This is usually needed for taint events insertion.
			*/
			int getIndexNextInsertedTaintRoutine();

			void insertDLLName(std::string dllName);
			void insertOriginalColorRecord(UINT16 &color, TagLog::original_color_data_t &data, int routineIndex);
			void insertTaintEventRecord(UTILS::IO::DataDumpLine::memory_color_event_line_t event);
			void insertFunctionCallsRecord(struct UTILS::IO::DataDumpLine::func_dll_names_dump_line_t event, int routineIndex);
			void insertTaintRoutineRecord(struct UTILS::IO::DataDumpLine::taint_routine_dump_line_t &data);
			void insertTraceFunctionRecord(UTILS::TRACE::TracePoint& tp);
			void insertProtocolRecords(REVERSING::PROTOCOL::Protocol& protocol);

			//setters and getters
			bool& databaseOpened() { return this->databaseOpened_; };
			bool& dumpFuncCallsArgs() { return this->dumpFuncCallsArgs_; };
		};
	}
}


#endif // !_DATABASE_MANAGER_H_
