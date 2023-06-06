#include "DatabaseManager.h"
#include "../../common/Context.h"

extern Context ctx;

std::string quotesql(const std::string& s) {
	return std::string("'") + s + std::string("'");
}

UTILS::DB::DatabaseManager::DatabaseManager() {};

void UTILS::DB::DatabaseManager::createDatabase()
{
	//DLL namestable
	std::string sql = "CREATE TABLE dll_names ("\
		"idx		INTEGER PRIMARY KEY AUTOINCREMENT, "\
		"dll_name	TEXT(150)"\
		"); ";
	char* errMsg = 0;
	int rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);
	if (rc)
	{
		LOG_ERR("DB Error: " << sqlite3_errmsg(this->dbSession) << "while running SQL : "<< sql);
		sqlite3_close(this->dbSession);
		return;
	}

	//Function calls table
	sql = "CREATE TABLE function_calls ("\
		"appearance   INTEGER    PRIMARY KEY NOT NULL, "\
		"dll_from_ix  INTEGER, "\
		"func_from    TEXT(150), "\
		"memaddr_from INTEGER    NOT NULL,"\
		"dll_to_ix    INTEGER, "\
		"func_to      TEXT(150), "\
		"memaddr_to   INTEGER    NOT NULL,"\
		"arg0         BLOB,"\
		"arg1         BLOB,"\
		"arg2         BLOB,"\
		"arg3         BLOB,"\
		"arg4         BLOB,"\
		"arg5         BLOB"\
		"); ";
	rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);
	if (rc)
	{
		LOG_ERR("DB Error: " << sqlite3_errmsg(this->dbSession));
		sqlite3_close(this->dbSession);
		return;
	}

	//Taint events table
	sql = "CREATE TABLE taint_events("\
		"type         INTEGER,"\
		"routine_idx  INTEGER,"\
		"indirect_routine_idx  INTEGER,"\
		"inst_address INTEGER,"\
		"mem_address  INTEGER,"\
		"color        INTEGER NOT NULL,"\
		"mem_value    TEXT(16),"\
		"mem_len      INTEGER"\
		"); ";
	rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);
	if (rc)
	{
		LOG_ERR("DB Error: " << sqlite3_errmsg(this->dbSession));
		sqlite3_close(this->dbSession);
		return;
	}

	//Color transformation table
	sql = "CREATE TABLE color_transformation("\
		"derivate_color  INTEGER PRIMARY KEY,"\
		"color_mix_1     INTEGER,"\
		"color_mix_2     INTEGER"\
		"); ";
	rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);
	if (rc)
	{
		LOG_ERR("DB Error: " << sqlite3_errmsg(this->dbSession));
		sqlite3_close(this->dbSession);
		return;
	}

	//Memory colors table
	sql = "CREATE TABLE memory_colors ("\
		"inst_address INTEGER,"\
		"func_index   INTEGER,"\
		"mem_address  INTEGER,"\
		"color        INTEGER NOT NULL"\
		"); ";
	rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);
	if (rc)
	{
		LOG_ERR("DB Error: " << sqlite3_errmsg(this->dbSession));
		sqlite3_close(this->dbSession);
		return;
	}

	//Original colors table
	sql = "CREATE TABLE original_colors ("\
		"color    INTEGER PRIMARY KEY,"\
		"function,"\
		"dll,"\
		"func_index INTEGER NOT NULL"\
		"); ";
	rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);
	if (rc)
	{
		LOG_ERR("DB Error: " << sqlite3_errmsg(this->dbSession));
		sqlite3_close(this->dbSession);
		return;
	}

	//Table holding routines in which there was some taint event
	sql = "CREATE TABLE taint_routines ("\
		"idx		INTEGER PRIMARY KEY NOT NULL,"\
		"function	TEXT(150),"\
		"dll_idx	TEXT(150),"\
		"inst_entry	INTEGER,"\
		"inst_last	INTEGER,"\
		"inst_base_entry	INTEGER,"\
		"inst_base_last		INTEGER,"\
		"events_type		INTEGER"\
		"); ";
	rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);
	if (rc)
	{
		LOG_ERR("DB Error: " << sqlite3_errmsg(this->dbSession));
		sqlite3_close(this->dbSession);
		return;
	}

	//Table holding routines from scoped images which indirectly lead to some taint event (that happens at some other routine)
	sql = "CREATE TABLE indirect_taint_routines ("\
		"idx		INTEGER PRIMARY KEY NOT NULL,"\
		"function	TEXT(150),"\
		"dll_idx	TEXT(150),"\
		"inst_entry	INTEGER,"\
		"inst_base_entry	INTEGER,"\
		"possible_jump		INTEGER,"\
		"possible_base_jump	INTEGER"\
		"); ";
	rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);
	if (rc)
	{
		LOG_ERR("DB Error: " << sqlite3_errmsg(this->dbSession));
		sqlite3_close(this->dbSession);
		return;
	}

	//Table holding functions which the user selected to trace
	sql = "CREATE TABLE trace_functions ("\
		"idx		INTEGER PRIMARY KEY NOT NULL,"\
		"function	TEXT(150),"\
		"dll_idx	TEXT(150),"\
		"num_args	INTEGER,"\
		"argpre0		BLOB,"\
		"argpre1		BLOB,"\
		"argpre2		BLOB,"\
		"argpre3		BLOB,"\
		"argpre4		BLOB,"\
		"argpre5		BLOB,"\
		"argpost0		BLOB,"\
		"argpost1		BLOB,"\
		"argpost2		BLOB,"\
		"argpost3		BLOB,"\
		"argpost4		BLOB,"\
		"argpost5		BLOB"\
		"); ";
	rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);
	if (rc)
	{
		LOG_ERR("DB Error: " << sqlite3_errmsg(this->dbSession));
		sqlite3_close(this->dbSession);
		return;
	}
}

void UTILS::DB::DatabaseManager::emptyDatabase()
{
	std::string sql = "DROP TABLE function_calls";
	char* errMsg = 0;
	sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);

	sql = "DROP TABLE dll_names";
	sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);

	sql = "DROP TABLE taint_events";
	sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);

	sql = "DROP TABLE color_transformation";
	sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);
	
	sql = "DROP TABLE memory_colors";
	sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);
	
	sql = "DROP TABLE original_colors";
	sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);

	sql = "DROP TABLE taint_routines";
	sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);

	sql = "DROP TABLE indirect_taint_routines";
	sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);

	sql = "DROP TABLE trace_functions";
	sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);
}

void UTILS::DB::DatabaseManager::openDatabase()
{
	if (sqlite3_open(getFilenameFullName(DB_LOCATION).c_str(), &this->dbSession) == SQLITE_OK)
	{
		LOG_DEBUG("Opened the system database");
		this->databaseOpened() = true;
	}
	else
	{
		LOG_ERR("Unable to open the system database.")
		this->databaseOpened() = false;
	}
}

void UTILS::DB::DatabaseManager::insertOriginalColorRecord(UINT16& color, TagLog::original_color_data_t& data, int routineIndex)
{
	if (!databaseOpened())
	{
		this->openDatabase();
	}
	std::string sql = "INSERT INTO original_colors(color, function, dll, func_index) VALUES(" +
		quotesql(std::to_string((int)color)) +", "+
		quotesql(data.dllName) +", "+
		quotesql(data.funcName) +", "+
		quotesql(std::to_string(routineIndex)) + ");";
	char* errMsg = 0;
	const int rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);
	if (rc)
	{
		LOG_ERR("DB Error: " << sqlite3_errmsg(this->dbSession)<<" while running SQL: "<< sql);
		sqlite3_close(this->dbSession);
		return;
	}
}

void UTILS::DB::DatabaseManager::insertTaintEventRecord(UTILS::IO::DataDumpLine::memory_color_event_line_t event)
{
	if (!databaseOpened())
	{
		this->openDatabase();
	}

	//We insert the taint event and put the routine index as the next routine that will be tainted, and only if it is a "manual taint". This is because
	//only the functions at taint routines will be responsible of generating a manual taint event (the rest are just moving the taint around). Also, we want to
	//get the next index because the taint event will always be dumped before the taint routine, since that one is only dumped after all of its instructions are
	//executed and it exists.
	//Secondly, we will insert the indirect taint, that is, the last routine from the main executable or a scoped image that we know was executed before this taint event happened
	this->insertIndirectTaintRoutineRecordFromContextData();
	int indirect_routine_idx = getLastInsertedIndex();

	int routine_idx = -1;
	//if (event.eventType == UTILS::IO::DataDumpLine::TAINTGEN || event.eventType == UTILS::IO::DataDumpLine::CHANGEGEN)
	{
		routine_idx = getIndexNextInsertedTaintRoutine();
	}

	LOG_DEBUG("INSERTING TAINT EVENT:: IRI:" << indirect_routine_idx << " RI:" << routine_idx);

	std::string sql = "INSERT INTO taint_events(type, routine_idx, indirect_routine_idx, inst_address, mem_address, color, mem_value, mem_len) VALUES(" +
		quotesql(std::to_string((int)event.eventType)) + ", " +
		quotesql(std::to_string(routine_idx)) + ", " +
		quotesql(std::to_string(indirect_routine_idx)) + ", " +
		quotesql(std::to_string(ctx.getCurrentBaseInstruction())) + ", " +
		quotesql(std::to_string(event.memAddr)) + ", " +
		quotesql(std::to_string((int)event.color)) + ", " +
		quotesql(ctx.getLastMemoryValue()) + ", " +
		quotesql(std::to_string(ctx.getLastMemoryLength())) + ");";
	char* errMsg = 0;
	int rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);
	if (rc)
	{
		LOG_ERR("DB Error: " << sqlite3_errmsg(this->dbSession) << " while running SQL: " << sql);
		sqlite3_close(this->dbSession);
		return;
	}

}

int getLastInsertedIndex_callback(void* veryUsed, int argc, char** argv, char** azcolename)
{
	int* ret = (int*)veryUsed;
	for (int ii = 0; ii < argc; ii++)
	{
		*ret = std::atoi(argv[ii]);
		return 0;
	}
	*ret = -1;
	return 0;
}

int UTILS::DB::DatabaseManager::getLastInsertedIndex()
{
	std::string sql = "SELECT last_insert_rowid()";
	char* errMsg = 0;
	int ret = -1;
	const int rc = sqlite3_exec(this->dbSession, sql.c_str(), getLastInsertedIndex_callback, &ret, &errMsg);
	return ret;
}

int getIndexNextInsertedTaintRoutine_callback(void* veryUsed, int argc, char** argv, char** azcolename)
{
	int* ret = (int*)veryUsed;
	for (int ii = 0; ii < argc; ii++)
	{
		if (argv[ii] != NULL)
		{
			*ret = std::atoi(argv[ii]);
			//We get the next index to be inserted, so +1
			(* ret)++;
			return 0;
		}
	}
	*ret = 1;
	return 0;
}

int UTILS::DB::DatabaseManager::getIndexNextInsertedTaintRoutine()
{
	std::string sql = "SELECT MAX(idx) FROM taint_routines";
	char* errMsg = 0;
	int ret = 1;
	const int rc = sqlite3_exec(this->dbSession, sql.c_str(), getIndexNextInsertedTaintRoutine_callback, &ret, &errMsg);
	return ret;
}

int getDLLIndex_callback(void* veryUsed, int argc, char** argv, char** azcolename)
{
	int* ret = (int*)veryUsed;
	for (int ii = 0; ii < argc; ii++)
	{
		*ret = std::atoi(argv[ii]);
		return 0;
	}
	*ret = 1;
	return 0;
}

int UTILS::DB::DatabaseManager::getDLLIndex(std::string dllName)
{
	std::string sql = "SELECT idx FROM dll_names WHERE dll_name='" + dllName + "'";
	char* errMsg = 0;
	int ret = -1;
	const int rc = sqlite3_exec(this->dbSession, sql.c_str(), getDLLIndex_callback, &ret, &errMsg);
	return ret;
}

void UTILS::DB::DatabaseManager::insertDLLName(std::string dllName)
{
	std::string sql = "INSERT INTO dll_names(dll_name) VALUES('" + dllName + "')";
	char* errMsg = 0;
	const int rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);
}


void UTILS::DB::DatabaseManager::insertFunctionCallsRecord(struct UTILS::IO::DataDumpLine::func_dll_names_dump_line_t event, int routineIndex)
{
	if (!databaseOpened())
	{
		this->openDatabase();
	}

	int dllFromIx = this->getDLLIndex(event.dllFrom);
	//LOG_DEBUG("Got IX: " << dllFromIx);
	if (dllFromIx == -1)
	{
		std::string sql = "INSERT INTO dll_names(dll_name) VALUES('" + event.dllFrom + "')";
		const int rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, NULL);
		dllFromIx = this->getDLLIndex(event.dllFrom);
	}

	int dllToIx = this->getDLLIndex(event.dllTo);
	//LOG_DEBUG("Got IX2: " << dllToIx);
	if (dllToIx == -1)
	{
		std::string sql = "INSERT INTO dll_names(dll_name) VALUES('" + event.dllTo + "')";
		const int rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, NULL);
		dllToIx = this->getDLLIndex(event.dllTo);
	}

	std::string sql;
	if (this->dumpFuncCallsArgs())
	{
		std::replace(event.arg0.begin(), event.arg0.end(), '\'', (char)'\\\'');
		std::replace(event.arg1.begin(), event.arg1.end(), '\'', (char)'\\\'');
		std::replace(event.arg2.begin(), event.arg2.end(), '\'', (char)'\\\'');
		std::replace(event.arg3.begin(), event.arg3.end(), '\'', (char)'\\\'');
		std::replace(event.arg4.begin(), event.arg4.end(), '\'', (char)'\\\'');
		std::replace(event.arg5.begin(), event.arg5.end(), '\'', (char)'\\\'');
		
		sql = "INSERT INTO function_calls(appearance, dll_from_ix, func_from, memaddr_from, dll_to_ix, func_to, memaddr_to, arg0, arg1, arg2, arg3, arg4, arg5) VALUES(" +
			quotesql(std::to_string(routineIndex)) + ", " +
			quotesql(std::to_string(dllFromIx)) + ", " +
			quotesql(event.funcFrom) + ", " +
			quotesql(std::to_string(event.memAddrFrom)) + ", " +
			quotesql(std::to_string(dllToIx)) + ", " +
			quotesql(event.funcTo) + ", " +
			quotesql(std::to_string(event.memAddrTo)) + ", " +
			quotesql(event.arg0) + ", " +
			quotesql(event.arg1) + ", " +
			quotesql(event.arg2) + ", " +
			quotesql(event.arg3) + ", " +
			quotesql(event.arg4) + ", " +
			quotesql(event.arg5) + ");";
	}
	else
	{
		sql = "INSERT INTO function_calls(appearance, dll_from_ix, func_from, memaddr_from, dll_to_ix, func_to, memaddr_to) VALUES(" +
			quotesql(std::to_string(routineIndex)) + ", " +
			quotesql(std::to_string(dllFromIx)) + ", " +
			quotesql(event.funcFrom) + ", " +
			quotesql(std::to_string(event.memAddrFrom)) + ", " +
			quotesql(std::to_string(dllToIx)) + ", " +
			quotesql(event.funcTo) + ", " +
			quotesql(std::to_string(event.memAddrTo)) + ");";
	}
	
	char* errMsg = 0;
	const int rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);
	if (rc)
	{
		LOG_ERR("DB Error: " << sqlite3_errmsg(this->dbSession) << " while running SQL: " << sql);
		sqlite3_close(this->dbSession);
		return;
	}
}

void UTILS::DB::DatabaseManager::insertTaintRoutineRecord(struct UTILS::IO::DataDumpLine::taint_routine_dump_line_t &data)
{
	if (!databaseOpened())
	{
		this->openDatabase();
	}

	int dllIx = this->getDLLIndex(data.dll);
	//LOG_DEBUG("Got IX: " << dllFromIx);
	if (dllIx == -1)
	{
		std::string sql = "INSERT INTO dll_names(dll_name) VALUES('" + data.dll + "')";
		const int rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, NULL);
		dllIx = this->getDLLIndex(data.dll);
	}

	PIN_LockClient();
	std::string sql = "INSERT INTO taint_routines(function, dll_idx, inst_entry, inst_last, inst_base_entry, inst_base_last, events_type) VALUES(" +
		quotesql(data.func) + ", " +
		quotesql(std::to_string(dllIx)) + ", " +
		quotesql(std::to_string(data.instAddrEntry)) + ", " +
		quotesql(std::to_string(data.instAddrLast)) + ", " +
		quotesql(std::to_string(InstructionWorker::getBaseAddress(data.instAddrEntry))) + ", " +
		quotesql(std::to_string(InstructionWorker::getBaseAddress(data.instAddrLast))) + ", " +
		quotesql(std::to_string((int)data.containedEventsType)) + ");";
	PIN_UnlockClient();
	char* errMsg = 0;
	const int rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);
	if (rc)
	{
		LOG_ERR("DB Error: " << sqlite3_errmsg(this->dbSession) << " while running SQL: " << sql);
		sqlite3_close(this->dbSession);
		return;
	}
	LOG_DEBUG("Inserted taint routine: " << data.func);

}

void UTILS::DB::DatabaseManager::insertIndirectTaintRoutineRecordFromContextData()
{
	if (!databaseOpened())
	{
		this->openDatabase();
	}

	int dllIx = this->getDLLIndex(ctx.lastRoutineInfo().dllName);
	//LOG_DEBUG("Got IX: " << dllFromIx);
	if (dllIx == -1)
	{
		std::string sql = "INSERT INTO dll_names(dll_name) VALUES('" + ctx.lastRoutineInfo().dllName + "')";
		const int rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, NULL);
		dllIx = this->getDLLIndex(ctx.lastRoutineInfo().dllName);
	}

	PIN_LockClient();
	std::string sql = "INSERT INTO indirect_taint_routines(function, dll_idx, inst_entry, inst_base_entry, possible_jump, possible_base_jump) VALUES(" +
		quotesql(ctx.lastRoutineInfo().funcName) + ", " +
		quotesql(std::to_string(dllIx)) + ", " +
		quotesql(std::to_string(ctx.lastRoutineInfo().routineStart)) + ", " +
		quotesql(std::to_string(ctx.lastRoutineInfo().routineBaseStart)) + ", " +
		quotesql(std::to_string(ctx.lastRoutineInfo().possibleJumpPoint)) + ", " +
		quotesql(std::to_string(ctx.lastRoutineInfo().possibleBaseJumpPoint)) + ");";
	PIN_UnlockClient();
	char* errMsg = 0;
	const int rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);
	if (rc)
	{
		LOG_ERR("DB Error: " << sqlite3_errmsg(this->dbSession) << " while running SQL: " << sql);
		sqlite3_close(this->dbSession);
		return;
	}
}

void UTILS::DB::DatabaseManager::insertTraceFunctionRecord(UTILS::TRACE::TracePoint& tp)
{
	if (!databaseOpened())
	{
		this->openDatabase();
	}

	int dllIx = this->getDLLIndex(tp.getDllName());
	//LOG_DEBUG("Got IX: " << dllFromIx);
	if (dllIx == -1)
	{
		std::string sql = "INSERT INTO dll_names(dll_name) VALUES('" + tp.getDllName() + "')";
		const int rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, NULL);
		dllIx = this->getDLLIndex(tp.getDllName());
	}

	PIN_LockClient();
	std::string sql;
	switch (tp.getNumArgs())
	{
	case 0:
		sql = "INSERT INTO trace_functions(function, dll_idx, num_args) VALUES(" +
			quotesql(tp.getFuncName()) + ", " +
			quotesql(std::to_string(dllIx)) + ", " +
			quotesql(std::to_string(tp.getNumArgs())) + ");";
		break;
	case 1:
		sql = "INSERT INTO trace_functions(function, dll_idx, num_args, argpre0, argpost0) VALUES(" +
			quotesql(tp.getFuncName()) + ", " +
			quotesql(std::to_string(dllIx)) + ", " +
			quotesql(std::to_string(tp.getNumArgs())) + ", " +
			quotesql(tp.getArgsPre().at(0)) + ", " +
			quotesql(tp.getArgsPost().at(0)) + ");";
		break;
	case 2:
		sql = "INSERT INTO trace_functions(function, dll_idx, num_args, argpre0, argpre1, argpost0, argpost1) VALUES(" +
			quotesql(tp.getFuncName()) + ", " +
			quotesql(std::to_string(dllIx)) + ", " +
			quotesql(std::to_string(tp.getNumArgs())) + ", " +
			quotesql(tp.getArgsPre().at(0)) + ", " +
			quotesql(tp.getArgsPre().at(1)) + ", " +
			quotesql(tp.getArgsPost().at(0)) + ", " +
			quotesql(tp.getArgsPost().at(1)) + ");";
		break;
	case 3:
		sql = "INSERT INTO trace_functions(function, dll_idx, num_args, argpre0, argpre1, argpre2, argpost0, argpost1, argpost2) VALUES(" +
			quotesql(tp.getFuncName()) + ", " +
			quotesql(std::to_string(dllIx)) + ", " +
			quotesql(std::to_string(tp.getNumArgs())) + ", " +
			quotesql(tp.getArgsPre().at(0)) + ", " +
			quotesql(tp.getArgsPre().at(1)) + ", " +
			quotesql(tp.getArgsPre().at(2)) + ", " +
			quotesql(tp.getArgsPost().at(0)) + ", " +
			quotesql(tp.getArgsPost().at(1)) + ", " +
			quotesql(tp.getArgsPost().at(2)) + ");";
		break;
	case 4:
		sql = "INSERT INTO trace_functions(function, dll_idx, num_args, argpre0, argpre1, argpre2, argpre3, argpost0, argpost1, argpost2, argpost3) VALUES(" +
			quotesql(tp.getFuncName()) + ", " +
			quotesql(std::to_string(dllIx)) + ", " +
			quotesql(std::to_string(tp.getNumArgs())) + ", " +
			quotesql(tp.getArgsPre().at(0)) + ", " +
			quotesql(tp.getArgsPre().at(1)) + ", " +
			quotesql(tp.getArgsPre().at(2)) + ", " +
			quotesql(tp.getArgsPre().at(3)) + ", " +
			quotesql(tp.getArgsPost().at(0)) + ", " +
			quotesql(tp.getArgsPost().at(1)) + ", " +
			quotesql(tp.getArgsPost().at(2)) + ", " +
			quotesql(tp.getArgsPost().at(3)) + ");";
		break;
	case 5:
		sql = "INSERT INTO trace_functions(function, dll_idx, num_args, argpre0, argpre1, argpre2, argpre3, argpre4, argpost0, argpost1, argpost2, argpost3, argpost4) VALUES(" +
			quotesql(tp.getFuncName()) + ", " +
			quotesql(std::to_string(dllIx)) + ", " +
			quotesql(std::to_string(tp.getNumArgs())) + ", " +
			quotesql(tp.getArgsPre().at(0)) + ", " +
			quotesql(tp.getArgsPre().at(1)) + ", " +
			quotesql(tp.getArgsPre().at(2)) + ", " +
			quotesql(tp.getArgsPre().at(3)) + ", " +
			quotesql(tp.getArgsPre().at(4)) + ", " +
			quotesql(tp.getArgsPost().at(0)) + ", " +
			quotesql(tp.getArgsPost().at(1)) + ", " +
			quotesql(tp.getArgsPost().at(2)) + ", " +
			quotesql(tp.getArgsPost().at(3)) + ", " +
			quotesql(tp.getArgsPost().at(4)) + ");";
		break;
	case 6:
	default:
		sql = "INSERT INTO trace_functions(function, dll_idx, num_args, argpre0, argpre1, argpre2, argpre3, argpre4, argpre5, argpost0, argpost1, argpost2, argpost3, argpost4, argpost5) VALUES(" +
			quotesql(tp.getFuncName()) + ", " +
			quotesql(std::to_string(dllIx)) + ", " +
			quotesql(std::to_string(tp.getNumArgs())) + ", " +
			quotesql(tp.getArgsPre().at(0)) + ", " +
			quotesql(tp.getArgsPre().at(1)) + ", " +
			quotesql(tp.getArgsPre().at(2)) + ", " +
			quotesql(tp.getArgsPre().at(3)) + ", " +
			quotesql(tp.getArgsPre().at(4)) + ", " +
			quotesql(tp.getArgsPre().at(5)) + ", " +
			quotesql(tp.getArgsPost().at(0)) + ", " +
			quotesql(tp.getArgsPost().at(1)) + ", " +
			quotesql(tp.getArgsPost().at(2)) + ", " +
			quotesql(tp.getArgsPost().at(3)) + ", " +
			quotesql(tp.getArgsPost().at(4)) + ", " +
			quotesql(tp.getArgsPost().at(5)) + ");";
	}
	
	PIN_UnlockClient();
	char* errMsg = 0;
	const int rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);
	if (rc)
	{
		LOG_ERR("DB Error: " << sqlite3_errmsg(this->dbSession) << " while running SQL: " << sql);
		sqlite3_close(this->dbSession);
		return;
	}
}