#include "DatabaseManager.h"
#include "../../common/Context.h"

extern Context ctx;

std::string quotesql(const std::string& s) {
	return std::string("'") + s + std::string("'");
}

#define EXECUTE_SQL_QUERY(sql)\
{\
	char* errMsg = 0;																				\
	int rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);							\
	if (rc)																							\
	{																								\
		LOG_ERR("DB Error: " << sqlite3_errmsg(this->dbSession) << "while running SQL : " << sql);	\
		sqlite3_close(this->dbSession);																\
		return;																						\
	}																								\
}

#define EXECUTE_SQL_QUERY_IGNORE_ERROR(sql) sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, NULL);																							\


UTILS::DB::DatabaseManager::DatabaseManager() {};

void UTILS::DB::DatabaseManager::createDatabase()
{
	//DLL namestable
	std::string sql = "CREATE TABLE dll_names ("\
		"idx		INTEGER PRIMARY KEY AUTOINCREMENT, "\
		"dll_name	TEXT(150)"\
		"); ";
	EXECUTE_SQL_QUERY(sql);

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
	EXECUTE_SQL_QUERY(sql);

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
	EXECUTE_SQL_QUERY(sql);

	//Color transformation table
	sql = "CREATE TABLE color_transformation("\
		"derivate_color  INTEGER PRIMARY KEY,"\
		"color_mix_1     INTEGER,"\
		"color_mix_2     INTEGER"\
		"); ";
	EXECUTE_SQL_QUERY(sql);

	//Memory colors table
	sql = "CREATE TABLE memory_colors ("\
		"inst_address INTEGER,"\
		"func_index   INTEGER,"\
		"mem_address  INTEGER,"\
		"color        INTEGER NOT NULL"\
		"); ";
	EXECUTE_SQL_QUERY(sql);

	//Original colors table
	sql = "CREATE TABLE original_colors ("\
		"color    INTEGER PRIMARY KEY,"\
		"function,"\
		"dll,"\
		"func_index INTEGER NOT NULL"\
		"); ";
	EXECUTE_SQL_QUERY(sql);

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
	EXECUTE_SQL_QUERY(sql);

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
	EXECUTE_SQL_QUERY(sql);

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
	EXECUTE_SQL_QUERY(sql);

	//Table holding protocol netbuffers
	sql = "CREATE TABLE protocol_buffer ("\
		"buffer_idx		INTEGER PRIMARY KEY NOT NULL,"\
		"mem_start		INTEGER,"\
		"mem_end		INTEGER,"\
		"color_start	INTEGER,"\
		"color_end		INTEGER,"\
		"num_words		INTEGER,"\
		"num_pointers	INTEGER"\
		"); ";
	EXECUTE_SQL_QUERY(sql);

	//Table holding protocol netbuffer bytes (bytes of each netbuffer)
	sql = "CREATE TABLE protocol_buffer_byte ("\
		"buffer_idx		INTEGER,"\
		"byte_offset	INTEGER,"\
		"byte_value		TEXT(10),"\
		"hex_value		TEXT(10),"\
		"color			INTEGER"\
		"); ";
	EXECUTE_SQL_QUERY(sql);

	//Table holding protocol words
	sql = "CREATE TABLE protocol_word ("\
		"buffer_idx		INTEGER,"\
		"word_idx		INTEGER,"\
		"type			INTEGER,"\
		"buffer_start	INTEGER,"\
		"buffer_end		INTEGER"\
		"); ";
	EXECUTE_SQL_QUERY(sql);

	//Table holding one byte inside a protocol word
	sql = "CREATE TABLE protocol_word_byte ("\
		"buffer_idx		INTEGER,"\
		"word_idx		INTEGER,"\
		"byte_offset	INTEGER,"\
		"value			TEXT(10),"\
		"color			INTEGER,"\
		"success		INTEGER"\
		"); ";
	EXECUTE_SQL_QUERY(sql);

	//Table holding a protocol pointer belonging to a buffer
	sql = "CREATE TABLE protocol_pointer ("\
		"buffer_idx		INTEGER,"\
		"pointer_idx	INTEGER,"\
		"pointed_color	INTEGER"\
		"); ";
	EXECUTE_SQL_QUERY(sql);

	//Table holding a byte of a protocol pointer
	sql = "CREATE TABLE protocol_pointer_byte ("\
		"buffer_idx		INTEGER,"\
		"pointer_idx	INTEGER,"\
		"byte_offset	INTEGER,"\
		"value			TEXT(10),"\
		"color			INTEGER"\
		"); ";
	EXECUTE_SQL_QUERY(sql);

	//Table holding taint leads belonging to a byte at a buffer
	sql = "CREATE TABLE protocol_taint_leads ("\
		"buffer_idx			INTEGER,"\
		"buffer_byte_offset	INTEGER,"\
		"class				INTEGER,"\
		"dll_idx			INTEGER,"\
		"func_name			TEXT(150),"\
		"arg_number			INTEGER"\
		"); ";
	EXECUTE_SQL_QUERY(sql);
}

void UTILS::DB::DatabaseManager::emptyDatabase()
{
	std::string sql = "DROP TABLE function_calls";
	EXECUTE_SQL_QUERY_IGNORE_ERROR(sql);

	sql = "DROP TABLE dll_names";
	EXECUTE_SQL_QUERY_IGNORE_ERROR(sql);

	sql = "DROP TABLE taint_events";
	EXECUTE_SQL_QUERY_IGNORE_ERROR(sql);

	sql = "DROP TABLE color_transformation";
	EXECUTE_SQL_QUERY_IGNORE_ERROR(sql);
	
	sql = "DROP TABLE memory_colors";
	EXECUTE_SQL_QUERY_IGNORE_ERROR(sql);
	
	sql = "DROP TABLE original_colors";
	EXECUTE_SQL_QUERY_IGNORE_ERROR(sql);

	sql = "DROP TABLE taint_routines";
	EXECUTE_SQL_QUERY_IGNORE_ERROR(sql);

	sql = "DROP TABLE indirect_taint_routines";
	EXECUTE_SQL_QUERY_IGNORE_ERROR(sql);

	sql = "DROP TABLE trace_functions";
	EXECUTE_SQL_QUERY_IGNORE_ERROR(sql);

	sql = "DROP TABLE protocol_buffer";
	EXECUTE_SQL_QUERY_IGNORE_ERROR(sql);

	sql = "DROP TABLE protocol_buffer_byte";
	EXECUTE_SQL_QUERY_IGNORE_ERROR(sql);

	sql = "DROP TABLE protocol_word";
	EXECUTE_SQL_QUERY_IGNORE_ERROR(sql);

	sql = "DROP TABLE protocol_word_byte";
	EXECUTE_SQL_QUERY_IGNORE_ERROR(sql);

	sql = "DROP TABLE protocol_pointer";
	EXECUTE_SQL_QUERY_IGNORE_ERROR(sql);

	sql = "DROP TABLE protocol_pointer_byte";
	EXECUTE_SQL_QUERY_IGNORE_ERROR(sql);

	sql = "DROP TABLE protocol_taint_leads";
	EXECUTE_SQL_QUERY_IGNORE_ERROR(sql);
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
	EXECUTE_SQL_QUERY(sql);
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
	EXECUTE_SQL_QUERY(sql);
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
	EXECUTE_SQL_QUERY(sql);
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
		EXECUTE_SQL_QUERY(sql);
		dllFromIx = this->getDLLIndex(event.dllFrom);
	}

	int dllToIx = this->getDLLIndex(event.dllTo);
	//LOG_DEBUG("Got IX2: " << dllToIx);
	if (dllToIx == -1)
	{
		std::string sql = "INSERT INTO dll_names(dll_name) VALUES('" + event.dllTo + "')";
		EXECUTE_SQL_QUERY(sql);
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
	
	EXECUTE_SQL_QUERY(sql);
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
		EXECUTE_SQL_QUERY(sql);
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

	EXECUTE_SQL_QUERY(sql);
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
		EXECUTE_SQL_QUERY(sql);
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
	EXECUTE_SQL_QUERY(sql);
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
		EXECUTE_SQL_QUERY(sql);
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
	EXECUTE_SQL_QUERY(sql);
}

void UTILS::DB::DatabaseManager::insertProtocolRecords(REVERSING::PROTOCOL::Protocol& protocol)
{
	//Inserting the protocol takes up a lot of steps, since we need to take all its different fields into different tables of the db
	//First, we extract the buffers in the protocol
	std::vector<REVERSING::PROTOCOL::ProtocolNetworkBuffer>& protNetbufferVec = protocol.getNetworkBufferVector();
	for (int ii = 0; ii < protNetbufferVec.size(); ii++)
	{
		REVERSING::PROTOCOL::ProtocolNetworkBuffer& protNetBuf = protNetbufferVec.at(ii);
		std::vector<UINT16>& colors = protNetBuf.getColorsVector();
		std::vector<UINT8>& values = protNetBuf.getValuesVector();
		std::vector<TagLog::color_taint_lead_t>& taintLeads = protNetBuf.getColorTaintLeadsVector();
		std::vector<REVERSING::PROTOCOL::ProtocolWord>& protWordVec = protNetBuf.getWordVector();
		std::vector<REVERSING::PROTOCOL::ProtocolPointer>& protPointerVec = protNetBuf.pointerVector();

		//We insert the protocol info itself
		std::string sql = "INSERT INTO protocol_buffer(mem_start, mem_end, color_start, color_end, num_words, num_pointers) VALUES(" +
			quotesql(std::to_string(protNetBuf.getStartMemAddress())) + ", " +
			quotesql(std::to_string(protNetBuf.getEndMemAddress())) + ", " +
			quotesql(std::to_string((int)protNetBuf.getStartColor())) + ", " +
			quotesql(std::to_string((int)protNetBuf.getEndColor())) + ", " +
			quotesql(std::to_string(protWordVec.size())) + ", " +
			quotesql(std::to_string(protPointerVec.size())) + ");";
		EXECUTE_SQL_QUERY(sql);

		//Now, we will insert each protocol byte info, together with its taint lead
		for (int jj = 0; jj < colors.size(); jj++)
		{
			UINT16& color = colors.at(jj);
			UINT8& value = values.at(jj);
			TagLog::color_taint_lead_t& lead = taintLeads.at(jj);
			sql = "INSERT INTO protocol_buffer_byte(buffer_idx, byte_offset, byte_value, hex_value, color) VALUES(" +
				quotesql(std::to_string(ii)) + ", " +
				quotesql(std::to_string(jj)) + ", " +
				quotesql(std::to_string((int)value)) + ", " +
				quotesql(InstructionWorker::byteToHexValueString(value)) + ", " +
				quotesql(std::to_string((int)color)) + ");";
			EXECUTE_SQL_QUERY(sql);

			//Only if the taint lead exists for this byte, we will insert it
			if (lead.leadClass == TagLog::TAINT_LEAD_SINK)
			{
				//TODO - add here other types of taint lead when incorporated
				//The DLL must get inserted into the dll's table
				int dllIx = this->getDLLIndex(lead.sinkData.dllName);
				//LOG_DEBUG("Got IX: " << dllFromIx);
				if (dllIx == -1)
				{
					std::string sql = "INSERT INTO dll_names(dll_name) VALUES('" + lead.sinkData.dllName + "')";
					EXECUTE_SQL_QUERY(sql);
					dllIx = this->getDLLIndex(lead.sinkData.dllName);
				}
				sql = "INSERT INTO protocol_taint_leads(buffer_idx, buffer_byte_offset, class, dll_idx, func_name, arg_number) VALUES(" +
					quotesql(std::to_string(ii)) + ", " +
					quotesql(std::to_string(jj)) + ", " +
					quotesql(std::to_string((int)lead.leadClass)) + ", " +
					quotesql(std::to_string(dllIx)) + ", " +
					quotesql(lead.sinkData.funcName) + ", " +
					quotesql(std::to_string(lead.sinkData.argNumber)) + ");";
				EXECUTE_SQL_QUERY(sql);
			}
		}

		//Now we insert each protocol word associated to the protocol
		for (int jj = 0; jj < protWordVec.size(); jj++)
		{
			REVERSING::PROTOCOL::ProtocolWord &protWord = protWordVec.at(jj);
			
			if (protWord.getWordType() == REVERSING::PROTOCOL::ProtocolWord::VARIABLE_LENGTH_FIELD)
			{
				//do not dump it, display in gui not supported yet
				continue;
			}
			sql = "INSERT INTO protocol_word(buffer_idx, word_idx, type, buffer_start, buffer_end) VALUES(" +
				quotesql(std::to_string(ii)) + ", " +
				quotesql(std::to_string(jj)) + ", " +
				quotesql(std::to_string((int)protWord.getWordType())) + ", " +
				quotesql(std::to_string(protWord.getStartIndex())) + ", " +
				quotesql(std::to_string(protWord.getEndIndex())) + ");";
			EXECUTE_SQL_QUERY(sql);

			//For each protocol word, we insert its bytes too
			std::vector<UINT8>& bytesVec = protWord.getAllBytes();
			std::vector<UINT16>& colorVec = protWord.getComparedColors();
			std::vector<int>& compVec = protWord.getSuccessIndexes();
			for (int kk = 0; kk < bytesVec.size(); kk++)
			{
				sql = "INSERT INTO protocol_word_byte(buffer_idx, word_idx, byte_offset, value, color, success) VALUES(" +
					quotesql(std::to_string(ii)) + ", " +
					quotesql(std::to_string(jj)) + ", " +
					quotesql(std::to_string(kk)) + ", " +
					quotesql(std::to_string((int)bytesVec.at(kk))) + ", " +
					quotesql(std::to_string((int)colorVec.at(kk))) + ", " +
					quotesql(std::to_string(compVec.at(kk))) + ");";
				EXECUTE_SQL_QUERY(sql);
			}
		}

		//Now we insert the buffer pointer fields
		for (int jj = 0; jj < protPointerVec.size(); jj++)
		{
			REVERSING::PROTOCOL::ProtocolPointer& protPointer = protPointerVec.at(jj);
			sql = "INSERT INTO protocol_pointer(buffer_idx, pointer_idx, pointed_color) VALUES(" +
				quotesql(std::to_string(ii)) + ", " +
				quotesql(std::to_string(jj)) + ", " +
				quotesql(std::to_string((int)protPointer.pointedColor())) + ");";
			EXECUTE_SQL_QUERY(sql);

			//For each protocol pointer, we insert its bytes
			std::vector<UINT8>& bytesVec = protPointer.pointerValue();
			std::vector<UINT16>& colorVec = protPointer.pointerColors();
			for (int kk = 0; kk < bytesVec.size(); kk++)
			{
				sql = "INSERT INTO protocol_pointer_byte(buffer_idx, pointer_idx, byte_offset, value, color) VALUES(" +
					quotesql(std::to_string(ii)) + ", " +
					quotesql(std::to_string(jj)) + ", " +
					quotesql(std::to_string(kk)) + ", " +
					quotesql(std::to_string((int)bytesVec.at(kk))) + ", " +
					quotesql(std::to_string((int)colorVec.at(kk))) + ");";
				EXECUTE_SQL_QUERY(sql);
			}
		}
	}
}

void UTILS::DB::DatabaseManager::insertColorTransformationRecords(std::vector<Tag> vec)
{
	if (!databaseOpened())
	{
		this->openDatabase();
	}

	for (Tag tag : vec)
	{
		std::string sql = "INSERT INTO color_transformation(derivate_color, color_mix_1, color_mix_2) VALUES("+
			quotesql(std::to_string((int)tag.color)) + ", " +
			quotesql(std::to_string((int)tag.derivate1)) + ", " +
			quotesql(std::to_string((int)tag.derivate2)) + ");";
		EXECUTE_SQL_QUERY(sql);
	}
}