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
		"func_index   INTEGER,"\
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
}

void UTILS::DB::DatabaseManager::openDatabase()
{
	if (sqlite3_open(DB_LOCATION, &this->dbSession) == SQLITE_OK)
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

void UTILS::DB::DatabaseManager::insertTaintEventRecord(UTILS::IO::DataDumpLine::memory_color_event_line_t event, int routineIndex)
{
	if (!databaseOpened())
	{
		this->openDatabase();
	}
	std::string sql = "INSERT INTO taint_events(type, func_index, inst_address, mem_address, color, mem_value, mem_len) VALUES(" +
		quotesql(std::to_string((int)event.eventType)) + ", " +
		quotesql(std::to_string(routineIndex)) + ", " +
		quotesql(std::to_string(ctx.getCurrentBaseInstruction())) + ", " +
		quotesql(std::to_string(event.memAddr)) + ", " +
		quotesql(std::to_string((int)event.color)) + ", " +
		quotesql(ctx.getLastMemoryValue()) + ", " +
		quotesql(std::to_string(ctx.getLastMemoryLength())) + ");";
	char* errMsg = 0;
	const int rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);
	if (rc)
	{
		LOG_ERR("DB Error: " << sqlite3_errmsg(this->dbSession) << " while running SQL: " << sql);
		sqlite3_close(this->dbSession);
		return;
	}
}

int getDLLIndex_callback(void* veryUsed, int argc, char** argv, char** azcolename)
{
	int* ret = (int*)veryUsed;
	LOG_DEBUG("Here");
	for (int ii = 0; ii < argc; ii++)
	{
		*ret = (int)*argv[ii];
		return 0;
	}
	*ret = -1;
	return 0;
}

int UTILS::DB::DatabaseManager::getDLLIndex(std::string dllName)
{
	std::string sql = "SELECT idx FROM dll_names WHERE dll_name='" + dllName + "'";
	char* errMsg = 0;
	int* ret;
	*ret = -1;
	const int rc = sqlite3_exec(this->dbSession, sql.c_str(), getDLLIndex_callback, ret, &errMsg);
	LOG_DEBUG("returning " << *ret);
	return *ret;
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
	std::replace(event.arg0.begin(), event.arg0.end(), '\'', (char)'\\\'');
	std::replace(event.arg1.begin(), event.arg1.end(), '\'', (char)'\\\'');
	std::replace(event.arg2.begin(), event.arg2.end(), '\'', (char)'\\\'');
	std::replace(event.arg3.begin(), event.arg3.end(), '\'', (char)'\\\'');
	std::replace(event.arg4.begin(), event.arg4.end(), '\'', (char)'\\\'');
	std::replace(event.arg5.begin(), event.arg5.end(), '\'', (char)'\\\'');

	int dllFromIx = this->getDLLIndex(event.dllFrom);
	LOG_DEBUG("Got IX: " << dllFromIx);
	if (dllFromIx == -1)
	{
		std::string sql = "INSERT INTO dll_names(dll_name) VALUES('" + event.dllFrom + "')";
		const int rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, NULL);
		dllFromIx = this->getDLLIndex(event.dllFrom);
	}

	int dllToIx = this->getDLLIndex(event.dllTo);
	LOG_DEBUG("Got IX2: " << dllToIx);
	if (dllToIx == -1)
	{
		std::string sql = "INSERT INTO dll_names(dll_name) VALUES('" + event.dllTo + "')";
		const int rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, NULL);
		dllToIx = this->getDLLIndex(event.dllTo);
	}

	std::string sql;
	if (this->dumpFuncCallsArgs())
	{
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