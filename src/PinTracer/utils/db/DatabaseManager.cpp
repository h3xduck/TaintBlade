#include "DatabaseManager.h"
#include "../../common/Context.h"

extern Context ctx;

std::string quotesql(const std::string& s) {
	return std::string("'") + s + std::string("'");
}

UTILS::DB::DatabaseManager::DatabaseManager() {};

void UTILS::DB::DatabaseManager::createDatabase()
{
	//Function calls table
	std::string sql = "CREATE TABLE function_calls ("\
		"appearance   INTEGER    PRIMARY KEY NOT NULL, "\
		"dll_from     TEXT(150), "\
		"func_from    TEXT(150), "\
		"memaddr_from INTEGER    NOT NULL,"\
		"dll_to,"\
		"func_to,"\
		"memaddr_to              NOT NULL,"\
		"arg0         INTEGER,"\
		"arg1         INTEGER,"\
		"arg2         INTEGER,"\
		"arg3         INTEGER,"\
		"arg4         INTEGER,"\
		"arg5         INTEGER"\
		"); ";
	char* errMsg = 0;
	int rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);
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

/*int callback(void* notUsed, int argc, char** argv, char** azcolename)
{
	for (int ii = 0; ii < argc; ii++)
	{
		LOG_DEBUG("LINE:: "<<azcolename[ii] << ": " << argv[ii]);
	}
	return 0;
}*/

void UTILS::DB::DatabaseManager::insertOriginalColorLine(UINT16& color, TagLog::original_color_data_t& data, int routineIndex)
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
	LOG_DEBUG("running sql: " << sql);
	char* errMsg = 0;
	const int rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);
	if (rc)
	{
		LOG_ERR("DB Error: " << sqlite3_errmsg(this->dbSession));
		sqlite3_close(this->dbSession);
		return;
	}
}

void UTILS::DB::DatabaseManager::insertTaintEventLine(UTILS::IO::DataDumpLine::memory_color_event_line_t event, int routineIndex)
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
	LOG_DEBUG("running sql: " << sql);
	char* errMsg = 0;
	const int rc = sqlite3_exec(this->dbSession, sql.c_str(), NULL, 0, &errMsg);
	if (rc)
	{
		LOG_ERR("DB Error: " << sqlite3_errmsg(this->dbSession));
		sqlite3_close(this->dbSession);
		return;
	}
}