#ifndef _DATABASE_MANAGER_H_
#define _DATABASE_MANAGER_H_

#include "../../utils/db/sqlite3.h"
#include "../../config/GlobalConfig.h"
#include "../io/log.h"
#include <vector>
#include "../../taint/data/TagLog.h"

namespace UTILS
{
	namespace DB
	{
		class DatabaseManager
		{
		private:
			sqlite3* dbSession;
			bool databaseOpened_ = false;

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

			//Data insertion
			void insertOriginalColorLine(UINT16 &color, TagLog::original_color_data_t &data, int routineIndex);

			//setters and getters
			bool& databaseOpened() { return this->databaseOpened_; };
		};
	}
}


#endif // !_DATABASE_MANAGER_H_
