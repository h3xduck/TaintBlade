#include "DatabaseManager.h"

DatabaseManager globalDBManager;

DatabaseManager::DatabaseManager(){}

int DatabaseManager::initializeDatabase(const QString& path)
{
    m_db = QSqlDatabase::addDatabase("QSQLITE");
    m_db.setDatabaseName(path);

    if (!m_db.open())
    {
        qDebug() << "Error: connection with database failed";
        return -1;
    }
    else
    {
        qDebug() << "Database: connection ok";
        return 0;
    }
}

