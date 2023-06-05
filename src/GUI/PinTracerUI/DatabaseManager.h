#ifndef DATABASEMANAGER_H
#define DATABASEMANAGER_H

#include <QString>
#include <QtSql/QSqlDatabase>
#include <QDebug>

class DatabaseManager
{
public:
    DatabaseManager();

    /**
     * Opens a SQLite database connection given a path to the DB file
     * Returns 0 if database was correctly opened.
     */
    int initializeDatabase(const QString& path);

private:
    QSqlDatabase m_db;

};


//Global DBManager for the full app
extern DatabaseManager globalDBManager;

#endif // DATABASEMANAGER_H
