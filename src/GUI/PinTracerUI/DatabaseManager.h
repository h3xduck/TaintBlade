#ifndef DATABASEMANAGER_H
#define DATABASEMANAGER_H

#include <QString>
#include <QtSql/QSqlDatabase>
#include <QDebug>

class DatabaseManager
{
public:
    DatabaseManager(const QString& path);
private:
    QSqlDatabase m_db;

};

#endif // DATABASEMANAGER_H
