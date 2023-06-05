#ifndef DATABASEMANAGER_H
#define DATABASEMANAGER_H

#include <QString>
#include <QtSql/QSqlDatabase>
#include <QDebug>
#include <QTreeWidget>
#include <QSqlQuery>
#include <QTableWidgetItem>

class DatabaseManager
{
public:
    DatabaseManager();

    /**
     * Opens a SQLite database connection given a path to the DB file
     * Returns 0 if database was correctly opened.
     */
    int initializeDatabase(const QString& path);

    /**
     * Puts all data related to taint routines into the tree widget passed
     */
    void buildTaintRoutinesTree(QTreeWidget *treeWidget);

private:
    QSqlDatabase m_db;

};


//Global DBManager for the full app
extern DatabaseManager globalDBManager;

#endif // DATABASEMANAGER_H
