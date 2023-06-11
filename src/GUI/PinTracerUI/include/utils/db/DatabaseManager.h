#ifndef DATABASEMANAGER_H
#define DATABASEMANAGER_H

#include <QString>
#include <QtSql/QSqlDatabase>
#include <QDebug>
#include <QTreeWidget>
#include <QSqlQuery>
#include <QTableWidgetItem>
#include "widgets/protocol/ProtocolBufferDrawer.h"
#include "widgets/protocol/data/Protocol.h"
#include "widgets/protocol/data/ProtocolBuffer.h"
#include "utils/proto/ProtoUtils.h"
#include "widgets/misc/TreeWidgetItemHeader.h"

class DatabaseManager
{
public:
    DatabaseManager();

    /**
     * Opens a SQLite database connection given a path to the DB file
     * Returns 0 if database was correctly opened.
     */
    int initializeDatabase(const QString& path);

    //Functions for building trees with database data
    void buildTaintRoutinesTree(QTreeWidget *treeWidget);
    void buildTraceFunctionsTree(QTreeWidget *treeWidget);
    void buildTaintEventsTree(QTreeWidget *treeWidget, bool withIndirectRoutines);
    void loadProtocolData(ProtocolBufferDrawer *bufferWidget);
    std::vector<int> getColorParentsListFromColor(int color);

private:
    QSqlDatabase m_db;

};


//Global DBManager for the full app
extern DatabaseManager globalDBManager;

#endif // DATABASEMANAGER_H
