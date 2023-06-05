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

void DatabaseManager::buildTaintRoutinesTree(QTreeWidget *treeWidget)
{
    qDebug()<<"Building taint routines tree";
    treeWidget->clear();
    treeWidget->setColumnCount(5);
    QStringList headers = { "Function name", "Dll", "Base entry address", "Base exit address", "Event type"};
    treeWidget->setHeaderLabels(headers);
    QSqlQuery query;
    query.exec("SELECT * from taint_routines as t JOIN dll_names as d ON (t.dll_idx = d.idx);");

    while(query.next())
    {
        qDebug("Received item");
        QTreeWidgetItem *item = new QTreeWidgetItem();
        item->setText(0, query.value("function").toString());
        item->setText(1, query.value("dll_name").toString());
        item->setText(2, query.value("inst_base_entry").toString());
        item->setText(3, query.value("inst_base_last").toString());
        item->setText(4, query.value("events_type").toString());
        treeWidget->addTopLevelItem(item);
    }
}

