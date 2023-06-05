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

void DatabaseManager::buildTraceFunctionsTree(QTreeWidget *treeWidget)
{
    qDebug()<<"Building trace functions tree";
    treeWidget->clear();
    treeWidget->setColumnCount(4);
    QStringList headers = { "Function name", "Dll", "Traced args", ""};
    treeWidget->setHeaderLabels(headers);
    QSqlQuery query;
    query.exec("SELECT * from trace_functions as t JOIN dll_names as d ON (t.dll_idx = d.idx);");

    while(query.next())
    {
        qDebug("Received item");
        QTreeWidgetItem *item = new QTreeWidgetItem();
        item->setText(0, query.value("function").toString());
        item->setText(1, query.value("dll_name").toString());
        item->setText(2, query.value("num_args").toString());

        //We always add a first child that displays the children headers (a bit hacky, but easiest way)
        QTreeWidgetItem *childHeader = new QTreeWidgetItem();
        childHeader->setText(0, "Arg");
        childHeader->setText(1, "Address");
        childHeader->setText(2, "Length");
        childHeader->setText(3, "String value");
        item->addChild(childHeader);
        int numArgs = query.value("num_args").toInt();
        for(int ii=0; ii<numArgs; ii++)
        {
            QTreeWidgetItem *child = new QTreeWidgetItem();
            //Each argument may or may not have a string value. We will partition it if found
            QString argNamePre = QStringLiteral("argpre%1").arg(ii);
            QStringList argElemList = query.value(argNamePre).toString().split(" --> Len:");
            if(argElemList.count() == 1)
            {
                //Means no string value found
                child->setText(0, QStringLiteral("arg%1 (Pre-call)").arg(ii));
                child->setText(1, query.value(argNamePre).toString());
            }
            else
            {
                //Found string value
                child->setText(0, QStringLiteral("arg%1 (Pre-call)").arg(ii));
                child->setText(1, argElemList.at(0));
                QStringList argElemValueList = argElemList.at(1).split(" | Value: ");
                child->setText(2, argElemValueList.at(0));
                child->setText(3, argElemValueList.at(1));
            }
            item->addChild(child);

            //Now we do the same with the post arguments, at a different child
            QString argNamePost = QStringLiteral("argpost%1").arg(ii);
            QTreeWidgetItem *postChild = new QTreeWidgetItem();
            QStringList argElemListPost = query.value(argNamePost).toString().split(" --> Len:");
            if(argElemListPost.count() == 1)
            {
                //Means no string value found
                postChild->setText(0, QStringLiteral("arg%1 (At return)").arg(ii));
                postChild->setText(1, query.value(argNamePost).toString());
            }
            else
            {
                //Found string value
                postChild->setText(0, QStringLiteral("arg%1 (At return)").arg(ii));
                postChild->setText(1, argElemListPost.at(0));
                QStringList argElemValueListPost = argElemListPost.at(1).split(" | Value: ");
                postChild->setText(2, argElemValueListPost.at(0));
                postChild->setText(3, argElemValueListPost.at(1));
            }
            item->addChild(postChild);
        }


        treeWidget->addTopLevelItem(item);
    }
}

void DatabaseManager::buildTaintEventsTree(QTreeWidget *treeWidget)
{
    qDebug()<<"Building taint events tree";
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
