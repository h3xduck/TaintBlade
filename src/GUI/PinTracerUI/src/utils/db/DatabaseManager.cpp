#include "utils/db/DatabaseManager.h"

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
    //Get all taint routines that were selected by the user, but not those where just some taint operation happened (type 3), only sources, sinks...
    query.exec("SELECT * from taint_routines as t JOIN dll_names as d ON (t.dll_idx = d.idx) WHERE events_type IS NOT 3;");

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
    treeWidget->setColumnCount(3);
    QStringList headers = { "Binary image", "", ""};
    treeWidget->setHeaderLabels(headers);
    QSqlQuery query;
    query.exec("SELECT te.type AS event_type, te.inst_address AS event_address, te.mem_address, te.color, te.mem_value, te.mem_len, "\
                "tr.function AS direct_function, d.dll_name AS direct_dll, "\
                "itr.function AS indirect_function, d2.dll_name AS indirect_dll, itr.inst_base_entry AS indirect_base_entry, itr.possible_base_jump AS indirect_jump "\
                "FROM taint_events AS te "
                "LEFT JOIN taint_routines as tr ON (te.routine_idx = tr.idx) "\
                "LEFT JOIN dll_names AS d ON (tr.dll_idx = d.idx) "\
                "JOIN indirect_taint_routines AS itr ON (te.indirect_routine_idx = itr.idx) "\
                "JOIN dll_names AS d2 ON (itr.dll_idx = d2.idx);");

    while(query.next())
    {
        //The first level will only show the dll of the scoped image
        qDebug()<<"Received item";
        //If is exactly the same as the one already displayed, refrain from showing it
        //If it was shown before but it is not exactly directly the same, no problems, we want to show cronological order
        QTreeWidgetItem *item;
        QTreeWidgetItem *lastTopLevel = treeWidget->topLevelItem(treeWidget->topLevelItemCount()-1);
        int lastTopLevelFirstLevelChildCount = 0;
        bool reusedDLL = false;
        if(lastTopLevel!=nullptr && query.value("indirect_dll").toString() == lastTopLevel->text(0))
        {
            //Reuse the same DLL as before
            item = lastTopLevel;
            reusedDLL = true;
            lastTopLevelFirstLevelChildCount = lastTopLevel->childCount();
            //qDebug()<<"Reused top level item";
        }
        else
        {
            //Show new DLL
            item = new QTreeWidgetItem();
            item->setText(0, query.value("indirect_dll").toString());
            //qDebug()<<"New top level item of DLL: "<<item->text(0);
        }


        //Second level will show the functions (routines)
        //If it is exactly the same as before, we reuse the function
        bool reusedRoutine = false;
        int lastTopLevelLastFirstLevelSecondLevelChildCount = 0;
        QTreeWidgetItem *child;
        if(reusedDLL && lastTopLevelFirstLevelChildCount > 0 &&
            lastTopLevel->child(lastTopLevelFirstLevelChildCount-1)->text(2) == query.value("indirect_jump").toString())
        {
            //Reuse last first-level child
            child = lastTopLevel->child(lastTopLevelFirstLevelChildCount-1);
            reusedRoutine = true;
            lastTopLevelLastFirstLevelSecondLevelChildCount = child->childCount();
            //qDebug()<<"Reused first child";
        }
        else
        {
            //Not the same, new function + addresses
            //If this is the first item, insert child showing headers for second level
            if(lastTopLevelFirstLevelChildCount==0)
            {
                QTreeWidgetItem *childHeader = new QTreeWidgetItem();
                childHeader->setText(0, "Routine");
                childHeader->setText(1, "Base start");
                childHeader->setText(2, "Jump address to taint routine");
                item->addChild(childHeader);
            }
            //Now add the actual data
            child = new QTreeWidgetItem();
            QString routineStr = query.value("indirect_function").toString();
            if (routineStr == "unnamedImageEntryPoint" || routineStr == ".text")
            {
                routineStr = "No Symbol";
            }
            child->setText(0, routineStr);
            child->setText(1, query.value("indirect_base_entry").toString());
            child->setText(2, query.value("indirect_jump").toString());
            //qDebug()<<"New first child with function: "<<child->text(0);
        }


        //Third level, show actual dll+function that contain the instructions resposible of the taint event
        //In here we do not care if values are repeated - if a taint event is repeated it is still relevant
        if(lastTopLevelLastFirstLevelSecondLevelChildCount==0)
        {
            //Means we are the first, introduce the children header
            QTreeWidgetItem *secondChildHeader;
            secondChildHeader = new QTreeWidgetItem();
            secondChildHeader->setText(0, "Binary image");
            secondChildHeader->setText(1, "Function");
            secondChildHeader->setText(2, "Base taint instruction");
            child->addChild(secondChildHeader);
        }
        QTreeWidgetItem *secondChild = new QTreeWidgetItem();
        secondChild->setText(0, query.value("direct_dll").toString());
        QString routineStr = query.value("direct_function").toString();
        if (routineStr == "unnamedImageEntryPoint" || routineStr == ".text")
        {
            routineStr = "No Symbol";
        }
        secondChild->setText(0, query.value("direct_dll").toString());
        secondChild->setText(1, routineStr);
        secondChild->setText(2, query.value("event_address").toString());
        //qDebug()<<"New second child with dll: "<<secondChild->text(0);

        //Fourth level, information about the taint event itself
        QTreeWidgetItem *thirdChildHeader = new QTreeWidgetItem();
        thirdChildHeader->setText(0, "Event type");
        thirdChildHeader->setText(1, "Color");
        secondChild->addChild(thirdChildHeader);
        QTreeWidgetItem *thirdChild = new QTreeWidgetItem();
        int eventType = query.value("event_type").toInt();
        QString eventTypeStr;
        switch(eventType)
        {
            case 1: eventTypeStr = "UNTAINT"; break;
            case 2: eventTypeStr = "TAINT"; break;
            case 3: eventTypeStr = "MOVED TAINT"; break;
            case 4: eventTypeStr = "MIXED COLORS"; break;
            case 5: eventTypeStr = "RULE TAINT"; break;
            case 6: eventTypeStr = "RULE MOVE TAINT"; break;
            case 0:
            default: eventTypeStr = "ERROR"; break;
        }
        thirdChild->setText(0, eventTypeStr);
        thirdChild->setText(1, query.value("color").toString());

        //Fifth level, detailed info about memory at the taint event
        QTreeWidgetItem *fourthChildHeader = new QTreeWidgetItem();
        fourthChildHeader->setText(0, "Memory value");
        fourthChildHeader->setText(1, "Length");
        fourthChildHeader->setText(2, "Address");
        thirdChild->addChild(fourthChildHeader);
        QTreeWidgetItem *fourthChild = new QTreeWidgetItem();
        fourthChild->setText(0, query.value("mem_value").toString());
        fourthChild->setText(1, query.value("mem_len").toString());
        fourthChild->setText(2, query.value("mem_address").toString());


        //Add all elements one inside the other
        thirdChild->addChild(fourthChild);
        secondChild->addChild(thirdChild);
        child->addChild(secondChild);
        if(!reusedRoutine)
        {
            item->addChild(child);
        }

        if(!reusedDLL)
        {
            treeWidget->addTopLevelItem(item);
        }

        treeWidget->resizeColumnToContents(0);
    }
}

void DatabaseManager::loadProtocolData(ProtocolBufferDrawer* bufferWidget)
{
    GLOBAL_VARS::globalProtocol = std::make_shared<PROTOCOL::Protocol>();
    std::shared_ptr<PROTOCOL::Protocol> protocol = GLOBAL_VARS::globalProtocol;
    qDebug() << "Gathering protocol data";

    //Get the value of the bytes of the buffer
    QSqlQuery query;
    query.exec("SELECT count(*) FROM protocol_buffer;");
    if (query.next())
    {
        int bufferCount = query.value("count(*)").toInt();
        for (int ii = 0; ii < bufferCount; ii++)
        {
            qDebug() << "Filling protocol buffer " << ii;
            std::vector<std::shared_ptr<PROTOCOL::ProtocolBuffer>>& bufferVector = protocol->bufferVector();
            std::shared_ptr<PROTOCOL::ProtocolBuffer> protocolBuffer = std::make_shared<PROTOCOL::ProtocolBuffer>();
            //Get the bytes from this buffer
            QSqlQuery bufferQuery;
            bufferQuery.exec(QString("SELECT * FROM protocol_buffer_byte pbb LEFT JOIN protocol_taint_leads ptl ON (pbb.buffer_idx=ptl.buffer_idx AND pbb.byte_offset=ptl.buffer_byte_offset) LEFT JOIN dll_names dn ON(ptl.dll_idx = dn.idx) WHERE pbb.buffer_idx = %1").arg(ii));
            int byteOffset = 0;
            while (bufferQuery.next())
            {
                qDebug() << "Adding byte " << byteOffset;
                //Add the byte into the protocol
                int byteValue = bufferQuery.value("byte_value").toInt();
                std::string hexValue = bufferQuery.value("hex_value").toString().toStdString();
                int color = bufferQuery.value("color").toInt();
                std::shared_ptr<PROTOCOL::ProtocolByte> byte = std::make_shared<PROTOCOL::ProtocolByte>(protocolBuffer, byteOffset, byteValue, hexValue, color);
                byte->belongingBuffer() = protocolBuffer;
                struct PROTOCOL::ProtocolByte::taint_lead_t lead
                {
                    bufferQuery.value("class").toInt(),
                    bufferQuery.value("dll_name").toString().toStdString(),
                    bufferQuery.value("arg_number").toInt()
                };
                byte->taintLead() = lead;
                qDebug() << "Byte info:: Color:" << byte->color() << " BValue:" << byte->byteValue();
                protocolBuffer->byteVector().push_back(byte);
                qDebug() << "here";
                byteOffset++;
            }
            qDebug() << "Finished filling bytes of buffer";

            //Now we get the words
            bufferQuery.exec(QString("SELECT * FROM protocol_word w JOIN protocol_word_byte pb ON (w.buffer_idx = pb.buffer_idx AND w.word_idx = pb.word_idx) WHERE w.buffer_idx = %1;").arg(ii));
            int lastWord = -1;
            qDebug() << "Now filling protocol words";
            while (bufferQuery.next())
            {
                std::shared_ptr<PROTOCOL::ProtocolWord> word;
                bool newWord = false;
                if (bufferQuery.value("word_idx").toInt() > lastWord)
                {
                    qDebug() << "New word created";
                    word = std::make_shared<PROTOCOL::ProtocolWord>();
                    lastWord = bufferQuery.value("word_idx").toInt();
                    newWord = true;
                }
                else
                {

                    qDebug() << "Reused last word";
                    word = protocolBuffer->wordVector().back();
                }
                word->belongingBuffer() = protocolBuffer;
                word->type() = bufferQuery.value("type").toInt();
                word->bufferStart() = bufferQuery.value("buffer_start").toInt();
                word->bufferEnd() = bufferQuery.value("buffer_end").toInt();

                qDebug() << " Pushing new protocol word";
                //Add the word byte info
                std::shared_ptr<PROTOCOL::ProtocolWordByte> byte = std::make_shared<PROTOCOL::ProtocolWordByte>(word, bufferQuery.value("byte_offset").toInt(), bufferQuery.value("value").toInt(), bufferQuery.value("color").toInt(), bufferQuery.value("success").toInt());
                word->byteVector().push_back(byte);

                if (newWord)
                {
                    protocolBuffer->wordVector().push_back(word);
                }
            }
            qDebug() << "Finished adding protocol words";

            //Now we get the pointers
            bufferQuery.exec(QString("SELECT * FROM protocol_pointer p JOIN protocol_pointer_byte pb ON (p.buffer_idx = pb.buffer_idx AND p.pointer_idx = pb.pointer_idx) LEFT JOIN protocol_buffer_byte bb ON(pb.color = bb.color) WHERE p.buffer_idx = %1;").arg(ii));
            int lastPointer = -1;

            qDebug() << "Now adding protocol pointers";
            while (bufferQuery.next())
            {
                qDebug() << "Starting protocol pointer insertion";
                std::shared_ptr<PROTOCOL::ProtocolPointer> pointer;
                bool newPointer = false;
                if (bufferQuery.value("protocol_pointer.pointer_idx").toInt() > lastPointer)
                {
                    qDebug() << "Created new protocol pointer";
                    pointer = std::make_shared<PROTOCOL::ProtocolPointer>();
                    lastPointer = bufferQuery.value("protocol_pointer.pointer_idx").toInt();
                    newPointer = true;
                }
                else
                {
                    qDebug() << "Reused protocol pointer";
                    pointer = protocolBuffer->pointerVector().back();
                }
                pointer->belongingBuffer() = protocolBuffer;
                pointer->pointedColor() = bufferQuery.value("pointed_color").toInt();
                pointer->pointedByte() = protocolBuffer->byteVector().at(protocolBuffer.get()->getOffsetOfColor(bufferQuery.value("protocol_pointer.pointed_color").toInt()));

                //Add the pointer byte info
                std::shared_ptr<PROTOCOL::ProtocolPointerByte> byte = std::make_shared<PROTOCOL::ProtocolPointerByte>(pointer, bufferQuery.value("protocol_pointer_byte.byte_offset").toInt(), bufferQuery.value("value").toInt(), bufferQuery.value("color").toInt());
                pointer->byteVector().push_back(byte);

                if (newPointer)
                {
                    protocolBuffer->pointerVector().push_back(pointer);
                }
            }

            qDebug() << "Finished adding all elements for buffer " << ii;

            //Finally push the buffer we just filled
            bufferVector.push_back(protocolBuffer);
        }
    }
}



std::vector<int> DatabaseManager::getColorParentsListFromColor(int color)
{
    std::shared_ptr<PROTOCOL::Protocol> protocol = GLOBAL_VARS::globalProtocol;
    int currentBufferIndex = GLOBAL_VARS::selectedBufferIndex;
    QSqlQuery query;
    //The following query returns rows if the color is not an original color. For each row, one of its parents,
    //which really is an original color, is returned. If the color passed is original, then no row is returned.
    query.exec(QString(
        "WITH RECURSIVE color_ancestors(derivate_color, color_mix_1, color_mix_2) AS( "
            "SELECT derivate_color, color_mix_1, color_mix_2 "
            "FROM color_transformation "
            "WHERE derivate_color = %1 "
            "UNION "
            "SELECT ct.derivate_color, ct.color_mix_1, ct.color_mix_2 "
            "FROM color_transformation AS ct "
            "JOIN color_ancestors "
                "ON color_ancestors.color_mix_1 = ct.derivate_color OR color_ancestors.color_mix_2 = ct.derivate_color "
        ") "
        "SELECT DISTINCT color_mix_1 AS original_color "
        "FROM color_ancestors "
        "WHERE color_mix_1 NOT IN( "
            "SELECT derivate_color "
            "FROM color_transformation "
        ") "
        "UNION "
        "SELECT DISTINCT color_mix_2 AS original_color " 
        "FROM color_ancestors "
        "WHERE color_mix_2 NOT IN( "
            "SELECT derivate_color "
            "FROM color_transformation "
        ")"
    ).arg(color));

    //We will take the original color parents of the color and put them in a vector
    std::vector<int> colorParents;
    while (query.next())
    {
        colorParents.push_back(query.value("original_color").toInt());
    }

    return colorParents;
}
