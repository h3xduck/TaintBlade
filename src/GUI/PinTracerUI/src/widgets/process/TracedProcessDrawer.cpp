#include "widgets/process/TracedProcessDrawer.h"
#include "widgets/process/TracedProcessWidget.h"

void TracedProcessDrawer::run()
{
    qDebug() << "Launched traced process drawer thread with PID " << thread()->currentThreadId();
    while(true)
    {
        this->sleep(3);
        //This thread checks the output directory for any file specifying traced processes
        QDir directory(GLOBAL_VARS::selectedOutputDirPath);
        QStringList processFiles = directory.entryList(QStringList() << "*tracedprocess.dfx" ,QDir::Files);
        foreach(QString filename, processFiles) {
            //For each one found, consume it
            QFile file(GLOBAL_VARS::selectedOutputDirPath+"/"+filename);
            if(!file.open(QIODevice::ReadOnly))
            {
                qDebug()<<"Error reading traced process file: "<< file.errorString();
            }
            QTextStream in(&file);
            QString line = in.readLine();
            QStringList fields = line.split("%");

            //Indicate the GUI to show a new traced process with its info
            emit sendRequestShowTracedProcessWidget(fields[0], fields[1], fields[2]);

            //We remove the file so that it is not consumed again
            file.remove();
            file.close();
        }
    }
}
