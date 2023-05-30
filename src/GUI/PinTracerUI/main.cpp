#include "mainwindow.h"
#include "Globals.h"

#include <QApplication>
#include <QDir>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    //Setup output dir
    GLOBAL_VARS::selectedOutputDirPath = QDir::currentPath();
    qDebug() << "Selected dir "<<GLOBAL_VARS::selectedOutputDirPath<<" to store output data";

    //Launch main app window
    MainWindow w;
    w.show();
    return a.exec();
}
