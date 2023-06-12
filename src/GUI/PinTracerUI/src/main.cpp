#include "mainwindow.h"
#include "common/Globals.h"

#include <QApplication>
#include <QDir>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    a.setApplicationName("TaintBlade");
    a.setWindowIcon(QIcon(":/res/res/appicon.png"));

    //Launch main app window
    MainWindow w;
    w.show();
    return a.exec();
}
