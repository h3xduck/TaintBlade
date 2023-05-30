#include "mainwindow.h"
#include "Globals.h"

#include <QApplication>
#include <QDir>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    //Launch main app window
    MainWindow w;
    w.show();
    return a.exec();
}
