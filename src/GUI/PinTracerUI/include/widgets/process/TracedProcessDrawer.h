#ifndef TRACEDPROCESSDRAWER_H
#define TRACEDPROCESSDRAWER_H

#include <QThread>
#include <QDebug>
#include "common/Globals.h"
#include <QDir>
#include <QFile>

class TracedProcessWidget;

class TracedProcessDrawer : public QThread
{
    Q_OBJECT

private:
    void run();

signals:
    void sendRequestShowTracedProcessWidget(QString pid, QString dll, QString timestamp);
};

#endif // TRACEDPROCESSDRAWER_H
