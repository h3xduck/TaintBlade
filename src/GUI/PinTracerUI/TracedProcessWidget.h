#ifndef TRACEDPROCESSWIDGET_H
#define TRACEDPROCESSWIDGET_H

#include <QWidget>
#include <QString>
#include "TracedProcessDrawer.h"
#include <QDateTime>
#include <QModelIndex>

namespace Ui {
class tracedProcessWidget;
}

class TracedProcessWidget : public QWidget
{
    Q_OBJECT

public:
    explicit TracedProcessWidget(QWidget *parent = nullptr);
    ~TracedProcessWidget();

    void showTracedProcess();
    void endTracedProcess();

public slots:
    void drawTracedProgramWidget(QString pid, QString dll, QString timestamp);
    void treeViewRowDoubleClicked(QModelIndex index);

private:
    Ui::tracedProcessWidget *ui;
    TracedProcessDrawer *processDrawer;
};

#endif // TRACEDPROCESSWIDGET_H
