#ifndef TAINTEVENTSWIDGET_H
#define TAINTEVENTSWIDGET_H

#include <QWidget>
#include "utils/db/DatabaseManager.h"
#include <QTreeWidget>
#include <QTreeWidgetItem>

namespace Ui {
class TaintEventsWidget;
}

class TaintEventsWidget : public QWidget
{
    Q_OBJECT

public:
    explicit TaintEventsWidget(QWidget *parent = nullptr);
    ~TaintEventsWidget();

private slots:
    void toggleIndirectRoutinesVisualization(bool activate);
    void toggleGroupTaintEvents(bool setting);

private:
    Ui::TaintEventsWidget *ui;
    bool indirectRoutinesShow = false;
    bool groupTaintEvents = false;
};

#endif // TAINTEVENTSWIDGET_H
