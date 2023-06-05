#ifndef TAINTEVENTSWIDGET_H
#define TAINTEVENTSWIDGET_H

#include <QWidget>
#include "DatabaseManager.h"
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

private:
    Ui::TaintEventsWidget *ui;
};

#endif // TAINTEVENTSWIDGET_H
