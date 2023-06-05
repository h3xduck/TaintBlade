#ifndef TAINTROUTINESWIDGET_H
#define TAINTROUTINESWIDGET_H

#include <QWidget>
#include "DatabaseManager.h"
#include <QTreeWidget>
#include <QTreeWidgetItem>

namespace Ui {
class TaintRoutinesWidget;
}

class TaintRoutinesWidget : public QWidget
{
    Q_OBJECT

public:
    explicit TaintRoutinesWidget(QWidget *parent = nullptr);
    ~TaintRoutinesWidget();

private:
    Ui::TaintRoutinesWidget *ui;
};

#endif // TAINTROUTINESWIDGET_H
