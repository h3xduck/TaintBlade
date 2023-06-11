#ifndef TAINTROUTINESWIDGET_H
#define TAINTROUTINESWIDGET_H

#include <QWidget>
#include "utils/db/DatabaseManager.h"
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include "widgets/misc/TreeWidgetItemColourableDelegate.h"

namespace Ui {
class TaintRoutinesWidget;
}

class TaintRoutinesWidget : public QWidget
{
    Q_OBJECT

public:
    explicit TaintRoutinesWidget(QWidget *parent = nullptr);
    ~TaintRoutinesWidget();

    void highlightTaintRoutineByLead(PROTOCOL::ProtocolByte::taint_lead_t& lead);
private:
    Ui::TaintRoutinesWidget *ui;
};

#endif // TAINTROUTINESWIDGET_H
