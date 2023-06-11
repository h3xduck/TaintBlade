#include "widgets/taint/TaintRoutinesWidget.h"
#include "ui_TaintRoutinesWidget.h"

TaintRoutinesWidget::TaintRoutinesWidget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::TaintRoutinesWidget)
{
    ui->setupUi(this);
    this->layout()->setContentsMargins(0,0,0,0);
    globalDBManager.buildTaintRoutinesTree(ui->treeWidget);
}

TaintRoutinesWidget::~TaintRoutinesWidget()
{
    delete ui;
}

void TaintRoutinesWidget::highlightTaintRoutineByLead(PROTOCOL::ProtocolByte::taint_lead_t& lead)
{
    QList<QModelIndex>* list = new QList<QModelIndex>();
    for (int ii = 0; ii < ui->treeWidget->topLevelItemCount(); ii++)
    {
        QTreeWidgetItem* item = (QTreeWidgetItem*)ui->treeWidget->topLevelItem(ii);
        if (item->text(0) == QString::fromLatin1(lead.funcName) && item->text(1) == QString::fromLatin1(lead.dllName))
        {
            //Select
            QColor color = QColor(230, 230, 230);
            for (int jj = 0; jj < 5; jj++)
            {
                list->append(ui->treeWidget->model()->index(ii, jj));
            }
        }
    }
    ui->treeWidget->setItemDelegate(new TreeWidgetItemColourableDelegate(list));
}