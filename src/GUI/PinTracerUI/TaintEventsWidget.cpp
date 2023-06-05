#include "TaintEventsWidget.h"
#include "ui_TaintEventsWidget.h"

TaintEventsWidget::TaintEventsWidget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::TaintEventsWidget)
{
    ui->setupUi(this);
    this->layout()->setContentsMargins(0,0,0,0);
    //globalDBManager.buildTaintEventsTree(ui->treeWidget);
}

TaintEventsWidget::~TaintEventsWidget()
{
    delete ui;
}
