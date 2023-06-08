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
