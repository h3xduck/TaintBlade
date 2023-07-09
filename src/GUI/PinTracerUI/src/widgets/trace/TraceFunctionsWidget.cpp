#include "widgets/trace/TraceFunctionsWidget.h"
#include "ui_TraceFunctionsWidget.h"

TraceFunctionsWidget::TraceFunctionsWidget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::TraceFunctionsWidget)
{
    ui->setupUi(this);
    this->layout()->setContentsMargins(0,0,0,0);
    globalDBManager.buildTraceFunctionsTree(ui->treeWidget);
}

TraceFunctionsWidget::~TraceFunctionsWidget()
{
    delete ui;
}
