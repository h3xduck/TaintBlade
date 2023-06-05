#include "TracedFunctionsWidget.h"
#include "ui_TracedFunctionsWidget.h"

TracedFunctionsWidget::TracedFunctionsWidget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::TracedFunctionsWidget)
{
    ui->setupUi(this);
}

TracedFunctionsWidget::~TracedFunctionsWidget()
{
    delete ui;
}
