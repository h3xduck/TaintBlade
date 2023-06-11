#include "widgets/taint/TaintEventsWidget.h"
#include "ui_TaintEventsWidget.h"

TaintEventsWidget::TaintEventsWidget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::TaintEventsWidget)
{
    ui->setupUi(this);
    this->layout()->setContentsMargins(0,0,0,0);
    globalDBManager.buildTaintEventsTree(ui->treeWidget, true);

    connect(ui->checkBox, SIGNAL(toggled(bool)), this, SLOT(toggleIndirectRoutinesVisualization(bool)));
}

TaintEventsWidget::~TaintEventsWidget()
{
    delete ui;
}

void TaintEventsWidget::toggleIndirectRoutinesVisualization(bool activate)
{
    //Triggers when the user toggles the state of the checbox
    ui->treeWidget->clear();
    globalDBManager.buildTaintEventsTree(ui->treeWidget, activate);
}
