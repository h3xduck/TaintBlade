#include "widgets/protocol/ProtocolVisualizationWidget.h"
#include "ui_ProtocolVisualizationWidget.h"

ProtocolVisualizationWidget::ProtocolVisualizationWidget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::ProtocolVisualizationWidget)
{
    ui->setupUi(this);

    //The visualization is a row of buttons next to the other
    //We add a content widget to center the elements in the scrollarea
    this->contentWidget = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(contentWidget);
    ui->scrollArea->setWidget(contentWidget);

    this->bufferDrawerWidget = new ProtocolBufferDrawer(this);
    layout->addWidget(this->bufferDrawerWidget);
    layout->setAlignment(Qt::AlignCenter);

    globalDBManager.loadProtocolData(this->bufferDrawerWidget);
    startProtocolBufferVisualization(0);
}

ProtocolVisualizationWidget::~ProtocolVisualizationWidget()
{
    delete ui;
}

void ProtocolVisualizationWidget::startProtocolBufferVisualization(int bufferIndex)
{
    this->bufferDrawerWidget->visualizeBufferByPurpose(bufferIndex);
}