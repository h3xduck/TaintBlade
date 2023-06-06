#include "ProtocolVisualizationWidget.h"
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

    ProtocolBufferWidget* bufferWidget = new ProtocolBufferWidget();
    layout->addWidget(bufferWidget);
    layout->setAlignment(Qt::AlignCenter);


    for(int ii=0; ii<100; ii++)
    bufferWidget->addButton();
}

ProtocolVisualizationWidget::~ProtocolVisualizationWidget()
{
    delete ui;
}
