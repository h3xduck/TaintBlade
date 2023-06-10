#include "widgets/protocol/ProtocolBufferElementVisualization.h"
#include "ui_ProtocolBufferElementVisualization.h"

ProtocolBufferElementVisualization::ProtocolBufferElementVisualization(QWidget* parent) :
    QWidget(parent),
    ui(new Ui::ProtocolBufferElementVisualization)
{
    ui->setupUi(this);
}


ProtocolBufferElementVisualization::~ProtocolBufferElementVisualization()
{
    delete ui;
}