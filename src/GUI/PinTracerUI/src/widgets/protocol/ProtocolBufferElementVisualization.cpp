#include "widgets/protocol/ProtocolBufferElementVisualization.h"
#include "ui_ProtocolBufferElementVisualization.h"

ProtocolBufferElementVisualization::ProtocolBufferElementVisualization(std::shared_ptr<PROTOCOL::ProtocolWord> word, QWidget* parent) :
    QWidget(parent),
    ui(new Ui::ProtocolBufferElementVisualization)
{
    ui->setupUi(this);

    //Setup the visualization in word mode

}

ProtocolBufferElementVisualization::ProtocolBufferElementVisualization(std::shared_ptr<PROTOCOL::ProtocolPointer> pointer, QWidget* parent) :
    QWidget(parent),
    ui(new Ui::ProtocolBufferElementVisualization)
{
    ui->setupUi(this);

    //Setup the visualization in pointer mode

}

ProtocolBufferElementVisualization::~ProtocolBufferElementVisualization()
{
    delete ui;
}