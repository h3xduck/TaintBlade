#include "widgets/protocol/ProtocolBufferElementVisualization.h"
#include "ui_ProtocolBufferElementVisualization.h"

ProtocolBufferElementVisualization::ProtocolBufferElementVisualization(std::shared_ptr<PROTOCOL::ProtocolWord> word, QWidget* parent) :
    QWidget(parent),
    ui(new Ui::ProtocolBufferElementVisualization)
{
    ui->setupUi(this);

    //Setup the visualization in word mode
    this->contentWidget = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(contentWidget);
    ui->scrollArea->setWidget(contentWidget);

    this->bufferDrawerWidget = new ProtocolBufferDrawer(this);
    layout->addWidget(this->bufferDrawerWidget);
    layout->setAlignment(Qt::AlignCenter);

    //Show the bytes of the word in the widget
    this->bufferDrawerWidget->visualizeWordBytes(word);

}

ProtocolBufferElementVisualization::ProtocolBufferElementVisualization(std::shared_ptr<PROTOCOL::ProtocolPointer> pointer, QWidget* parent) :
    QWidget(parent),
    ui(new Ui::ProtocolBufferElementVisualization)
{
    ui->setupUi(this);

    //Setup the visualization in pointer mode
    this->contentWidget = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(contentWidget);
    ui->scrollArea->setWidget(contentWidget);

    this->bufferDrawerWidget = new ProtocolBufferDrawer(this);
    layout->addWidget(this->bufferDrawerWidget);
    layout->setAlignment(Qt::AlignCenter);

    //Show the bytes of the pointer in the widget
    this->bufferDrawerWidget->visualizePointerBytes(pointer);

}

ProtocolBufferElementVisualization::~ProtocolBufferElementVisualization()
{
    delete ui;
}