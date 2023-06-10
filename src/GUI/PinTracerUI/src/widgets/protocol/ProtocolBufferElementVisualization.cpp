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

    //Put the data into the labels
    ui->bufferIndexLabel->setText(QString("%1 %2").arg(ui->bufferIndexLabel->text()).arg(GLOBAL_VARS::selectedBufferIndex));
    QString wordTypeText = "UNKNOWN";
    switch (word.get()->type())
    {
    case 1: wordTypeText = "DELIMETER"; break;
    case 2: wordTypeText = "KEYWORD"; break;
    case 5: wordTypeText = "BYTEKEYWORD"; break;
    }
    ui->wordTypeLabel->setText(QString("%1 %2").arg(ui->wordTypeLabel->text()).arg(wordTypeText));

    //Finally fill in the tree widget with byte data
    ui->treeWidget->clear();
    ui->treeWidget->setColumnCount(4);
    QStringList headers = { "Byte offset", "Value", "Color", "Comparison success"};
    ui->treeWidget->setHeaderLabels(headers);
    
    for (std::shared_ptr<PROTOCOL::ProtocolWordByte> byte : word.get()->byteVector())
    {
        QTreeWidgetItem* item = new QTreeWidgetItem();
        item->setText(0, QString::number(byte.get()->byteOffset()));
        item->setText(1, QString::number(byte.get()->byteValue()));
        item->setText(2, QString::number(byte.get()->color()));
        item->setText(3, QString::number(byte.get()->success()));
        ui->treeWidget->addTopLevelItem(item);
    }

    ui->treeWidget->resizeColumnToContents(0);
    ui->treeWidget->resizeColumnToContents(1);
    ui->treeWidget->resizeColumnToContents(2);
    ui->treeWidget->resizeColumnToContents(3);
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