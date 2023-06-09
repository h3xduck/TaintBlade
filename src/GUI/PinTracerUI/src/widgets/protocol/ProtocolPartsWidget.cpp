#include "widgets/protocol/ProtocolPartsWidget.h"
#include "ui_ProtocolPartsWidget.h"


ProtocolPartsWidget::ProtocolPartsWidget(QWidget* parent) :
    QWidget(parent),
    ui(new Ui::ProtocolPartsWidget)
{
    ui->setupUi(this);
    
    //Introduce the data from the protocol into the widgets
    //The first one holds info about buffers
    std::vector<std::shared_ptr<PROTOCOL::ProtocolBuffer>> protocolBufferVec = GLOBAL_VARS::globalProtocol.get()->bufferVector();
    for (int ii=0; ii<protocolBufferVec.size(); ii++)
    {
        std::shared_ptr<PROTOCOL::ProtocolBuffer> buffer = protocolBufferVec.at(ii);
        QListWidgetItem *item = new QListWidgetItem();
        //Each buffer has as data their own index in the buffer vector
        item->setData(Qt::UserRole, ii);
        item->setText(QString("PROTOCOL BUFFER %1").arg(ii));
        ui->topListWidget->addItem(item);

        connect(ui->topListWidget, SIGNAL(itemClicked(QListWidgetItem*)), this, SLOT(onTopListItemClicked(QListWidgetItem*)));
    }


}

ProtocolPartsWidget::~ProtocolPartsWidget()
{
    delete ui;
}

void ProtocolPartsWidget::onTopListItemClicked(QListWidgetItem* item)
{
    ui->midListWidget->clear();
    ui->botListWidget->clear();
    int bufferPosition = item->data(Qt::UserRole).toInt();
    //Display the words and pointers relative to this clicked buffer
    std::shared_ptr<PROTOCOL::ProtocolBuffer> buffer = GLOBAL_VARS::globalProtocol.get()->bufferVector().at(bufferPosition);
    std::vector<std::shared_ptr<PROTOCOL::ProtocolWord>> wordVec = buffer.get()->wordVector();
    int delimeterNum = 0;
    int keywordNum = 0;
    int byteKeywordNum = 0;
    for (int ii = 0; ii < wordVec.size(); ii++)
    {
        std::shared_ptr<PROTOCOL::ProtocolWord> word = wordVec.at(ii);
        QListWidgetItem* item = new QListWidgetItem();
        item->setData(Qt::UserRole, ii);
        int type = word.get()->type();
        switch (type)
        {
        case 1: 
            item->setText(QString("%1 %2").arg("DELIMETER").arg(delimeterNum++));
            break;
        case 2: 
            item->setText(QString("%1 %2").arg("KEYWORD").arg(keywordNum++));
            break;
        case 5: 
            item->setText(QString("%1 %2").arg("BYTEKEYWORD").arg(byteKeywordNum++));
            break;
        default:
            item->setText(QString("%1 %2").arg("UNKNOWN - ERROR").arg("??"));
        }
        
        ui->midListWidget->addItem(item);
    }
    int pointerFieldNum = 0;
    std::vector<std::shared_ptr<PROTOCOL::ProtocolPointer>> pointerVec = buffer.get()->pointerVector();
    for (int ii = 0; ii < pointerVec.size(); ii++)
    {
        std::shared_ptr<PROTOCOL::ProtocolPointer> pointer = pointerVec.at(ii);
        QListWidgetItem* item = new QListWidgetItem();
        item->setData(Qt::UserRole, ii);
        item->setText(QString("%1 %2").arg("POINTER FIELD").arg(pointerFieldNum++));
        ui->botListWidget->addItem(item);
    }

    //Once all fields are ready, we also setup the buffer visualization in the other widget


}