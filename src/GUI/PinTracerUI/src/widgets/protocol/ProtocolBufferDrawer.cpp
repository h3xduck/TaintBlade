#include "widgets/protocol/ProtocolBufferDrawer.h"
#include "ui_ProtocolBufferDrawer.h"

ProtocolBufferDrawer::ProtocolBufferDrawer(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::ProtocolBufferDrawer)
{
    ui->setupUi(this);

    //Initialize protocol
    //std::shared_ptr<PROTOCOL::Protocol> protocol = this->protocol();
    GLOBAL_VARS::globalProtocol = std::make_shared<PROTOCOL::Protocol>();

    //Build a series of buttons representing bytes
    /*QPushButton *button = new QPushButton(QString("No\nprotocol\nfound"), this);
    button->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    button->setFixedSize(60,90);

    ui->horizontalLayout->addWidget(button);
    ui->horizontalLayout->setContentsMargins(0, 0, 0, 0);
    ui->horizontalLayout->setSpacing(0);
    button->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    button->setStyleSheet(
        "QPushButton { "
        "background-color: orange; "
        "border-style: outset; "
        "border-width: 2px; "
        "border-radius: 0px; "
        "border-color: black; "
        "padding: 4px; }"
        );

    QPalette pal = QPalette();
    pal.setColor(QPalette::Window, Qt::red);
    this->setAutoFillBackground(true);
    this->setPalette(pal);*/


    ui->horizontalLayout->setContentsMargins(0, 0, 0, 0);
    ui->horizontalLayout->setSpacing(0);

}

ProtocolBufferDrawer::~ProtocolBufferDrawer()
{
    delete ui;
}

void ProtocolBufferDrawer::addButton()
{
    QPushButton *button = new QPushButton(QString("No\nprotocol\nfound"), this);
    button->setFixedSize(60,90);
    button->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    ui->horizontalLayout->addWidget(button);
}

void ProtocolBufferDrawer::addProtocolBufferByte(QString byteValue, int byteOffset)
{
    PROTOCOL::ByteBufferPushButton *button = new PROTOCOL::ByteBufferPushButton(byteValue, this, byteOffset);

    ui->horizontalLayout->addWidget(button);
    /*QPropertyAnimation animation(button, "geometry");
    animation.setDuration(5000);  //2000 miliseconds = 2 seconds
    animation.setStartValue(QRect(0,0, button->width(),button->height()));
    animation.setEndValue(QRect(180,180, button->width(),button->height()));
    animation.start();*/
}

void ProtocolBufferDrawer::visualizeBufferByWordtype(int bufferIndex)
{
    qDebug() << "Drawing data in the widget by word type";

    QLayoutItem* child;
    while ((child = ui->horizontalLayout->takeAt(0)) != nullptr) {
        delete child->widget();
    }

    //Now that we've got the data, we can draw it
    std::shared_ptr<PROTOCOL::ProtocolBuffer> protocolBuffer = GLOBAL_VARS::globalProtocol.get()->bufferVector().at(bufferIndex);
    for (std::shared_ptr<PROTOCOL::ProtocolByte> byte : protocolBuffer.get()->byteVector())
    {
        //Display the byte at the widget
        this->addProtocolBufferByte(QString(QChar(byte.get()->byteValue())), byte.get()->byteOffset());
    }

    //Now, each of the widget buttons will be colored differently depending on whether it belongs to a word or pointer
    for (std::shared_ptr<PROTOCOL::ProtocolWord> word : protocolBuffer.get()->wordVector())
    {
        //Color it depending on the word type       
        for (auto byte : word.get()->byteVector())
        {
            int wordType = word.get()->type();
            int offset = protocolBuffer.get()->getOffsetOfColor(byte.get()->color());
            if (offset == -1)
            {
                continue;
            }
            PROTOCOL::ByteBufferPushButton* button = (PROTOCOL::ByteBufferPushButton*)ui->horizontalLayout->itemAt(offset)->widget();
            QString buttonStylesheet;

            //If the word byte was a fail check, we don't mark it
            if (byte.get()->success() != 1)
            {
                continue;
            }

            //Choose color depending on word type
            switch (wordType)
            {
            case 1: //DELIMETER
                buttonStylesheet = QString("QPushButton { "
                    "background-color: blue; "
                    "border-style: outset; "
                    "border-width: 2px; "
                    "border-radius: 0px; "
                    "border-color: black; "
                    "padding: 4px; }");
                button->type() = PROTOCOL::ByteBufferPushButton::TDELIMETER_CTAINTSINK;
                break;
            case 2: //KEYWORD
                buttonStylesheet = QString("QPushButton { "
                    "background-color: green; "
                    "border-style: outset; "
                    "border-width: 2px; "
                    "border-radius: 0px; "
                    "border-color: black; "
                    "padding: 4px; }");
                button->type() = PROTOCOL::ByteBufferPushButton::TKEYWORD;
                break;
            case 5: //BYTEKEYWORD
                buttonStylesheet = QString("QPushButton { "
                    "background-color: yellow; "
                    "border-style: outset; "
                    "border-width: 2px; "
                    "border-radius: 0px; "
                    "border-color: black; "
                    "padding: 4px; }");
                button->type() = PROTOCOL::ByteBufferPushButton::TBYTEKEYWORD;
                break;
            case 0:
            default:
                buttonStylesheet = QString("QPushButton { "
                    "background-color: white; "
                    "border-style: outset; "
                    "border-width: 2px; "
                    "border-radius: 0px; "
                    "border-color: black; "
                    "padding: 4px; }");
                button->type() = PROTOCOL::ByteBufferPushButton::TNONE_CNONE;
                break;
            }

            button->setStyleSheet(buttonStylesheet);
        }
    }

    //We do the same but for pointer fields
    for (std::shared_ptr<PROTOCOL::ProtocolPointer> pointer : protocolBuffer.get()->pointerVector())
    {
        for (auto byte : pointer.get()->byteVector())
        {
            int offset = protocolBuffer.get()->getOffsetOfColor(byte.get()->color());
            if (offset == -1)
            {
                continue;
            }
            PROTOCOL::ByteBufferPushButton* button = (PROTOCOL::ByteBufferPushButton*)ui->horizontalLayout->itemAt(offset)->widget();
            //If the pointer references color 0, means it did not take part in the referencig job (but rather some other byte)
            if (byte.get()->color() == 0)
            {
                continue;
            }
            QString buttonStylesheet = QString("QPushButton { "
                "background-color: purple; "
                "border-style: outset; "
                "border-width: 2px; "
                "border-radius: 0px; "
                "border-color: black; "
                "padding: 4px; }");
            button->type() = PROTOCOL::ByteBufferPushButton::TPOINTER;
            button->setStyleSheet(buttonStylesheet);
        }
    }

    redistributeLayoutButtons();
}

void ProtocolBufferDrawer::visualizeBufferByPurpose(int bufferIndex)
{
    qDebug() << "Drawing data in the widget by purpose";

    QLayoutItem* child;
    while ((child = ui->horizontalLayout->takeAt(0)) != nullptr) {
        delete child->widget();
    }
    //Now that we've got the data, we can draw it
    std::shared_ptr<PROTOCOL::ProtocolBuffer> protocolBuffer = GLOBAL_VARS::globalProtocol.get()->bufferVector().at(bufferIndex);
    for (std::shared_ptr<PROTOCOL::ProtocolByte> byte : protocolBuffer.get()->byteVector())
    {
        //Display the byte at the widget, color of the button depends on taint lead class
        PROTOCOL::ProtocolByte::taint_lead_t lead = byte.get()->taintLead();
        QString buttonStylesheet;
        int selectedType = 0;
        switch (lead.leadClass)
        {
        case 1: //TAINT SINK
            buttonStylesheet = QString("QPushButton { "
                "background-color: orange; "
                "border-style: outset; "
                "border-width: 2px; "
                "border-radius: 0px; "
                "border-color: black; "
                "padding: 4px; }");
            selectedType = PROTOCOL::ByteBufferPushButton::TDELIMETER_CTAINTSINK;
            break;
        case 0:
        default:
            //ERROR
            buttonStylesheet = QString("QPushButton { "
                "background-color: white; "
                "border-style: outset; "
                "border-width: 2px; "
                "border-radius: 0px; "
                "border-color: black; "
                "padding: 4px; }");
            break;
        }

        this->addProtocolBufferByte(QString(QChar(byte.get()->byteValue())), byte.get()->byteOffset());
        PROTOCOL::ByteBufferPushButton* button = (PROTOCOL::ByteBufferPushButton*)ui->horizontalLayout->itemAt(byte.get()->byteOffset())->widget();
        button->type() = (PROTOCOL::ByteBufferPushButton::buttonType_t)selectedType;
        button->setStyleSheet(buttonStylesheet);
        //Connect the signal that will trigger when someone clicks the button
    }

    redistributeLayoutButtons();
}

void ProtocolBufferDrawer::redistributeLayoutButtons()
{
    int lastType = PROTOCOL::ByteBufferPushButton::TNONE_CNONE;
    bool firstInGroup = true;
    qDebug() << "Starting button redistrubution, there are "<< ui->horizontalLayout->count()<<" buttons";
    for (int ii= ui->horizontalLayout->count()-1; ii>=0; ii--)
    {
        qDebug()<<"Going for button at index " << ii;
        PROTOCOL::ByteBufferPushButton *button = (PROTOCOL::ByteBufferPushButton*)ui->horizontalLayout->itemAt(ii)->widget();
        if (button->type() != PROTOCOL::ByteBufferPushButton::TNONE_CNONE && button->type() == lastType && ii != ui->horizontalLayout->count() - 1)
        {
            //Join the button to the last one if it is part of the same type
            PROTOCOL::ByteBufferPushButton* lastButton = (PROTOCOL::ByteBufferPushButton*)ui->horizontalLayout->itemAt(ii + 1)->widget();
            button->joinAdditionalButton(lastButton->textList(), lastButton->startByte(), lastButton->endByte());
            //Delete the old button
            delete lastButton;
            qDebug() << "Redistributed button!";
        }
        lastType = button->type();
    }
}