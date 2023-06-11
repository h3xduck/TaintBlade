#include "widgets/protocol/ProtocolBufferDrawer.h"
#include "ui_ProtocolBufferDrawer.h"

ProtocolBufferDrawer::ProtocolBufferDrawer(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::ProtocolBufferDrawer)
{
    ui->setupUi(this);

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

void ProtocolBufferDrawer::addProtocolBufferByte(QString byteValue, int byteOffset, float widthMultiplicator, float heightMultiplicator)
{
    PROTOCOL::ByteBufferPushButton *button = new PROTOCOL::ByteBufferPushButton(byteValue, this, byteOffset);
    button->setFixedSize(button->width() * widthMultiplicator, button->height() * heightMultiplicator);

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
    this->currentBufferIndex = bufferIndex;

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
    for (int ii=0; ii<protocolBuffer.get()->wordVector().size(); ii++)
    {
        std::shared_ptr<PROTOCOL::ProtocolWord> word = protocolBuffer.get()->wordVector().at(ii);
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
                button->setColor(QColor(Qt::blue));
                button->type() = PROTOCOL::ByteBufferPushButton::TDELIMETER_CTAINTSINK;
                break;
            case 2: //KEYWORD
                button->setColor(QColor(0, 207, 29));
                button->type() = PROTOCOL::ByteBufferPushButton::TKEYWORD;
                break;
            case 5: //BYTEKEYWORD
                button->setColor(QColor(Qt::lightGray));
                button->type() = PROTOCOL::ByteBufferPushButton::TBYTEKEYWORD;
                break;
            case 0:
            default:
                button->setColor(QColor(Qt::white));
                button->type() = PROTOCOL::ByteBufferPushButton::TNONE_CNONE;
                break;
            }
            button->protocolElementIndex() = ii;
        }
    }

    //We do the same but for pointer fields
    for (int ii=0; ii< protocolBuffer.get()->pointerVector().size(); ii++)
    {
        std::shared_ptr<PROTOCOL::ProtocolPointer> pointer = protocolBuffer.get()->pointerVector().at(ii);
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
            button->setColor(QColor(193,77,255));
            button->type() = PROTOCOL::ByteBufferPushButton::TPOINTER;
            button->protocolElementIndex() = ii;
        }
    }

    redistributeLayoutButtons();
}

void ProtocolBufferDrawer::visualizeBufferByPurpose(int bufferIndex)
{
    qDebug() << "Drawing data in the widget by purpose";
    this->currentBufferIndex = bufferIndex;

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
        this->addProtocolBufferByte(QString(QChar(byte.get()->byteValue())), byte.get()->byteOffset());
        PROTOCOL::ByteBufferPushButton* button = (PROTOCOL::ByteBufferPushButton*)ui->horizontalLayout->itemAt(byte.get()->byteOffset())->widget();

        int selectedType = 0;
        switch (lead.leadClass)
        {
        case 1: //TAINT SINK
            button->setColor(QColor(254,130,0));
            selectedType = PROTOCOL::ByteBufferPushButton::TDELIMETER_CTAINTSINK;
            break;
        case 0:
        default:
            //ERROR
            button->setColor(QColor(Qt::white));
            break;
        }

        button->type() = (PROTOCOL::ByteBufferPushButton::buttonType_t)selectedType;
        //Connect the signal that will trigger when someone clicks the button
        //TODO
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

void ProtocolBufferDrawer::highlightButtonWithProtocolWord(int index)
{
    //First we check whether that word index is shown at the buffer or not. If it was not a successful check, then it should not be shown
    std::shared_ptr<PROTOCOL::ProtocolWord> word = GLOBAL_VARS::globalProtocol.get()->bufferVector().at(this->currentBufferIndex).get()->wordVector().at(index);
    bool successWord = false;
    for (std::shared_ptr<PROTOCOL::ProtocolWordByte> byte : word.get()->byteVector())
    {
        if (byte.get()->success() == 1)
        {
            successWord = true;
        }
    }
    if (!successWord)
    {
        qDebug() << "Requested to highlight button of word which was not a success word";
        return;
    }

    for (int ii = 0; ii< ui->horizontalLayout->count(); ii++)
    {
        PROTOCOL::ByteBufferPushButton* button = (PROTOCOL::ByteBufferPushButton*)ui->horizontalLayout->itemAt(ii)->widget();
        //Check if the button holds a word
        if (button->type() == PROTOCOL::ByteBufferPushButton::TKEYWORD ||
            button->type() == PROTOCOL::ByteBufferPushButton::TBYTEKEYWORD ||
            button->type() == PROTOCOL::ByteBufferPushButton::TDELIMETER_CTAINTSINK)
        {
            if (button->protocolElementIndex() == index)
            {
                //Highlight the button
                QPropertyAnimation* paAnimation = new QPropertyAnimation(button, "color");
                QColor initialColor = button->getColor();
                paAnimation->setStartValue(initialColor);
                paAnimation->setEndValue(QColor(242, 253, 111));
                paAnimation->setDuration(500);
                paAnimation->setLoopCount(10);
                paAnimation->start();

                return;
            }
        }
    }
}

void ProtocolBufferDrawer::highlightButtonWithProtocolPointer(int index)
{
    for (int ii = 0; ii < ui->horizontalLayout->count(); ii++)
    {
        PROTOCOL::ByteBufferPushButton* button = (PROTOCOL::ByteBufferPushButton*)ui->horizontalLayout->itemAt(ii)->widget();
        //Check if the button holds a word
        if (button->type() == PROTOCOL::ByteBufferPushButton::TPOINTER)
        {
            if (button->protocolElementIndex() == index)
            {
                //Highlight the button
                QPropertyAnimation* paAnimation = new QPropertyAnimation(button, "color");
                QColor initialColor = button->getColor();
                paAnimation->setStartValue(initialColor);
                paAnimation->setEndValue(QColor(242, 253, 111));
                paAnimation->setDuration(500);
                paAnimation->setLoopCount(10);
                paAnimation->start();

                return;
            }
        }
    }
}

void ProtocolBufferDrawer::visualizeWordBytes(std::shared_ptr<PROTOCOL::ProtocolWord> word)
{
    for (std::shared_ptr<PROTOCOL::ProtocolWordByte> byte : word.get()->byteVector())
    {
        addProtocolBufferByte(UTILS::getHexValueOfByte(byte.get()->byteValue(), 2), byte.get()->byteOffset(), 1.2);
        PROTOCOL::ByteBufferPushButton* button = (PROTOCOL::ByteBufferPushButton*)ui->horizontalLayout->itemAt(byte.get()->byteOffset())->widget();
        //Depending on whether the check is a fail or a success in this byte, we color in one way or another
        if (byte.get()->success() == 0)
        {
            button->setColor(QColor(255, 100, 95));
        }
        else if(byte.get()->success() == 1)
        {
            button->setColor(QColor(95, 255, 100));
        }
    }
}

void ProtocolBufferDrawer::visualizePointerBytes(std::shared_ptr<PROTOCOL::ProtocolPointer> pointer)
{
    for (std::shared_ptr<PROTOCOL::ProtocolPointerByte> byte : pointer.get()->byteVector())
    {
        addProtocolBufferByte(UTILS::getHexValueOfByte(byte.get()->byteValue(), 2), byte.get()->byteOffset(), 1.2);
        PROTOCOL::ByteBufferPushButton* button = (PROTOCOL::ByteBufferPushButton*)ui->horizontalLayout->itemAt(byte.get()->byteOffset())->widget();
        //Depending on whether there is a color in the byte or not, we show that the byte was useful or not
        if (byte.get()->color() == 0)
        {
            button->setColor(QColor(230, 230, 230));
        }
        else
        {
            button->setColor(QColor(78, 108, 254));
        }
    }
}

void ProtocolBufferDrawer::highlightButtonWithProtocolByte(int byteOffset)
{
    int byteOffsetAccumulator = 0;
    for (int ii = 0; ii < ui->horizontalLayout->count(); ii++)
    {
        PROTOCOL::ByteBufferPushButton* button = (PROTOCOL::ByteBufferPushButton*)ui->horizontalLayout->itemAt(ii)->widget();
        //Check if the button contains the byte
        if ((byteOffsetAccumulator + button->getInternalByteSize()) > byteOffset)
        {
            //Highlight the button
            QPropertyAnimation* paAnimation = new QPropertyAnimation(button, "color");
            QColor initialColor = button->getColor();
            paAnimation->setStartValue(initialColor);
            paAnimation->setEndValue(QColor(249, 23, 13));
            paAnimation->setDuration(500);
            paAnimation->setLoopCount(10);
            paAnimation->start();

            return;
        }
        byteOffsetAccumulator += button->getInternalByteSize();
    }
}