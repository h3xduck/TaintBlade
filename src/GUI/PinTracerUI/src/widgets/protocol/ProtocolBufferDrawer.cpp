#include "widgets/protocol/ProtocolBufferDrawer.h"
#include "ui_ProtocolBufferDrawer.h"

ProtocolBufferDrawer::ProtocolBufferDrawer(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::ProtocolBufferDrawer)
{
    ui->setupUi(this);

    //Initialize protocol
    //std::shared_ptr<PROTOCOL::Protocol> protocol = this->protocol();
    this->protocol_ = std::make_shared<PROTOCOL::Protocol>();

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

void ProtocolBufferDrawer::addProtocolBufferByte(QString byteValue)
{
    QPushButton *button = new QPushButton(byteValue, this);
    button->setFixedSize(30,90);

    button->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    ui->horizontalLayout->addWidget(button);
    QPropertyAnimation animation(button, "geometry");
    animation.setDuration(5000);  //2000 miliseconds = 2 seconds
    animation.setStartValue(QRect(0,0, button->width(),button->height()));
    animation.setEndValue(QRect(180,180, button->width(),button->height()));
    animation.start();
}

void ProtocolBufferDrawer::visualizeBufferByWordtype(int bufferIndex)
{
    qDebug() << "Drawing data in the widget";

    //Now that we've got the data, we can draw it
    //TODO - Support rest of the buffers
    std::shared_ptr<PROTOCOL::ProtocolBuffer> protocolBuffer = this->protocol().get()->bufferVector().at(bufferIndex);
    for (std::shared_ptr<PROTOCOL::ProtocolByte> byte : protocolBuffer.get()->byteVector())
    {
        //Display the byte at the widget
        this->addProtocolBufferByte(QString(QChar(byte.get()->byteValue())));
    }

    //Now, each of the widget buttons will be colored differently depending on whether it belongs to a word or pointer
    for (std::shared_ptr<PROTOCOL::ProtocolWord> word : protocolBuffer.get()->wordVector())
    {
        //Color it depending on the word type       
        for (auto byte : word.get()->byteVector())
        {
            int wordType = word.get()->type();
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
                break;
            case 2: //KEYWORD
                buttonStylesheet = QString("QPushButton { "
                    "background-color: green; "
                    "border-style: outset; "
                    "border-width: 2px; "
                    "border-radius: 0px; "
                    "border-color: black; "
                    "padding: 4px; }");
                break;
            case 5: //BYTEKEYWORD
                buttonStylesheet = QString("QPushButton { "
                    "background-color: yellow; "
                    "border-style: outset; "
                    "border-width: 2px; "
                    "border-radius: 0px; "
                    "border-color: black; "
                    "padding: 4px; }");
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
                break;
            }

            ui->horizontalLayout->itemAt(byte.get()->byteOffset())->widget()->setStyleSheet(buttonStylesheet);
        }
    }

    //We do the same but for pointer fields
    for (std::shared_ptr<PROTOCOL::ProtocolPointer> pointer : protocolBuffer.get()->pointerVector())
    {
        for (auto byte : pointer.get()->byteVector())
        {
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

            ui->horizontalLayout->itemAt(byte.get()->byteOffset())->widget()->setStyleSheet(buttonStylesheet);

        }
    }
}