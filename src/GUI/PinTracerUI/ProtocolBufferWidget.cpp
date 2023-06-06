#include "ProtocolBufferWidget.h"
#include "ui_ProtocolBufferWidget.h"

ProtocolBufferWidget::ProtocolBufferWidget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::ProtocolBufferWidget)
{
    ui->setupUi(this);

    //Build a series of buttons representing bytes
    QPushButton *button = new QPushButton(QString("No\nprotocol\nfound"), this);
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
    this->setPalette(pal);


}

ProtocolBufferWidget::~ProtocolBufferWidget()
{
    delete ui;
}

void ProtocolBufferWidget::addButton()
{
    QPushButton *button = new QPushButton(QString("No\nprotocol\nfound"), this);
    button->setFixedSize(60,90);
    button->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    ui->horizontalLayout->addWidget(button);
}
