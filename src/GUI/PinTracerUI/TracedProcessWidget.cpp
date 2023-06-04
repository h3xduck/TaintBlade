#include "TracedProcessWidget.h"
#include "ui_TracedProcessWidget.h"
#include <QDebug>

TracedProcessWidget::TracedProcessWidget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::tracedProcessWidget)
{
    qDebug()<<"aa";
    ui->setupUi(this);
    QPalette pal = QPalette();
    pal.setColor(QPalette::Window, Qt::blue);
    this->setAutoFillBackground(true);
    this->setPalette(pal);
    this->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
}

TracedProcessWidget::~TracedProcessWidget()
{
    delete ui;
}
