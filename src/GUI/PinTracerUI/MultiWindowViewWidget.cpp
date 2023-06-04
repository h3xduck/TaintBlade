#include "MultiWindowViewWidget.h"
#include "ui_MultiWindowViewWidget.h"

MultiWindowViewWidget::MultiWindowViewWidget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::MultiWindowViewWidget)
{
    ui->setupUi(this);
    QPalette pal = QPalette();
    pal.setColor(QPalette::Window, Qt::red);
    this->setAutoFillBackground(true);
    this->setPalette(pal);
    this->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    this->tracedProcessWidget = new TracedProcessWidget(ui->frameUp);
    //ui->frameUp->setLayout(new QVBoxLayout());
    ui->frameUp->layout()->addWidget(this->tracedProcessWidget);
    ui->frameUp->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    pal.setColor(QPalette::Window, Qt::green);
    ui->frameDown->setAutoFillBackground(true);
    ui->frameDown->setPalette(pal);
    ui->frameDown->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    pal.setColor(QPalette::Window, Qt::black);
    ui->splitter->setAutoFillBackground(true);
    ui->splitter->setPalette(pal);
    ui->splitter->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
}

MultiWindowViewWidget::~MultiWindowViewWidget()
{
    delete this->tracedProcessWidget;
    delete ui;
}
