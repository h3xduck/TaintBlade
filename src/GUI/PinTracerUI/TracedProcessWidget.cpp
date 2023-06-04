#include "TracedProcessWidget.h"
#include "ui_TracedProcessWidget.h"
#include <QDebug>

TracedProcessWidget::TracedProcessWidget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::tracedProcessWidget)
{
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

void TracedProcessWidget::showTracedProcess()
{
    this->processDrawer = new TracedProcessDrawer();
    //Register a slot for receiving the data whenever the thread find some new traced process to show
    connect(this->processDrawer, SIGNAL(sendRequestShowTracedProcessWidget(QString, QString, QString)), this, SLOT(drawTracedProgramWidget(QString, QString, QString)));
    //Start the thread that looks for traced processes
    this->processDrawer->start();
}

void TracedProcessWidget::drawTracedProgramWidget(QString pid, QString dll, QString timestamp)
{
    qDebug()<<"Received signal PID:"<<pid<<" DLL:"<<dll<<" TIME:"<<timestamp;

    //We will draw the data into the list (which is a tree btw, for aesthetic reasons)

}

void TracedProcessWidget::endTracedProcess()
{
    //We terminate the drawer thread
    this->processDrawer->terminate();
}
