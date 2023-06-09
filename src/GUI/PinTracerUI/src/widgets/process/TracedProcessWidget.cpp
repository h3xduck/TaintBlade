#include "widgets/process/TracedProcessWidget.h"
#include "ui_TracedProcessWidget.h"
#include <QDebug>

TracedProcessWidget::TracedProcessWidget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::tracedProcessWidget)
{
    ui->setupUi(this);
    //QPalette pal = QPalette();
    //pal.setColor(QPalette::Window, Qt::blue);
    //this->setAutoFillBackground(true);
    //this->setPalette(pal);
    this->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    ui->treeWidget->setColumnCount(3);
    ui->treeWidget->setContextMenuPolicy(Qt::CustomContextMenu);

    QStringList headers;
    headers << "PID" << "PROCESS BINARY" << "START TIME";
    ui->treeWidget->setHeaderLabels(headers);
    //Connect the double-click event to a slot at the parent. Note that we've got a frame and splitters in the middle... a bit dirty but works :)
    connect(ui->treeWidget, SIGNAL(doubleClicked(QModelIndex)), this->parentWidget()->parentWidget()->parentWidget()->parentWidget()->parentWidget(), SLOT(treeViewRowDoubleClicked(QModelIndex)));
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
    QTreeWidgetItem* item = new QTreeWidgetItem();
    QDateTime timestampDate;
    timestampDate = QDateTime::fromSecsSinceEpoch(timestamp.toInt());
    item->setText(0, pid);
    item->setText(1, dll);
    item->setText(2, timestampDate.toString("hh:mm:ss"));
    ui->treeWidget->addTopLevelItem(item);
    ui->treeWidget->resizeColumnToContents(0);
    ui->treeWidget->resizeColumnToContents(1);
    ui->treeWidget->resizeColumnToContents(2);
    ui->treeWidget->scrollToItem(item);
}

void TracedProcessWidget::endTracedProcess()
{
    //We terminate the drawer thread
    this->processDrawer->terminate();
}

QTreeWidgetItem* TracedProcessWidget::getItemFromTableView(QModelIndex index)
{
    return  ui->treeWidget->itemFromIndex(index);
}