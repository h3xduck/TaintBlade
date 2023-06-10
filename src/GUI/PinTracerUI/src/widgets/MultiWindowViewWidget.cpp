#include "widgets/MultiWindowViewWidget.h"
#include "ui_MultiWindowViewWidget.h"

MultiWindowViewWidget::MultiWindowViewWidget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::MultiWindowViewWidget)
{
    ui->setupUi(this);
    this->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    this->layout()->setContentsMargins(0,0,0,0);
    this->tracedProcessWidget = new TracedProcessWidget(ui->frameLeftUpLeft);
    ui->frameLeftUpLeft->layout()->addWidget(this->tracedProcessWidget);
    ui->frameLeftUpLeft->layout()->setContentsMargins(0,0,0,0);

    QPalette pal = QPalette();
    pal.setColor(QPalette::Window, Qt::red);
    ui->frameLeftUpLeft->setAutoFillBackground(true);
    ui->frameLeftUpLeft->setPalette(pal);
    ui->frameLeftUpLeft->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    pal.setColor(QPalette::Window, Qt::green);
    ui->frameLeftUpRight->setAutoFillBackground(true);
    ui->frameLeftUpRight->setPalette(pal);
    ui->frameLeftUpRight->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    pal.setColor(QPalette::Window, Qt::blue);
    ui->frameLeftDownRight->setAutoFillBackground(true);
    ui->frameLeftDownRight->setPalette(pal);
    ui->frameLeftDownRight->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    pal.setColor(QPalette::Window, Qt::gray);
    ui->frameLeftDownLeft->setAutoFillBackground(true);
    ui->frameLeftDownLeft->setPalette(pal);
    ui->frameLeftDownLeft->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    pal.setColor(QPalette::Window, Qt::darkRed);
    ui->frameRightUpLeft->setAutoFillBackground(true);
    ui->frameRightUpLeft->setPalette(pal);
    ui->frameRightUpLeft->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    pal.setColor(QPalette::Window, Qt::darkGreen);
    ui->frameRightUpRight->setAutoFillBackground(true);
    ui->frameRightUpRight->setPalette(pal);
    ui->frameRightUpRight->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    pal.setColor(QPalette::Window, Qt::darkBlue);
    ui->frameRightDownRight->setAutoFillBackground(true);
    ui->frameRightDownRight->setPalette(pal);
    ui->frameRightDownRight->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    pal.setColor(QPalette::Window, Qt::darkGray);
    ui->frameRightDownLeft->setAutoFillBackground(true);
    ui->frameRightDownLeft->setPalette(pal);
    ui->frameRightDownLeft->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    //Initialize splitters position
    //ui->frameLeftUpLeft->sizePolicy().setHorizontalStretch(1);
    //ui->frameLeftUpRight->sizePolicy().setHorizontalStretch(8);
    ui->level1VSplitter->setSizes(QList<int>() << 300 << 200);
    ui->level2HSplitterLeft->setSizes(QList<int>() << 300 << 200);
    ui->level2HSplitterRight->setSizes(QList<int>() << 200 << 200);
    ui->level3VSplitterLeftUp->setSizes(QList<int>() << 300 << 100);
}

MultiWindowViewWidget::~MultiWindowViewWidget()
{
    delete ui;
}

void MultiWindowViewWidget::showTracedProcesses()
{
    this->tracedProcessWidget->showTracedProcess();
}

void MultiWindowViewWidget::tracedProcessFinished()
{
    //First, we tell the drawer window to stop showing more processes
    this->tracedProcessWidget->endTracedProcess();

    //Now, we will enable the user to query all data and show the rest of widgets
    initializeResultWidgets();
}

void MultiWindowViewWidget::initializeResultWidgets()
{
    qDebug()<<"Requested to initiliaze all result widgets";
    //TODO change colors or something
}

void MultiWindowViewWidget::treeViewRowDoubleClicked(QModelIndex index)
{
    QTreeWidgetItem* item = this->tracedProcessWidget->getItemFromTableView(index);
    qDebug()<<"Double-clicked traced process, PID: "<<item->text(0);

    //For the double-clicked item, we will show the rest of windows
    //First check that the tracing process has already finished, otherwise let's try not to be
    if(EXECUTION::tracerProcessRunning())
    {
        qDebug()<<"Did not show widgets, process still running";
        return;
    }

    //Start a connection to the DB corresponding to the selected process
    int ret = globalDBManager.initializeDatabase(GLOBAL_VARS::selectedOutputDirPath+"/"+item->text(0)+"_dump.db");
    if(ret !=0)
    {
        return;
    }

    //Now that we are connected to the database, we can draw the rest of windows
    //TODO add here all widgets

    //Taint routines widget. Delete any preious one.
    QLayoutItem *layoutItem;
    if((layoutItem = ui->frameRightDownRight->layout()->takeAt(0)) != NULL)
    {
        delete layoutItem->widget();
        delete layoutItem;
    }
    ui->frameRightDownRight->layout()->addWidget(new TaintRoutinesWidget(ui->frameRightDownRight));
    ui->frameRightDownRight->layout()->setContentsMargins(0,0,0,0);

    //Trace functions widget. Delete any preious one.
    if((layoutItem = ui->frameRightDownLeft->layout()->takeAt(0)) != NULL)
    {
        delete layoutItem->widget();
        delete layoutItem;
    }
    ui->frameRightDownLeft->layout()->addWidget(new TraceFunctionsWidget(ui->frameRightDownLeft));
    ui->frameRightDownLeft->layout()->setContentsMargins(0,0,0,0);

    //Taint events widget. Delete any preious one.
    if((layoutItem = ui->frameRightUpRight->layout()->takeAt(0)) != NULL)
    {
        delete layoutItem->widget();
        delete layoutItem;
    }
    ui->frameRightUpRight->layout()->addWidget(new TaintEventsWidget(ui->frameRightUpRight));
    ui->frameRightUpRight->layout()->setContentsMargins(0,0,0,0);

    //Protocol widgets. Include buffers and other displays
    if((layoutItem = ui->frameLeftDownRight->layout()->takeAt(0)) != NULL)
    {
        delete layoutItem->widget();
        delete layoutItem;
    }
    this->protocolVisualizationWidget = new ProtocolVisualizationWidget(ui->frameLeftDownRight);
    ui->frameLeftDownRight->layout()->addWidget(this->protocolVisualizationWidget);
    ui->frameLeftDownRight->layout()->setContentsMargins(0,0,0,0);
    if ((layoutItem = ui->frameLeftDownLeft->layout()->takeAt(0)) != NULL)
    {
        delete layoutItem->widget();
        delete layoutItem;
    }
    this->protocolPartsWidget = new ProtocolPartsWidget(ui->frameLeftDownLeft);
    ui->frameLeftDownLeft->layout()->addWidget(this->protocolPartsWidget);
    ui->frameLeftDownLeft->layout()->setContentsMargins(0, 0, 0, 0);
    connect(this->protocolPartsWidget, SIGNAL(onSelectedProtocolBuffer(int)), this, SLOT(selectedProtocolBufferFromWidget(int)));
    connect(this->protocolPartsWidget, SIGNAL(onSelectedBufferWord(int)), this, SLOT(selectedProtocolWord(int)));
    connect(this->protocolPartsWidget, SIGNAL(onSelectedBufferPointer(int)), this, SLOT(selectedProtocolPointer(int)));

}


void MultiWindowViewWidget::selectedProtocolBufferFromWidget(int bufferIndex)
{
    //The user clicked on a buffer at the protocolPartsWidget.
    //We must display that buffer at the protocolVisualizationWidget
    this->protocolVisualizationWidget->startProtocolBufferVisualization(bufferIndex);
}

void MultiWindowViewWidget::selectedProtocolWord(int wordIndex)
{
    this->protocolVisualizationWidget->buttonColorByWordTypeClicked();
    this->protocolVisualizationWidget->highlightProtocolWord(wordIndex);
}


void MultiWindowViewWidget::selectedProtocolPointer(int pointerIndex)
{
    this->protocolVisualizationWidget->buttonColorByWordTypeClicked();
    this->protocolVisualizationWidget->highlightProtocolPointer(pointerIndex);
}
