#include "widgets/MultiWindowViewWidget.h"
#include "ui_MultiWindowViewWidget.h"

MultiWindowViewWidget::MultiWindowViewWidget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::MultiWindowViewWidget)
{
    ui->setupUi(this);
    GLOBAL_VARS::mainMultiWindowWidget = this;
    this->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    this->layout()->setContentsMargins(0,0,0,0);
    this->tracedProcessWidget = new TracedProcessWidget(ui->frameLeftUpLeft);
    ui->frameLeftUpLeft->layout()->addWidget(this->tracedProcessWidget);
    ui->frameLeftUpLeft->layout()->setContentsMargins(0,0,0,0);
    
    ui->frameLeftUpLeft->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    ui->frameLeftUpRight->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    ui->frameLeftDownRight->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    ui->frameLeftDownLeft->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    ui->frameRightUpLeft->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    ui->frameRightUpRight->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    ui->frameRightDownRight->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    ui->frameRightDownLeft->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    //COLORINGS, set in case you want to visualize each widget
    /*
    QPalette pal = QPalette();
    pal.setColor(QPalette::Window, Qt::red);
    ui->frameLeftUpLeft->setAutoFillBackground(true);
    ui->frameLeftUpLeft->setPalette(pal);
    pal.setColor(QPalette::Window, Qt::green);
    ui->frameLeftUpRight->setAutoFillBackground(true);
    ui->frameLeftUpRight->setPalette(pal);
    pal.setColor(QPalette::Window, Qt::blue);
    ui->frameLeftDownRight->setAutoFillBackground(true);
    ui->frameLeftDownRight->setPalette(pal);
    pal.setColor(QPalette::Window, Qt::gray);
    ui->frameLeftDownLeft->setAutoFillBackground(true);
    ui->frameLeftDownLeft->setPalette(pal);

    pal.setColor(QPalette::Window, Qt::darkRed);
    ui->frameRightUpLeft->setAutoFillBackground(true);
    ui->frameRightUpLeft->setPalette(pal);
    pal.setColor(QPalette::Window, Qt::darkGreen);
    ui->frameRightUpRight->setAutoFillBackground(true);
    ui->frameRightUpRight->setPalette(pal);
    pal.setColor(QPalette::Window, Qt::darkBlue);
    ui->frameRightDownRight->setAutoFillBackground(true);
    ui->frameRightDownRight->setPalette(pal);
    pal.setColor(QPalette::Window, Qt::darkGray);
    ui->frameRightDownLeft->setAutoFillBackground(true);
    ui->frameRightDownLeft->setPalette(pal);
    */

    //Initialize splitters position
    //ui->frameLeftUpLeft->sizePolicy().setHorizontalStretch(1);
    //ui->frameLeftUpRight->sizePolicy().setHorizontalStretch(8);
    ui->level1VSplitter->setSizes(QList<int>() << 300 << 200);
    ui->level2HSplitterLeft->setSizes(QList<int>() << 300 << 200);
    ui->level2HSplitterRight->setSizes(QList<int>() << 200 << 200);
    ui->level3VSplitterLeftUp->setSizes(QList<int>() << 300 << 100);

    //For now, we will delete this widget, since it is not being used
    delete ui->frameRightUpLeft;
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

void MultiWindowViewWidget::treeViewRowClicked(QModelIndex index)
{
    QTreeWidgetItem* item = this->tracedProcessWidget->getItemFromTableView(index);
    qDebug()<<"Clicked traced process, PID: "<<item->text(0);

    //For the clicked item, we will show the rest of windows
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
    GLOBAL_VARS::selectedProcessPID = item->text(0);

    //Now that we are connected to the database, we can draw the rest of windows
    //TODO add here all widgets

    //Taint routines widget. Delete any preious one.
    QLayoutItem *layoutItem;
    if((layoutItem = ui->frameRightDownRight->layout()->takeAt(0)) != NULL)
    {
        delete layoutItem->widget();
        delete layoutItem;
    }
    this->taintRoutinesWidget = new TaintRoutinesWidget(ui->frameRightDownRight);
    ui->frameRightDownRight->layout()->addWidget(this->taintRoutinesWidget);
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

    if ((layoutItem = ui->frameLeftUpRight->layout()->takeAt(0)) != NULL)
    {
        delete layoutItem->widget();
        delete layoutItem;
    }
    //Only deleted elements, the protocol element visualization widget is drawn when the user clicks on a buffer word/pointer


    connect(this->protocolPartsWidget, SIGNAL(onSelectedProtocolBuffer(int)), this, SLOT(selectedProtocolBufferFromWidget(int)));
    connect(this->protocolPartsWidget, SIGNAL(onSelectedBufferWord(int)), this, SLOT(selectedProtocolWord(int)));
    connect(this->protocolPartsWidget, SIGNAL(onSelectedBufferPointer(int)), this, SLOT(selectedProtocolPointer(int)));
    connect(this->protocolVisualizationWidget->bufferDrawerWidget, SIGNAL(signalShowBufferByteContextMenu(std::vector<std::shared_ptr<PROTOCOL::ProtocolByte>>)), 
        this, SLOT(showBufferByteContextMenu(std::vector<std::shared_ptr<PROTOCOL::ProtocolByte>>)));
}


void MultiWindowViewWidget::selectedProtocolBufferFromWidget(int bufferIndex)
{
    //The user clicked on a buffer at the protocolPartsWidget.
    //We must display that buffer at the protocolVisualizationWidget
    this->protocolVisualizationWidget->startProtocolBufferVisualization(bufferIndex);
    GLOBAL_VARS::selectedBufferIndex = bufferIndex;
}

void MultiWindowViewWidget::selectedProtocolWord(int wordIndex)
{
    this->protocolVisualizationWidget->buttonColorByWordTypeClicked();
    this->protocolVisualizationWidget->highlightProtocolWord(wordIndex);
    showProtocolElementVisualizationWidget(GLOBAL_VARS::selectedBufferIndex, wordIndex, true);
}


void MultiWindowViewWidget::selectedProtocolPointer(int pointerIndex)
{
    this->protocolVisualizationWidget->buttonColorByWordTypeClicked();
    this->protocolVisualizationWidget->highlightProtocolPointer(pointerIndex);
    showProtocolElementVisualizationWidget(GLOBAL_VARS::selectedBufferIndex, pointerIndex, false);
}

void MultiWindowViewWidget::showProtocolElementVisualizationWidget(int bufferIndex, int elementIndex, bool isWord)
{
    QLayoutItem* layoutItem;
    if ((layoutItem = ui->frameLeftUpRight->layout()->takeAt(0)) != NULL)
    {
        delete layoutItem->widget();
        delete layoutItem;
    }

    //Before constructing the widget, we get the element we will pass to it
    if (isWord)
    {
        std::shared_ptr<PROTOCOL::ProtocolWord> word = GLOBAL_VARS::globalProtocol.get()->bufferVector().at(bufferIndex).get()->wordVector().at(elementIndex);
        this->protocolBufferElementVisualizationWidget = new ProtocolBufferElementVisualization(word, ui->frameLeftUpRight);
    }
    else
    {
        std::shared_ptr<PROTOCOL::ProtocolPointer> pointer = GLOBAL_VARS::globalProtocol.get()->bufferVector().at(bufferIndex).get()->pointerVector().at(elementIndex);
        this->protocolBufferElementVisualizationWidget = new ProtocolBufferElementVisualization(pointer, ui->frameLeftUpRight);
    }

    ui->frameLeftUpRight->layout()->addWidget(this->protocolBufferElementVisualizationWidget);
    ui->frameLeftUpRight->layout()->setContentsMargins(0, 0, 0, 0);
    connect(this->protocolBufferElementVisualizationWidget, SIGNAL(onPointedByteHighlighButtonClicked(int)), this, SLOT(selectedHighlightPointedToByte(int)));
    connect(this->protocolBufferElementVisualizationWidget, SIGNAL(showTreeWidgetContextMenu(const QPoint&, QTreeWidget*)), this, SLOT(showHighlightColorByteContextMenu(const QPoint&, QTreeWidget*)));
}

void MultiWindowViewWidget::selectedHighlightPointedToByte(int byteOffset)
{
    this->protocolVisualizationWidget->buttonColorByWordTypeClicked();
    this->protocolVisualizationWidget->highlightProtocolByte(byteOffset);
}

void MultiWindowViewWidget::showHighlightColorByteContextMenu(const QPoint& pos, QTreeWidget* treeWidget)
{
    //Connect the specific row clicked by the user to the action of highlighting the color of that row
    QTreeWidgetItem* item = treeWidget->itemAt(pos);
    qDebug() << "Requested to highlight color byte at pos " << pos << " with color " << item->text(2);
    
    QAction* newAct = new QAction(QIcon(":/res/res/icons8-external-link-26.png"), "Highlight parent colors", this);
    connect(newAct, &QAction::triggered, this, [this, item] {selectedProtocolColor(item->text(2).toInt()); });


    QMenu menu(this);
    menu.addAction(newAct);

    QPoint pt(pos);
    menu.exec(treeWidget->mapToGlobal(pos));
}

void MultiWindowViewWidget::showBufferByteContextMenu(std::vector<std::shared_ptr<PROTOCOL::ProtocolByte>> byteVec)
{
    //We will take the function responsible of the taint lead here
    PROTOCOL::ProtocolByte::taint_lead_t lead;
    //Any byte will do, they belong to the same function
    //TODO - allow for bytes having multiple taint leads
    lead = byteVec.at(0).get()->taintLead();
    qDebug() << "Requested to highlight the taint routine named " << lead.funcName;
    this->taintRoutinesWidget->highlightTaintRoutineByLead(lead);
}

void MultiWindowViewWidget::selectedProtocolColor(int color)
{
    //We will have to find all parents of this color to be highlighted
    std::vector<int> originalParentColors = globalDBManager.getColorParentsListFromColor(color);
    //We add the color itself too
    originalParentColors.push_back(color);

    //For every color we've got, we will highlight them in the buffer visualization widget
    selectedHighlightBytesWithColors(originalParentColors);
}

void MultiWindowViewWidget::selectedHighlightBytesWithColors(std::vector<int> colorVector)
{
    this->protocolVisualizationWidget->buttonColorByWordTypeClicked();

    //We take the offset in the currently selected buffer that corresponds to each color
    std::vector<int> offsetVec;
    std::shared_ptr<PROTOCOL::ProtocolBuffer> buffer = GLOBAL_VARS::globalProtocol.get()->bufferVector().at(GLOBAL_VARS::selectedBufferIndex);
    for (int color : colorVector)
    {
        int offset = buffer.get()->getOffsetOfColor(color);
        if (offset != -1)
        {
            offsetVec.push_back(offset);
        }
    }

    this->protocolVisualizationWidget->highlightProtocolBytes(offsetVec);
}