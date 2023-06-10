#include "widgets/protocol/ProtocolVisualizationWidget.h"
#include "ui_ProtocolVisualizationWidget.h"

ProtocolVisualizationWidget::ProtocolVisualizationWidget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::ProtocolVisualizationWidget)
{
    ui->setupUi(this);

    //The visualization is a row of buttons next to the other
    //We add a content widget to center the elements in the scrollarea
    this->contentWidget = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(contentWidget);
    ui->scrollArea->setWidget(contentWidget);

    this->bufferDrawerWidget = new ProtocolBufferDrawer(this);
    layout->addWidget(this->bufferDrawerWidget);
    layout->setAlignment(Qt::AlignCenter);

    connect(ui->buttonColorWordType, SIGNAL(clicked()), this, SLOT(buttonColorByWordTypeClicked()));
    connect(ui->buttonColorPurpose, SIGNAL(clicked()), this, SLOT(buttonColorByPurposeClicked()));

    globalDBManager.loadProtocolData(this->bufferDrawerWidget);

    //If we click the viewrawprotocol button, we display a dialog with the full protocol data
    connect(ui->viewRawProtocolButton, SIGNAL(clicked()), this, SLOT(buttonViewRawProtocolClicked()));
}

ProtocolVisualizationWidget::~ProtocolVisualizationWidget()
{
    delete ui;
}

void ProtocolVisualizationWidget::startProtocolBufferVisualization(int bufferIndex)
{
    this->bufferDrawerWidget->visualizeBufferByWordtype(bufferIndex);
    currentlyVisualizedBufferIndex = bufferIndex;
}

void ProtocolVisualizationWidget::buttonColorByWordTypeClicked()
{
    if (this->currentlyVisualizedBufferIndex == -1) return;
    this->bufferDrawerWidget->visualizeBufferByWordtype(this->currentlyVisualizedBufferIndex);
}

void ProtocolVisualizationWidget::buttonColorByPurposeClicked()
{
    if (this->currentlyVisualizedBufferIndex == -1) return;
    this->bufferDrawerWidget->visualizeBufferByPurpose(this->currentlyVisualizedBufferIndex);
}

void ProtocolVisualizationWidget::highlightProtocolWord(int wordIndex)
{
    if (this->currentlyVisualizedBufferIndex == -1) return;
    this->bufferDrawerWidget->highlightButtonWithProtocolWord(wordIndex);
}

void ProtocolVisualizationWidget::highlightProtocolPointer(int pointerIndex)
{
    if (this->currentlyVisualizedBufferIndex == -1) return;
    this->bufferDrawerWidget->highlightButtonWithProtocolPointer(pointerIndex);
}

void ProtocolVisualizationWidget::buttonViewRawProtocolClicked()
{
    //We will open the file PID_protocol.dfx and put it on a dialog
    QFile file(GLOBAL_VARS::selectedOutputDirPath + "/" + GLOBAL_VARS::selectedProcessPID + "_" + "protocol.dfx");
    qDebug() << "Reading raw protocol data from file " << file.fileName();
    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream in(&file);
        QString fileContent = in.readAll();
        file.close();

        QDialog dialog(this);
        dialog.setWindowTitle("Raw protocol data");
        dialog.setMinimumSize(400, 300);
        QVBoxLayout layout(&dialog);
        QTextEdit textEdit(&dialog);
        textEdit.setText(fileContent);
        textEdit.setReadOnly(true);
        layout.addWidget(&textEdit);
        dialog.exec();
    }
    else {
        QMessageBox::critical(this, "Error", "Could not open the protocol data file.");
    }
}

void ProtocolVisualizationWidget::highlightProtocolByte(int byteOffset)
{
    if (this->currentlyVisualizedBufferIndex == -1) return;
    this->bufferDrawerWidget->highlightButtonWithProtocolByte(byteOffset);
}