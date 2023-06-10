#ifndef PROTOCOLVISUALIZATIONWIDGET_H
#define PROTOCOLVISUALIZATIONWIDGET_H

#include <QWidget>
#include "widgets/protocol/ProtocolBufferDrawer.h"
#include "utils/db/DatabaseManager.h"
#include <QFile>
#include <QMessageBox>
#include <QTextEdit>

namespace Ui {
class ProtocolVisualizationWidget;
}

class ProtocolVisualizationWidget : public QWidget
{
    Q_OBJECT

public:
    explicit ProtocolVisualizationWidget(QWidget *parent = nullptr);
    ~ProtocolVisualizationWidget();

    void startProtocolBufferVisualization(int bufferIndex);
    void highlightProtocolWord(int wordIndex);
    void highlightProtocolPointer(int pointerIndex);
    void highlightProtocolByte(int byteOffset);

public slots:
    void buttonColorByWordTypeClicked();
    void buttonColorByPurposeClicked();
    void buttonViewRawProtocolClicked();

private:
    Ui::ProtocolVisualizationWidget *ui;
    QWidget *contentWidget;
    ProtocolBufferDrawer* bufferDrawerWidget;
    int currentlyVisualizedBufferIndex = -1;
};

#endif // PROTOCOLVISUALIZATIONWIDGET_H
