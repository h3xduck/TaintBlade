#ifndef PROTOCOLBUFFERELEMENTVISUALIZATION_H
#define PROTOCOLBUFFERELEMENTVISUALIZATION_H

#include <QWidget>
#include <QPushButton>
#include "widgets/protocol/data/Protocol.h"
#include <memory>
#include "ui/ByteBufferButton.h"
#include "common/Globals.h"
#include "widgets/protocol/ProtocolBufferDrawer.h"
#include <QPoint>
#include <QTreeWidget>

namespace Ui {
    class ProtocolBufferElementVisualization;
}

class ProtocolBufferElementVisualization : public QWidget
{
    Q_OBJECT

public:
    ProtocolBufferElementVisualization(std::shared_ptr<PROTOCOL::ProtocolWord> word, QWidget* parent = nullptr);
    ProtocolBufferElementVisualization(std::shared_ptr<PROTOCOL::ProtocolPointer> pointer, QWidget* parent = nullptr);
    ~ProtocolBufferElementVisualization();

    void setupByteTreeWidgetContextMenu();

signals:
    void onPointedByteHighlighButtonClicked(int byteOffset);
    void showTreeWidgetContextMenu(const QPoint& point, QTreeWidget* treeWidget);

private slots:
    void buttonRequestHighlightPointedToByte();
    void sendRequestShowTreeWidgetContextMenu(const QPoint& point);

private:
    Ui::ProtocolBufferElementVisualization* ui;
    QWidget* contentWidget;
    ProtocolBufferDrawer* bufferDrawerWidget;
    std::shared_ptr<PROTOCOL::ProtocolByte> pointedToByte;
};

#endif 
