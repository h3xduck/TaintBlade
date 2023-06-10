#ifndef PROTOCOLBUFFERELEMENTVISUALIZATION_H
#define PROTOCOLBUFFERELEMENTVISUALIZATION_H

#include <QWidget>
#include <QPushButton>
#include "widgets/protocol/data/Protocol.h"
#include <memory>
#include "ui/ByteBufferButton.h"
#include "common/Globals.h"

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

private:
    Ui::ProtocolBufferElementVisualization* ui;
};

#endif 
