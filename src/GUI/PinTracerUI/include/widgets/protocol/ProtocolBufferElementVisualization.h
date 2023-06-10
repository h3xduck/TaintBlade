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
    ProtocolBufferElementVisualization(QWidget* parent = nullptr);
    ~ProtocolBufferElementVisualization();

private:
    Ui::ProtocolBufferElementVisualization* ui;
};

#endif 
