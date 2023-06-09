#ifndef PROTOCOLVISUALIZATIONWIDGET_H
#define PROTOCOLVISUALIZATIONWIDGET_H

#include <QWidget>
#include "widgets/protocol/ProtocolBufferDrawer.h"
#include "utils/db/DatabaseManager.h"

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

private:
    Ui::ProtocolVisualizationWidget *ui;
    QWidget *contentWidget;
    ProtocolBufferDrawer* bufferDrawerWidget;
};

#endif // PROTOCOLVISUALIZATIONWIDGET_H
