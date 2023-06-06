#ifndef PROTOCOLVISUALIZATIONWIDGET_H
#define PROTOCOLVISUALIZATIONWIDGET_H

#include <QWidget>
#include "ProtocolBufferWidget.h"

namespace Ui {
class ProtocolVisualizationWidget;
}

class ProtocolVisualizationWidget : public QWidget
{
    Q_OBJECT

public:
    explicit ProtocolVisualizationWidget(QWidget *parent = nullptr);
    ~ProtocolVisualizationWidget();

private:
    Ui::ProtocolVisualizationWidget *ui;
    QWidget *contentWidget;
};

#endif // PROTOCOLVISUALIZATIONWIDGET_H
