#ifndef PROTOCOLBUFFERWIDGET_H
#define PROTOCOLBUFFERWIDGET_H

#include <QWidget>
#include <QPushButton>

namespace Ui {
class ProtocolBufferWidget;
}

class ProtocolBufferWidget : public QWidget
{
    Q_OBJECT

public:
    explicit ProtocolBufferWidget(QWidget *parent = nullptr);
    ~ProtocolBufferWidget();

    void addButton();

private:
    Ui::ProtocolBufferWidget *ui;
};

#endif // PROTOCOLBUFFERWIDGET_H
