#ifndef PROTOCOLBUFFERDRAWER_H
#define PROTOCOLBUFFERDRAWER_H

#include <QWidget>
#include <QPushButton>
#include <QPropertyAnimation>

namespace Ui {
class ProtocolBufferDrawer;
}

class ProtocolBufferDrawer : public QWidget
{
    Q_OBJECT

public:
    ProtocolBufferDrawer(QWidget *parent = nullptr);
    ~ProtocolBufferDrawer();

    void addButton();
    void addProtocolBufferByte(QString byteValue);

private:
    Ui::ProtocolBufferDrawer *ui;
};

#endif // PROTOCOLBUFFERDRAWER_H
