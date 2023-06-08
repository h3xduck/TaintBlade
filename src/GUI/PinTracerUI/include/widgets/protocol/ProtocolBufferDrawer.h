#ifndef PROTOCOLBUFFERDRAWER_H
#define PROTOCOLBUFFERDRAWER_H

#include <QWidget>
#include <QPushButton>
#include <QPropertyAnimation>
#include "widgets/protocol/data/Protocol.h"
#include <memory>

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

    std::shared_ptr<PROTOCOL::Protocol> protocol() { return this->protocol_; }

private:
    Ui::ProtocolBufferDrawer *ui;
    std::shared_ptr<PROTOCOL::Protocol> protocol_;
};

#endif // PROTOCOLBUFFERDRAWER_H
