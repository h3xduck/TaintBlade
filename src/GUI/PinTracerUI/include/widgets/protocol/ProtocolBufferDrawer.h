#ifndef PROTOCOLBUFFERDRAWER_H
#define PROTOCOLBUFFERDRAWER_H

#include <QWidget>
#include <QPushButton>
#include <QPropertyAnimation>
#include "widgets/protocol/data/Protocol.h"
#include <memory>
#include "ui/ByteBufferButton.h"

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
    void addProtocolBufferByte(QString byteValue, int byteOffset);
    //Puts the protocol data into the widget based on the protocol data gathered from the DB
    void visualizeBufferByWordtype(int bufferIndex);
    //Puts the protocol data into the widget based on the purpose inside the program of the gathered bytes
    void visualizeBufferByPurpose(int bufferIndex);
    //Joins or separates widget buttons based on whether they should be together or not
    void redistributeLayoutButtons();

    std::shared_ptr<PROTOCOL::Protocol> protocol() { return this->protocol_; }

private:
    Ui::ProtocolBufferDrawer *ui;
    std::shared_ptr<PROTOCOL::Protocol> protocol_;
};

#endif // PROTOCOLBUFFERDRAWER_H
