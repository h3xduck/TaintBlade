#ifndef PROTOCOLBUFFERDRAWER_H
#define PROTOCOLBUFFERDRAWER_H

#include <QWidget>
#include <QPushButton>
#include <QPropertyAnimation>
#include "widgets/protocol/data/Protocol.h"
#include <memory>
#include "ui/ByteBufferButton.h"
#include "common/Globals.h"
#include <QGraphicsColorizeEffect>
#include "utils/proto/ProtoUtils.h"

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
    void addProtocolBufferByte(QString byteValue, int byteOffset, float widthMultiplicator = 1, float heightMultiplicator = 1);
    //Puts the protocol data into the widget based on the protocol data gathered from the DB
    void visualizeBufferByWordtype(int bufferIndex);
    //Puts the protocol data into the widget based on the purpose inside the program of the gathered bytes
    void visualizeBufferByPurpose(int bufferIndex);
    //Joins or separates widget buttons based on whether they should be together or not
    void redistributeLayoutButtons();
    //Highlights a button corresponding to a protocol word at index
    void highlightButtonWithProtocolWord(int index);
    //Highlights a button corresponding to a protocol pointer at index
    void highlightButtonWithProtocolPointer(int index);
    //Shows the bytes of a word in the widget
    void visualizeWordBytes(std::shared_ptr<PROTOCOL::ProtocolWord> word);
    //Shows the bytes of a pointer in the widget
    void visualizePointerBytes(std::shared_ptr<PROTOCOL::ProtocolPointer> pointer);

private:
    Ui::ProtocolBufferDrawer *ui;
    int currentBufferIndex = -1;
};

#endif // PROTOCOLBUFFERDRAWER_H
