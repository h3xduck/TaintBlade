#ifndef BYTEBUFFERBUTTON_H
#define BYTEBUFFERBUTTON_H

#include <QPushButton>
#include <QWidget>

namespace PROTOCOL
{
    class ByteBufferPushButton : public QPushButton
    {
        Q_OBJECT
    public:
        ByteBufferPushButton(int byteIndex);

        int& startByte() { return startByte_; }
        int& endByte() { return endByte_; }
    private:
        int startByte_ = -1;
        int endByte_ = -1;
    };
}

#endif