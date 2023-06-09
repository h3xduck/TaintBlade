#ifndef BYTEBUFFERBUTTON_H
#define BYTEBUFFERBUTTON_H

#include <QPushButton>
#include <QWidget>
#include <QString>
#include <QStringList>

namespace PROTOCOL
{
    class ByteBufferPushButton : public QPushButton
    {
        Q_OBJECT
    public:
        enum buttonType_t
        {
            NONE,
            DELIMETER,
            KEYWORD,
            BYTEKEYWORD,
            POINTER
        };

        ByteBufferPushButton(QString text, QWidget* parent, buttonType_t type, int byteIndex);
        ByteBufferPushButton(QString text, QWidget* parent, int byteIndex);

        void joinAdditionalByte(QString text, int byteIndex);

        int& startByte() { return startByte_; }
        int& endByte() { return endByte_; }
        
        buttonType_t& type() { return this->type_; }
        
    private:
        int startByte_ = -1;
        int endByte_ = -1;
        QStringList textList;
        buttonType_t type_;
    };
}

#endif