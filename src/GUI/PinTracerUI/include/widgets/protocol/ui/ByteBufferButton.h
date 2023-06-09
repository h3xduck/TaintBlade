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
        //Either a Type or a Class, depending on whether the buffer is shown by word type or by purpose (taint lead)
        enum buttonType_t
        {
            TNONE_CNONE,
            TDELIMETER_CTAINTSINK,
            TKEYWORD,
            TBYTEKEYWORD,
            TPOINTER
        };

        ByteBufferPushButton(QString text, QWidget* parent, buttonType_t type, int byteIndex);
        ByteBufferPushButton(QString text, QWidget* parent, int byteIndex);

        void joinAdditionalButton(QStringList text, int startIndex, int endIndex);

        int& startByte() { return startByte_; }
        int& endByte() { return endByte_; }
        QStringList& textList() { return this->textList_; }
        
        buttonType_t& type() { return this->type_; }
        
    private:
        int startByte_ = -1;
        int endByte_ = -1;
        QStringList textList_;
        buttonType_t type_;
    };
}

#endif