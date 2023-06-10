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
        Q_PROPERTY(QColor color READ getColor WRITE setColor)
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
        ByteBufferPushButton(QString text, QWidget* parent, int byteIndex, int protocolElementIndex);

        void joinAdditionalButton(QStringList text, int startIndex, int endIndex);

        int& startByte() { return startByte_; }
        int& endByte() { return endByte_; }
        QStringList& textList() { return this->textList_; }
        int getInternalByteSize() { return this->endByte_ - this->startByte_ + 1; }
        buttonType_t& type() { return this->type_; }
        int& protocolElementIndex() { return this->protocolElementIndex_; }

        void setColor(QColor color) {
            QString styleSheet = QString(" QPushButton { background-color: rgb(%1, %2, %3);"
                "border-style: outset; "
                "border-width: 2px; "
                "border-radius: 0px; "
                "border-color: black; "
                "padding: 4px; }"
            ).arg(color.red()).arg(color.green()).arg(color.blue());
            this->setStyleSheet(styleSheet);
            qDebug() << "R:" << color.red() << " G:" << color.green() << " B:" << color.blue()<<" STYLE: "<<styleSheet;
            this->color_ = color;
        }
        QColor getColor() { return this->color_; }
        
    private:
        int startByte_ = -1;
        int endByte_ = -1;
        QStringList textList_;
        buttonType_t type_;
        int protocolElementIndex_ = -1;
        QColor color_;
    };
}

#endif