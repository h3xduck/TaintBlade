#include "widgets/protocol/ui/ByteBufferButton.h"

PROTOCOL::ByteBufferPushButton::ByteBufferPushButton(QString text, QWidget* parent, buttonType_t type, int byteIndex): QPushButton(text, parent)
{
	this->startByte_ = byteIndex;
	this->endByte_ = byteIndex;
	this->type_ = type;
	this->textList.append(text);
	this->setFixedSize(30, 90);
	this->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
	this->setText(this->textList.join(" "));
}

PROTOCOL::ByteBufferPushButton::ByteBufferPushButton(QString text, QWidget* parent, int byteIndex) : QPushButton(text, parent)
{
	this->startByte_ = byteIndex;
	this->endByte_ = byteIndex;
	this->textList.append(text);
	this->type_ = PROTOCOL::ByteBufferPushButton::NONE;
	this->setFixedSize(30, 90);
	this->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
	this->setText(this->textList.join(" "));
}

void PROTOCOL::ByteBufferPushButton::joinAdditionalByte(QString text, int byteIndex)
{
	//Extend the button (and its size and text) according to the introduced byte
	if (this->startByte() > byteIndex)
	{
		//Extend it in reverse
		this->startByte() = byteIndex;
		this->textList.prepend(text);
	}
	else if (this->startByte() < byteIndex)
	{
		//Extend it forward
		this->endByte() = byteIndex;
		this->textList.append(text);
	}
	else
	{
		//Substitute the value of the byte at that position
		this->textList[endByte() - startByte()] = text;
	}

	this->setFixedSize(30*((endByte() - startByte()) +1), 90);
	this->setText(this->textList.join(" "));
}