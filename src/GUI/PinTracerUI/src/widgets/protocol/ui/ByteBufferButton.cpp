#include "widgets/protocol/ui/ByteBufferButton.h"

PROTOCOL::ByteBufferPushButton::ByteBufferPushButton(QString text, QWidget* parent, buttonType_t type, int byteIndex): QPushButton(text, parent)
{
	this->startByte_ = byteIndex;
	this->endByte_ = byteIndex;
	this->type_ = type;
	this->textList_.append(text);
	this->setFixedSize(30, 90);
	this->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
	this->setText(this->textList_.join(" "));
}

PROTOCOL::ByteBufferPushButton::ByteBufferPushButton(QString text, QWidget* parent, int byteIndex) : QPushButton(text, parent)
{
	this->startByte_ = byteIndex;
	this->endByte_ = byteIndex;
	this->textList_.append(text);
	this->type_ = PROTOCOL::ByteBufferPushButton::TNONE_CNONE;
	this->setFixedSize(30, 90);
	this->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
	this->setText(this->textList_.join(" "));
}

void PROTOCOL::ByteBufferPushButton::joinAdditionalButton(QStringList text, int startIndex, int endIndex)
{
	//Extend the button (and its size and text) according to the introduced byte
	if (this->startByte() > startIndex)
	{
		//Extend it in reverse
		this->startByte() = startIndex;
		QStringList temp = this->textList_;
		this->textList_ = text;
		this->textList_.append(temp);
	}
	else if (this->endByte() < endIndex)
	{
		//Extend it forward
		this->endByte() = endIndex;
		this->textList_.append(text);
	}
	else
	{
		qDebug() << "Tried to expand a button in an unsupported way";
	}

	this->setFixedSize(30*((endByte() - startByte()) +1), 90);
	qDebug() << "Button has been expanded to fit " << endByte() - startByte() + 1 << " elements! From "<<startByte()<<" to "<<endByte();
	this->setText(this->textList_.join("     "));
}