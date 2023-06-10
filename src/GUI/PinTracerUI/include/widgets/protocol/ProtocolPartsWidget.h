#ifndef PROTOCOLPARTSWIDGET_H
#define PROTOCOLPARTSWIDGET_H

#include <QWidget>
#include "widgets/protocol/data/Protocol.h"
#include "common/Globals.h"
#include <QListWidget>

namespace Ui {
    class ProtocolPartsWidget;
}

class ProtocolPartsWidget : public QWidget
{
    Q_OBJECT

public:
    explicit ProtocolPartsWidget(QWidget* parent = nullptr);
    ~ProtocolPartsWidget();

public slots:
    void onTopListItemClicked(QListWidgetItem*);
    void onMidListItemClicked(QListWidgetItem*);
    void onBotListItemClicked(QListWidgetItem*);

signals:
    void onSelectedProtocolBuffer(int bufferIndex);
    void onSelectedBufferWord(int wordIndex);
    void onSelectedBufferPointer(int pointerIndex);

private:
    Ui::ProtocolPartsWidget* ui;
};


#endif
