#ifndef MULTIWINDOWVIEWWIDGET_H
#define MULTIWINDOWVIEWWIDGET_H

#include <QWidget>
#include "widgets/process/TracedProcessWidget.h"
#include <QTreeWidgetItem>
#include "utils/exec/ExecutionBridge.h"
#include "utils/db/DatabaseManager.h"
#include <QLayout>
#include "widgets/taint/TaintRoutinesWidget.h"
#include "widgets/trace/TraceFunctionsWidget.h"
#include "widgets/taint/TaintEventsWidget.h"
#include "widgets/protocol/ProtocolVisualizationWidget.h"
#include "widgets/protocol/ProtocolPartsWidget.h"
#include "widgets/protocol/ProtocolBufferElementVisualization.h"

namespace Ui {
class MultiWindowViewWidget;
}

class MultiWindowViewWidget : public QWidget
{
    Q_OBJECT

public:
    explicit MultiWindowViewWidget(QWidget *parent = nullptr);
    ~MultiWindowViewWidget();

    /**
     * Scans the output directory and draws processes data when any is found
     */
    void showTracedProcesses();

    /**
     * Called when the tracer process finishes its execution
     */
    void tracedProcessFinished();

    /**
     * Initializes all widgets that show the result of the tracing, and draw the data on them.
     * For any info to be shown, however, the user needs to double-click in some process of the traced
     * process window.
     */
    void initializeResultWidgets();


public slots:
    /**
     * Called when the user clicks on some item of the tree view of the traced processes window.
     * We must load all data from that process if the process execution has finished.
     */
    void treeViewRowClicked(QModelIndex index);

    /**
    * Called when the protocol parts widget requests to show the data from a certain buffer.
    * This will show the data of the buffer in the protocol visualization widget.
    */
    void selectedProtocolBufferFromWidget(int bufferIndex);

    /**
    * Called when the protocolPartsWidget requests to remark the data of a protocol word.
    * Will highlight the data at the protocolVisualizationWidget. Also switch to filter by word type.
    */
    void selectedProtocolWord(int wordIndex);

    /**
    * Called when the protocolPartsWidget requests to remark the data of a protocol pointer.
    * Will highlight the data at the protocolVisualizationWidget. Also switch to filter by word type.
    */
    void selectedProtocolPointer(int pointerIndex);

    /**
    * Shows (or resets) a widget with information about an specific buffer element (word / pointer)
    * Gets the element from the chosen buffer, at the specified element index. 
    * If isWord, chooses word. Otherwise, interprets it as a pointer field.
    */
    void showProtocolElementVisualizationWidget(int bufferIndex, int elementIndex, bool isWord);

    /**
    * Called when the user requests to highlight a specific byte (or the whole word, if inside a word) 
    * indicated at the protocol visualization widget.
    */
    void selectedHighlightPointedToByte(int byteOffset);

private:
    Ui::MultiWindowViewWidget *ui;
    TracedProcessWidget* tracedProcessWidget;
    ProtocolPartsWidget* protocolPartsWidget;
    ProtocolVisualizationWidget* protocolVisualizationWidget;
    ProtocolBufferElementVisualization* protocolBufferElementVisualizationWidget;
};

#endif // MULTIWINDOWVIEWWIDGET_H
