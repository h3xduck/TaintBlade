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
     * Called when the user double-click on some item of the tree view of the traced processes window.
     * We must load all data from that process if the process execution has finished.
     */
    void treeViewRowDoubleClicked(QModelIndex index);

private:
    Ui::MultiWindowViewWidget *ui;
    TracedProcessWidget* tracedProcessWidget;
};

#endif // MULTIWINDOWVIEWWIDGET_H
