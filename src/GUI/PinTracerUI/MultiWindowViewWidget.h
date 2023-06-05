#ifndef MULTIWINDOWVIEWWIDGET_H
#define MULTIWINDOWVIEWWIDGET_H

#include <QWidget>
#include "TracedProcessWidget.h"
#include <QTreeWidgetItem>
#include "ExecutionBridge.h"
#include "DatabaseManager.h"
#include <QLayout>

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
