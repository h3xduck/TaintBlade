#ifndef MULTIWINDOWVIEWWIDGET_H
#define MULTIWINDOWVIEWWIDGET_H

#include <QWidget>
#include "TracedProcessWidget.h"

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

private:
    Ui::MultiWindowViewWidget *ui;
    TracedProcessWidget* tracedProcessWidget;
};

#endif // MULTIWINDOWVIEWWIDGET_H
