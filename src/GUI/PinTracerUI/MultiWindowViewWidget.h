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

private:
    Ui::MultiWindowViewWidget *ui;
    TracedProcessWidget* tracedProcessWidget;
};

#endif // MULTIWINDOWVIEWWIDGET_H
