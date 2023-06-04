#ifndef TRACEDPROCESSWIDGET_H
#define TRACEDPROCESSWIDGET_H

#include <QWidget>

namespace Ui {
class tracedProcessWidget;
}

class TracedProcessWidget : public QWidget
{
    Q_OBJECT

public:
    explicit TracedProcessWidget(QWidget *parent = nullptr);
    ~TracedProcessWidget();

private:
    Ui::tracedProcessWidget *ui;
};

#endif // TRACEDPROCESSWIDGET_H
