#ifndef TRACEDFUNCTIONSWIDGET_H
#define TRACEDFUNCTIONSWIDGET_H

#include <QWidget>

namespace Ui {
class TracedFunctionsWidget;
}

class TracedFunctionsWidget : public QWidget
{
    Q_OBJECT

public:
    explicit TracedFunctionsWidget(QWidget *parent = nullptr);
    ~TracedFunctionsWidget();

private:
    Ui::TracedFunctionsWidget *ui;
};

#endif // TRACEDFUNCTIONSWIDGET_H
