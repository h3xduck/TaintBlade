#ifndef TRACEFUNCTIONSWIDGET_H
#define TRACEFUNCTIONSWIDGET_H

#include <QWidget>
#include "DatabaseManager.h"
#include <QTreeWidget>

namespace Ui {
class TraceFunctionsWidget;
}

class TraceFunctionsWidget : public QWidget
{
    Q_OBJECT

public:
    explicit TraceFunctionsWidget(QWidget *parent = nullptr);
    ~TraceFunctionsWidget();

private:
    Ui::TraceFunctionsWidget *ui;
};

#endif // TRACEFUNCTIONSWIDGET_H
