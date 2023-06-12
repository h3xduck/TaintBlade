#ifndef TRACEPOINTSELECTORDIALOG_H
#define TRACEPOINTSELECTORDIALOG_H

#include <QDialog>
#include <QLineEdit>
#include <QFileDialog>
#include "common/Globals.h"
#include <QObject>
#include <QTreeWidget>
#include <QRegularExpression>

QT_BEGIN_NAMESPACE
namespace Ui { class TracePointSelectorDialog; }
QT_END_NAMESPACE

class TracePointSelectorDialog : public QDialog
{
    //Q_OBJECT

public:
    TracePointSelectorDialog(QWidget* parent = nullptr);
    ~TracePointSelectorDialog();

    void addLineToTreeWidget(const QString& dll, const QString& func, const QString& numArgs);

public slots:
    void saveTextContents();

private:
    Ui::TracePointSelectorDialog* ui;
};

#endif
