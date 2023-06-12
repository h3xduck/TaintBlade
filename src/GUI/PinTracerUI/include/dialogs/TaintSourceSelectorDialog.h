#ifndef TAINTSOURCESELECTORDIAOG_H
#define TAINTSOURCESELECTORDIAOG_H

#include <QDialog>
#include <QLineEdit>
#include <QFileDialog>
#include "common/Globals.h"
#include <QObject>
#include <QCheckBox>
#include <QMessageBox>
#include <QListWidget>

QT_BEGIN_NAMESPACE
namespace Ui { class TaintSourceSelectorDialog; }
QT_END_NAMESPACE

class TaintSourceSelectorDialog : public QDialog
{
    //Q_OBJECT

public:
    TaintSourceSelectorDialog(QWidget* parent = nullptr);
    ~TaintSourceSelectorDialog();

    void showAvailableTaintSources();
    void addLineToTreeWidget(const QString& dll, const QString& func, const QString& argNum, const QString& arch, const QString& helpLine);

public slots:
    void saveTextContents();

private:
    Ui::TaintSourceSelectorDialog* ui;
};

#endif
