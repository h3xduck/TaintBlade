#ifndef DLLSELECTORDIAOG_H
#define DLLSELECTORDIAOG_H

#include <QDialog>
#include <QLineEdit>
#include <QFileDialog>
#include "common/Globals.h"
#include <QObject>

QT_BEGIN_NAMESPACE
namespace Ui { class DLLSelectorDialog; }
QT_END_NAMESPACE

class DLLSelectorDialog : public QDialog
{
    //Q_OBJECT

public:
    DLLSelectorDialog(QWidget* parent = nullptr);
    ~DLLSelectorDialog();

public slots:
    void saveTextContents();

private:
    Ui::DLLSelectorDialog* ui;
};

#endif
