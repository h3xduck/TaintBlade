#ifndef NOPSECTIONSELECTORDIALOG_H
#define NOPSECTIONSELECTORDIALOG_H

#include <QDialog>
#include <QLineEdit>
#include <QFileDialog>
#include "common/Globals.h"
#include <QObject>
#include <QTreeWidget>

QT_BEGIN_NAMESPACE
namespace Ui { class NopSectionSelectorDialog; }
QT_END_NAMESPACE

class NopSectionSelectorDialog : public QDialog
{
    //Q_OBJECT

public:
    NopSectionSelectorDialog(QWidget* parent = nullptr);
    ~NopSectionSelectorDialog();

    void addLineToTreeWidget(const QString& dll, const QString& func, const QString& numArgs);

public slots:
    void saveTextContents();

private:
    Ui::NopSectionSelectorDialog* ui;
};

#endif
