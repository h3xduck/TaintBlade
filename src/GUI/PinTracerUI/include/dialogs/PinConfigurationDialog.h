#ifndef PINCONFIGURATIONDIALOG_H
#define PINCONFIGURATIONDIALOG_H

#include <QDialog>
#include <QLineEdit>
#include <QFileDialog>
#include "common/Globals.h"

QT_BEGIN_NAMESPACE
namespace Ui { class PinConfigurationDialog; }
QT_END_NAMESPACE

class PinConfigurationDialog : public QDialog
{
    //Needed for signals and slots in QT
    Q_OBJECT

public:
    PinConfigurationDialog(QWidget* parent = nullptr);
    ~PinConfigurationDialog();
    void enableOkButtonIfAllDataSet();

private slots:
    void on_outputDirBrowseButton_clicked();

    void on_pinExeBrowseButton_clicked();

    void on_tracerdllBrowseButton_clicked();

    void on_buttonBox_rejected();

    void on_buttonBox_accepted();

private:
    Ui::PinConfigurationDialog *ui;
};

#endif // PINCONFIGURATIONDIALOG_H
