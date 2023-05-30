#include "PinconfigurationDialog.h"
#include "./ui_PinConfigurationDialog.h"

PinConfigurationDialog::PinConfigurationDialog(QWidget* parent)
    : QDialog(parent)
    , ui(new Ui::PinConfigurationDialog)
{
    //OK button not enabled initially until all options set
    ui->setupUi(this);
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
}

PinConfigurationDialog::~PinConfigurationDialog()
{

}

void PinConfigurationDialog::enableOkButtonIfAllDataSet()
{
    if(!ui->outputDirLineEdit->text().isEmpty() &&
        !ui->pinExeLineEdit->text().isEmpty() &&
        !ui->tracerdllLineEdit->text().isEmpty())
    {
        //We activate the button if all options are set
        ui->buttonBox->buttons().at(0)->setEnabled(true);
    }
}

void PinConfigurationDialog::on_outputDirBrowseButton_clicked()
{
    QString selectedPath = QFileDialog::getExistingDirectory(this, "Select output directory");
    if(!selectedPath.isEmpty())
    {
        ui->outputDirLineEdit->setText(selectedPath);
    }
    enableOkButtonIfAllDataSet();
}


void PinConfigurationDialog::on_pinExeBrowseButton_clicked()
{
    QString selectedPath = QFileDialog::getOpenFileName(this, "Select file");
    if(!selectedPath.isEmpty())
    {
        ui->pinExeLineEdit->setText(selectedPath);
    }
    enableOkButtonIfAllDataSet();
}


void PinConfigurationDialog::on_tracerdllBrowseButton_clicked()
{
    QString selectedPath = QFileDialog::getOpenFileName(this, "Select file");
    if(!selectedPath.isEmpty())
    {
        ui->tracerdllLineEdit->setText(selectedPath);
    }
    enableOkButtonIfAllDataSet();
}

void PinConfigurationDialog::on_buttonBox_rejected()
{
    reject();
}

void PinConfigurationDialog::on_buttonBox_accepted()
{
    GLOBAL_VARS::selectedOutputDirPath = ui->outputDirLineEdit->text();
    GLOBAL_VARS::pinExeDirPath = ui->pinExeLineEdit->text();
    GLOBAL_VARS::tracerDLLDirPath = ui->tracerdllLineEdit->text();

    accept();
}

