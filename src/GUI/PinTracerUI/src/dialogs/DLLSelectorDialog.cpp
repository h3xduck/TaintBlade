#include "dialogs/DLLSelectorDialog.h"
#include "./ui_DLLSelectorDialog.h"

DLLSelectorDialog::DLLSelectorDialog(QWidget* parent)
    : QDialog(parent)
    , ui(new Ui::DLLSelectorDialog)
{
    //OK button not enabled initially until all options set
    ui->setupUi(this);
    
    //In the text edit field, we will put the DLLs to track
    QFile file(GLOBAL_VARS::selectedOutputDirPath + "/" + "dllinclude.txt");
    if (file.open(QIODevice::ReadWrite | QIODevice::Text)) {
        QTextStream in(&file);
        QString fileContent = in.readAll();

        ui->textEdit->setPlainText(fileContent);
        file.close();
    }

    connect(ui->okButton, &QPushButton::clicked, this, &DLLSelectorDialog::saveTextContents);
}

DLLSelectorDialog::~DLLSelectorDialog()
{
    delete ui;
}

void DLLSelectorDialog::saveTextContents()
{
    QFile file(GLOBAL_VARS::selectedOutputDirPath + "/" + "dllinclude.txt");
    if (file.exists())
    {
        file.remove();
    }
    if (file.open(QIODevice::ReadWrite | QIODevice::Text)) {
        QTextStream in(&file);
        file.write(ui->textEdit->toPlainText().toLatin1());
        file.close();
    }
}

