#include "dialogs/TaintSourceSelectorDialog.h"
#include "./ui_TaintSourceSelectorDialog.h"


TaintSourceSelectorDialog::TaintSourceSelectorDialog(QWidget* parent)
    : QDialog(parent)
    , ui(new Ui::TaintSourceSelectorDialog)
{
    ui->setupUi(this);
    ui->treeWidget->clear();

    connect(ui->okButton, &QPushButton::clicked, this, &TaintSourceSelectorDialog::saveTextContents);
    showAvailableTaintSources();
}

TaintSourceSelectorDialog::~TaintSourceSelectorDialog()
{
    delete ui;
}

void showDialog(const QString& data)
{
    QMessageBox msgBox;
    msgBox.setIcon(QMessageBox::NoIcon);
    msgBox.setWindowTitle("Taint source information");
    msgBox.setText(data);
    msgBox.exec();
}

void TaintSourceSelectorDialog::addLineToTreeWidget(const QString& dll, const QString& func, const QString& argNum, const QString& arch, const QString& helpLine)
{
    QTreeWidgetItem* item = new QTreeWidgetItem(ui->treeWidget);

    QCheckBox* checkBox = new QCheckBox(ui->treeWidget);
    checkBox->setChecked(true);
    ui->treeWidget->setItemWidget(item, 0, checkBox);

    item->setText(1, dll);
    item->setText(2, func);
    item->setText(3, argNum);
    item->setText(4, arch);

    QPushButton* rightButton = new QPushButton(ui->treeWidget);
    rightButton->setIcon(QIcon(":/res/res/icons8-info-26.png")); // Replace with the actual path to your icon resource
    rightButton->setIconSize(QSize(24, 24)); // Set the desired size of the icon
    rightButton->setFixedSize(QSize(24, 24)); // Set a fixed size for the button
    ui->treeWidget->setItemWidget(item, 5, rightButton);

    ui->treeWidget->setColumnWidth(0, 50);
    ui->treeWidget->resizeColumnToContents(1);
    ui->treeWidget->resizeColumnToContents(2);
    ui->treeWidget->resizeColumnToContents(3);
    ui->treeWidget->resizeColumnToContents(4);
    ui->treeWidget->setColumnWidth(5, 50);

    connect(rightButton, &QPushButton::clicked, this, [this, helpLine]() {showDialog(helpLine); });
}


void TaintSourceSelectorDialog::showAvailableTaintSources()
{
    //The taint sources are hardcoded and depend on the ones programmed in the main pintool
    ui->treeWidget->setColumnCount(6);
    ui->treeWidget->setHeaderLabels({"", "DLL path", "Routine name", "Num. of args", "Arch", ""});

    //recv
    QString helpStr = QString(
        "'recv' will activate the taint functionality when it EXITS.\n"
        "It will take the return value of the function, and taint as many bytes in the second argument 'buf' as indicated in the return value.\n"
        "\n"
        "WINDOWS::SOCKET s;\n"
        "char* buf;     <-- taint <return value> bytes at exit\n"
        "int len;\n"
        "int flags;"
    );
    addLineToTreeWidget("c:\\windows\\system32\\ws2_32.dll", "recv", "4", "x86_64", helpStr);
    addLineToTreeWidget("c:\\windows\\syswow64\\ws2_32.dll", "recv", "4", "x86", helpStr);
    addLineToTreeWidget("c:\\windows\\system32\\wsock32.dll", "recv", "4", "x86_64", helpStr);
    addLineToTreeWidget("c:\\windows\\syswow64\\wsock32.dll", "recv", "4", "x86", helpStr);

    //internetreadfile
    helpStr = QString(
        "'InternetReadFile' will activate the taint functionality when it EXITS.\n"
        "It will take the value of 'lpdwNumberOfBytesRead', and taint that many bytes of the buffer 'lpBuffer'.\n"
        "\n"
        "WINDOWS::LPVOID hFile;\n"
        "WINDOWS::LPVOID lpBuffer;      <-- taint <lpdwNumberOfBytesRead> bytes at exit\n"
        "WINDOWS::DWORD dwNumberOfBytesToRead;\n"
        "WINDOWS::LPDWORD lpdwNumberOfBytesRead;"
    );

    addLineToTreeWidget("c:\\windows\\system32\\wininet.dll", "InternetReadFile", "4", "x86_64", helpStr);
    addLineToTreeWidget("c:\\windows\\syswow64\\wininet.dll", "InternetReadFile", "4", "x86", helpStr);

}

void TaintSourceSelectorDialog::saveTextContents()
{
    QFile file(GLOBAL_VARS::selectedOutputDirPath + "/" + "taintsources.txt");
    if (file.exists())
    {
        file.remove();
    }
    if (file.open(QIODevice::ReadWrite | QIODevice::Text)) {
        QTextStream out(&file);
        for (int ii = 0; ii < ui->treeWidget->topLevelItemCount(); ii++)
        {
            QTreeWidgetItem* item = ui->treeWidget->topLevelItem(ii);
            QCheckBox* checkBox = qobject_cast<QCheckBox*>(ui->treeWidget->itemWidget(item, 0));
            if (checkBox && checkBox->isChecked())
            {
                out << item->text(1) << " " << item->text(2) << " " << item->text(3) << "\n";
            }
        }
        file.close();
    }
}