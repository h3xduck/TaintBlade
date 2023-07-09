#include "dialogs/TracePointSelectorDialog.h"
#include "./ui_TracePointSelectorDialog.h"


void TracePointSelectorDialog::addLineToTreeWidget(const QString& dll, const QString& func, const QString& numArgs)
{
    QTreeWidgetItem* item = new QTreeWidgetItem(ui->treeWidget);
    item->setText(0, dll);
    item->setText(1, func);
    item->setText(2, numArgs);

    QPushButton* rightButton = new QPushButton(ui->treeWidget);
    rightButton->setIcon(QIcon(":/res/res/icons8-cross-26.png"));
    rightButton->setIconSize(QSize(24, 24)); 
    rightButton->setFixedSize(QSize(24, 24));
    ui->treeWidget->setItemWidget(item, 3, rightButton);
    
    ui->treeWidget->addTopLevelItem(item);

    ui->treeWidget->resizeColumnToContents(0);
    ui->treeWidget->resizeColumnToContents(1);
    ui->treeWidget->resizeColumnToContents(2);
    ui->treeWidget->setColumnWidth(3, 50);

    //In case the user clicks on an X icon at some item
    connect(rightButton, &QPushButton::clicked, [=]() {
        //We remove this line
        delete item;
    });
}

TracePointSelectorDialog::TracePointSelectorDialog(QWidget* parent)
    : QDialog(parent)
    , ui(new Ui::TracePointSelectorDialog)
{
    //OK button not enabled initially until all options set
    ui->setupUi(this);

    ui->treeWidget->clear();
    ui->treeWidget->setHeaderLabels({"DLL", "Routine name", "Number of arguments", ""});
    connect(ui->okButton, &QPushButton::clicked, this, &TracePointSelectorDialog::saveTextContents);

    QFile file(GLOBAL_VARS::selectedOutputDirPath + "/" + "tracepoints.txt");
    if (file.open(QIODevice::ReadWrite | QIODevice::Text)) {
        QTextStream in(&file);

        //Read all lines, put them into the listwidget
        while (!in.atEnd())
        {
            QString line = in.readLine();
            QStringList words = line.split(" ");
            if (words.size() != 3) {
                // The line does not contain three words
                continue;
            }
            addLineToTreeWidget(words[0], words[1], words[2]);
        }

        file.close();
    }

    
    connect(ui->addPushButton, &QPushButton::clicked, this, [this] {
        if (ui->lineEditDll->text() != "" && ui->lineEditFunc->text() != "" && ui->lineEditArgs->text() != "")
        {
            addLineToTreeWidget(ui->lineEditDll->text(), ui->lineEditFunc->text(), ui->lineEditArgs->text());
            ui->treeWidget->scrollToBottom();
            ui->lineEditDll->clear();
            ui->lineEditFunc->clear();
            ui->lineEditArgs->clear();
        }
    });
}

TracePointSelectorDialog::~TracePointSelectorDialog()
{
    delete ui;
}

void TracePointSelectorDialog::saveTextContents()
{
    QFile file(GLOBAL_VARS::selectedOutputDirPath + "/" + "tracepoints.txt");
    if (file.exists())
    {
        file.remove();
    }
    if (file.open(QIODevice::ReadWrite | QIODevice::Text)) {
        QTextStream out(&file);
        for (int ii = 0; ii < ui->treeWidget->topLevelItemCount(); ii++)
        {
            QTreeWidgetItem* item = ui->treeWidget->topLevelItem(ii);
            out << item->text(0) << " " << item->text(1) << " " << item->text(2) << "\n";
        }
        file.close();
    }
}

