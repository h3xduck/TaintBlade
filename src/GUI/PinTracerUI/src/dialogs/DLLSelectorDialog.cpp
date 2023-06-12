#include "dialogs/DLLSelectorDialog.h"
#include "./ui_DLLSelectorDialog.h"


void DLLSelectorDialog::addLineToListWidget(const QString& line, QListWidget* listWidget)
{
    QListWidgetItem* item = new QListWidgetItem(listWidget);
    listWidget->addItem(item);

    QWidget* widget = new QWidget();
    QHBoxLayout* layout = new QHBoxLayout(widget);
    layout->setContentsMargins(0, 0, 0, 0);

    QLabel* label = new QLabel(line);
    layout->addWidget(label);

    layout->addStretch(); 
    QPushButton* button = new QPushButton(widget); 
    button->setIcon(QIcon(":/res/res/icons8-cross-26.png"));
    button->setIconSize(QSize(24, 24)); 
    button->setFixedSize(QSize(24, 24)); 
    layout->addWidget(button);

    connect(button, &QPushButton::clicked, [=]() {
        //We remove this line
        int row = listWidget->row(item);
        listWidget->takeItem(row);
        delete item;
    });

    widget->setLayout(layout);
    item->setSizeHint(widget->sizeHint());
    listWidget->setItemWidget(item, widget);
}

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

        //Read all lines, put them into the listwidget
        while (!in.atEnd())
        {
            QString line = in.readLine();
            addLineToListWidget(line, ui->listWidget);
        }

        file.close();
    }

    connect(ui->okButton, &QPushButton::clicked, this, &DLLSelectorDialog::saveTextContents);
    connect(ui->addLinePushButton, &QPushButton::clicked, this, [this] {
        if (ui->lineEdit->text() != "")
        {
            addLineToListWidget(ui->lineEdit->text(), ui->listWidget);
            ui->listWidget->scrollToBottom();
            ui->lineEdit->clear();
        }
    });
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
        QTextStream out(&file);
        for (int ii = 0; ii < ui->listWidget->count(); ii++)
        {
            QListWidgetItem* item = ui->listWidget->item(ii);
            QWidget* widget = ui->listWidget->itemWidget(item);
            QLabel* label = widget->findChild<QLabel*>();
            if (label)
            {
                QString line = label->text();
                out << line << "\n";
            }
        }
        file.close();
    }
}

