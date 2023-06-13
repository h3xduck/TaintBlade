#include "dialogs/AboutDialog.h"
#include "./ui_AboutDialog.h"


AboutDialog::AboutDialog(QWidget* parent)
    : QDialog(parent)
    , ui(new Ui::AboutDialog)
{
    ui->setupUi(this);
    this->setWindowTitle("About");

    QHBoxLayout* mainLayout = new QHBoxLayout(this);
    QVBoxLayout* iconLayout = new QVBoxLayout();

    QLabel* iconLabel = new QLabel(this);
    QPixmap icon(":/res/res/appicon.png");
    QSize maxSize(200, 200);
    icon = icon.scaled(maxSize, Qt::KeepAspectRatio, Qt::SmoothTransformation);
    iconLabel->setPixmap(icon);
    iconLabel->setAlignment(Qt::AlignCenter);
    
    iconLayout->addStretch();
    iconLayout->addWidget(iconLabel);
    iconLayout->addStretch();
    iconLayout->setAlignment(Qt::AlignHCenter);
    mainLayout->addLayout(iconLayout);

    QLabel* otherLabel = new QLabel("<html><head/><body><p align=\"center\"><span style=\" font-size:22pt;\">TaintBlade</span></p><p align=\"center\"><a href=\"https://github.com/h3xduck/TFM\"><span style=\" font-size:12pt; text-decoration: underline; color:#0000ff;\">Github Repository</span></a></p><p><br/></p><p align=\"center\"><span style=\" font-size:12pt;\">Authors:</span></p><p align=\"center\"><a href=\"https://twitter.com/h3xduck\"><span style=\" font-size:16pt; text-decoration: underline; color:#0000ff;\">@h3xduck </span></a></p><p align=\"center\"><a href=\"https://twitter.com/0xjet\"><span style=\" font-size:16pt; text-decoration: underline; color:#0000ff;\">@0xjet</span></a></p><p align=\"center\"><br/></p></body></html>", this);
    mainLayout->addWidget(otherLabel);
    setLayout(mainLayout);
}

AboutDialog::~AboutDialog()
{
    delete ui;
}