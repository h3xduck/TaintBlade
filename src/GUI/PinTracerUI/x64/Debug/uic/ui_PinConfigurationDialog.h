/********************************************************************************
** Form generated from reading UI file 'PinConfigurationDialog.ui'
**
** Created by: Qt User Interface Compiler version 6.5.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_PINCONFIGURATIONDIALOG_H
#define UI_PINCONFIGURATIONDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QAbstractButton>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_PinConfigurationDialog
{
public:
    QVBoxLayout *verticalLayout;
    QVBoxLayout *optionsLayout;
    QVBoxLayout *tracerDLLLayout_2;
    QLabel *label_7;
    QHBoxLayout *horizontalLayout_8;
    QLineEdit *tracerdllLineEdit;
    QPushButton *tracerdllBrowseButton;
    QVBoxLayout *pinExeLayout;
    QLabel *label;
    QHBoxLayout *horizontalLayout_2;
    QLineEdit *pinExeLineEdit;
    QPushButton *pinExeBrowseButton;
    QVBoxLayout *outputDirLayout;
    QLabel *label_6;
    QHBoxLayout *horizontalLayout_7;
    QLineEdit *outputDirLineEdit;
    QPushButton *outputDirBrowseButton;
    QSpacerItem *horizontalSpacer;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *PinConfigurationDialog)
    {
        if (PinConfigurationDialog->objectName().isEmpty())
            PinConfigurationDialog->setObjectName("PinConfigurationDialog");
        PinConfigurationDialog->setEnabled(true);
        PinConfigurationDialog->resize(700, 200);
        QSizePolicy sizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(PinConfigurationDialog->sizePolicy().hasHeightForWidth());
        PinConfigurationDialog->setSizePolicy(sizePolicy);
        PinConfigurationDialog->setMinimumSize(QSize(700, 200));
        PinConfigurationDialog->setMaximumSize(QSize(700, 256));
        PinConfigurationDialog->setAutoFillBackground(false);
        PinConfigurationDialog->setSizeGripEnabled(false);
        verticalLayout = new QVBoxLayout(PinConfigurationDialog);
        verticalLayout->setObjectName("verticalLayout");
        optionsLayout = new QVBoxLayout();
        optionsLayout->setObjectName("optionsLayout");
        tracerDLLLayout_2 = new QVBoxLayout();
        tracerDLLLayout_2->setObjectName("tracerDLLLayout_2");
        label_7 = new QLabel(PinConfigurationDialog);
        label_7->setObjectName("label_7");
        label_7->setMaximumSize(QSize(16777215, 15));

        tracerDLLLayout_2->addWidget(label_7);

        horizontalLayout_8 = new QHBoxLayout();
        horizontalLayout_8->setObjectName("horizontalLayout_8");
        tracerdllLineEdit = new QLineEdit(PinConfigurationDialog);
        tracerdllLineEdit->setObjectName("tracerdllLineEdit");

        horizontalLayout_8->addWidget(tracerdllLineEdit);

        tracerdllBrowseButton = new QPushButton(PinConfigurationDialog);
        tracerdllBrowseButton->setObjectName("tracerdllBrowseButton");

        horizontalLayout_8->addWidget(tracerdllBrowseButton);


        tracerDLLLayout_2->addLayout(horizontalLayout_8);


        optionsLayout->addLayout(tracerDLLLayout_2);

        pinExeLayout = new QVBoxLayout();
        pinExeLayout->setObjectName("pinExeLayout");
        label = new QLabel(PinConfigurationDialog);
        label->setObjectName("label");
        label->setMaximumSize(QSize(16777215, 15));

        pinExeLayout->addWidget(label);

        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName("horizontalLayout_2");
        pinExeLineEdit = new QLineEdit(PinConfigurationDialog);
        pinExeLineEdit->setObjectName("pinExeLineEdit");

        horizontalLayout_2->addWidget(pinExeLineEdit);

        pinExeBrowseButton = new QPushButton(PinConfigurationDialog);
        pinExeBrowseButton->setObjectName("pinExeBrowseButton");

        horizontalLayout_2->addWidget(pinExeBrowseButton);


        pinExeLayout->addLayout(horizontalLayout_2);


        optionsLayout->addLayout(pinExeLayout);

        outputDirLayout = new QVBoxLayout();
        outputDirLayout->setObjectName("outputDirLayout");
        label_6 = new QLabel(PinConfigurationDialog);
        label_6->setObjectName("label_6");
        label_6->setMaximumSize(QSize(16777215, 15));

        outputDirLayout->addWidget(label_6);

        horizontalLayout_7 = new QHBoxLayout();
        horizontalLayout_7->setObjectName("horizontalLayout_7");
        outputDirLineEdit = new QLineEdit(PinConfigurationDialog);
        outputDirLineEdit->setObjectName("outputDirLineEdit");

        horizontalLayout_7->addWidget(outputDirLineEdit);

        outputDirBrowseButton = new QPushButton(PinConfigurationDialog);
        outputDirBrowseButton->setObjectName("outputDirBrowseButton");

        horizontalLayout_7->addWidget(outputDirBrowseButton);


        outputDirLayout->addLayout(horizontalLayout_7);


        optionsLayout->addLayout(outputDirLayout);


        verticalLayout->addLayout(optionsLayout);

        horizontalSpacer = new QSpacerItem(40, 10, QSizePolicy::Expanding, QSizePolicy::Minimum);

        verticalLayout->addItem(horizontalSpacer);

        buttonBox = new QDialogButtonBox(PinConfigurationDialog);
        buttonBox->setObjectName("buttonBox");
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Ok);
        buttonBox->setCenterButtons(false);

        verticalLayout->addWidget(buttonBox);


        retranslateUi(PinConfigurationDialog);
        QObject::connect(buttonBox, &QDialogButtonBox::rejected, PinConfigurationDialog, qOverload<>(&QDialog::reject));
        QObject::connect(buttonBox, &QDialogButtonBox::accepted, PinConfigurationDialog, qOverload<>(&QDialog::accept));

        QMetaObject::connectSlotsByName(PinConfigurationDialog);
    } // setupUi

    void retranslateUi(QDialog *PinConfigurationDialog)
    {
        PinConfigurationDialog->setWindowTitle(QCoreApplication::translate("PinConfigurationDialog", "Dialog", nullptr));
        label_7->setText(QCoreApplication::translate("PinConfigurationDialog", "Select tracer DLL file", nullptr));
        tracerdllBrowseButton->setText(QCoreApplication::translate("PinConfigurationDialog", "Browse", nullptr));
        label->setText(QCoreApplication::translate("PinConfigurationDialog", "Select Intel PIN EXE file", nullptr));
        pinExeBrowseButton->setText(QCoreApplication::translate("PinConfigurationDialog", "Browse", nullptr));
        label_6->setText(QCoreApplication::translate("PinConfigurationDialog", "Select directory for store output files", nullptr));
        outputDirBrowseButton->setText(QCoreApplication::translate("PinConfigurationDialog", "Browse", nullptr));
    } // retranslateUi

};

namespace Ui {
    class PinConfigurationDialog: public Ui_PinConfigurationDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_PINCONFIGURATIONDIALOG_H
