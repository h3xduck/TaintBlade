/********************************************************************************
** Form generated from reading UI file 'DLLSelectorDialog.ui'
**
** Created by: Qt User Interface Compiler version 6.5.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_DLLSELECTORDIALOG_H
#define UI_DLLSELECTORDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPlainTextEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_DLLSelectorDialog
{
public:
    QVBoxLayout *verticalLayout_2;
    QLabel *label;
    QLabel *label_2;
    QPlainTextEdit *textEdit;
    QHBoxLayout *hboxLayout;
    QSpacerItem *spacerItem;
    QPushButton *okButton;
    QPushButton *cancelButton;

    void setupUi(QDialog *DLLSelectorDialog)
    {
        if (DLLSelectorDialog->objectName().isEmpty())
            DLLSelectorDialog->setObjectName("DLLSelectorDialog");
        DLLSelectorDialog->resize(621, 346);
        verticalLayout_2 = new QVBoxLayout(DLLSelectorDialog);
        verticalLayout_2->setObjectName("verticalLayout_2");
        label = new QLabel(DLLSelectorDialog);
        label->setObjectName("label");

        verticalLayout_2->addWidget(label);

        label_2 = new QLabel(DLLSelectorDialog);
        label_2->setObjectName("label_2");

        verticalLayout_2->addWidget(label_2);

        textEdit = new QPlainTextEdit(DLLSelectorDialog);
        textEdit->setObjectName("textEdit");
        textEdit->setLineWrapMode(QPlainTextEdit::NoWrap);

        verticalLayout_2->addWidget(textEdit);

        hboxLayout = new QHBoxLayout();
#ifndef Q_OS_MAC
        hboxLayout->setSpacing(6);
#endif
        hboxLayout->setContentsMargins(0, 0, 0, 0);
        hboxLayout->setObjectName("hboxLayout");
        spacerItem = new QSpacerItem(131, 31, QSizePolicy::Expanding, QSizePolicy::Minimum);

        hboxLayout->addItem(spacerItem);

        okButton = new QPushButton(DLLSelectorDialog);
        okButton->setObjectName("okButton");

        hboxLayout->addWidget(okButton);

        cancelButton = new QPushButton(DLLSelectorDialog);
        cancelButton->setObjectName("cancelButton");

        hboxLayout->addWidget(cancelButton);


        verticalLayout_2->addLayout(hboxLayout);


        retranslateUi(DLLSelectorDialog);
        QObject::connect(okButton, &QPushButton::clicked, DLLSelectorDialog, qOverload<>(&QDialog::accept));
        QObject::connect(cancelButton, &QPushButton::clicked, DLLSelectorDialog, qOverload<>(&QDialog::reject));

        QMetaObject::connectSlotsByName(DLLSelectorDialog);
    } // setupUi

    void retranslateUi(QDialog *DLLSelectorDialog)
    {
        DLLSelectorDialog->setWindowTitle(QCoreApplication::translate("DLLSelectorDialog", "Dialog", nullptr));
        label->setText(QCoreApplication::translate("DLLSelectorDialog", "Enter the full path of the DLLs to include to the scope. Write one DLL per line.", nullptr));
        label_2->setText(QCoreApplication::translate("DLLSelectorDialog", "*Note that the main binary is always included in the scope.", nullptr));
        okButton->setText(QCoreApplication::translate("DLLSelectorDialog", "OK", nullptr));
        cancelButton->setText(QCoreApplication::translate("DLLSelectorDialog", "Cancel", nullptr));
    } // retranslateUi

};

namespace Ui {
    class DLLSelectorDialog: public Ui_DLLSelectorDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_DLLSELECTORDIALOG_H
