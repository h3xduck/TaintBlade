/********************************************************************************
** Form generated from reading UI file 'TaintSourceSelectorDialog.ui'
**
** Created by: Qt User Interface Compiler version 6.5.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_TAINTSOURCESELECTORDIALOG_H
#define UI_TAINTSOURCESELECTORDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_TaintSourceSelectorDialog
{
public:
    QVBoxLayout *verticalLayout;
    QLabel *label;
    QLabel *label_2;
    QTreeWidget *treeWidget;
    QHBoxLayout *hboxLayout;
    QSpacerItem *spacerItem;
    QPushButton *okButton;
    QPushButton *cancelButton;

    void setupUi(QDialog *TaintSourceSelectorDialog)
    {
        if (TaintSourceSelectorDialog->objectName().isEmpty())
            TaintSourceSelectorDialog->setObjectName("TaintSourceSelectorDialog");
        TaintSourceSelectorDialog->resize(665, 333);
        verticalLayout = new QVBoxLayout(TaintSourceSelectorDialog);
        verticalLayout->setObjectName("verticalLayout");
        label = new QLabel(TaintSourceSelectorDialog);
        label->setObjectName("label");

        verticalLayout->addWidget(label);

        label_2 = new QLabel(TaintSourceSelectorDialog);
        label_2->setObjectName("label_2");

        verticalLayout->addWidget(label_2);

        treeWidget = new QTreeWidget(TaintSourceSelectorDialog);
        QTreeWidgetItem *__qtreewidgetitem = new QTreeWidgetItem();
        __qtreewidgetitem->setText(0, QString::fromUtf8("1"));
        treeWidget->setHeaderItem(__qtreewidgetitem);
        treeWidget->setObjectName("treeWidget");

        verticalLayout->addWidget(treeWidget);

        hboxLayout = new QHBoxLayout();
#ifndef Q_OS_MAC
        hboxLayout->setSpacing(6);
#endif
        hboxLayout->setContentsMargins(0, 0, 0, 0);
        hboxLayout->setObjectName("hboxLayout");
        spacerItem = new QSpacerItem(131, 31, QSizePolicy::Expanding, QSizePolicy::Minimum);

        hboxLayout->addItem(spacerItem);

        okButton = new QPushButton(TaintSourceSelectorDialog);
        okButton->setObjectName("okButton");

        hboxLayout->addWidget(okButton);

        cancelButton = new QPushButton(TaintSourceSelectorDialog);
        cancelButton->setObjectName("cancelButton");

        hboxLayout->addWidget(cancelButton);


        verticalLayout->addLayout(hboxLayout);


        retranslateUi(TaintSourceSelectorDialog);
        QObject::connect(okButton, &QPushButton::clicked, TaintSourceSelectorDialog, qOverload<>(&QDialog::accept));
        QObject::connect(cancelButton, &QPushButton::clicked, TaintSourceSelectorDialog, qOverload<>(&QDialog::reject));

        QMetaObject::connectSlotsByName(TaintSourceSelectorDialog);
    } // setupUi

    void retranslateUi(QDialog *TaintSourceSelectorDialog)
    {
        TaintSourceSelectorDialog->setWindowTitle(QCoreApplication::translate("TaintSourceSelectorDialog", "Dialog", nullptr));
        label->setText(QCoreApplication::translate("TaintSourceSelectorDialog", "Select here the routines you want to spread taint.", nullptr));
        label_2->setText(QCoreApplication::translate("TaintSourceSelectorDialog", "* You can also check how each routine generates taint in the info buttons.", nullptr));
        okButton->setText(QCoreApplication::translate("TaintSourceSelectorDialog", "OK", nullptr));
        cancelButton->setText(QCoreApplication::translate("TaintSourceSelectorDialog", "Cancel", nullptr));
    } // retranslateUi

};

namespace Ui {
    class TaintSourceSelectorDialog: public Ui_TaintSourceSelectorDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_TAINTSOURCESELECTORDIALOG_H
