/********************************************************************************
** Form generated from reading UI file 'NopSectionSelectorDialog.ui'
**
** Created by: Qt User Interface Compiler version 6.5.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_NOPSECTIONSELECTORDIALOG_H
#define UI_NOPSECTIONSELECTORDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_NopSectionSelectorDialog
{
public:
    QVBoxLayout *verticalLayout;
    QLabel *label;
    QTreeWidget *treeWidget;
    QHBoxLayout *horizontalLayout;
    QLineEdit *lineEditDll;
    QLineEdit *lineEditRangeStart;
    QLineEdit *lineEditRangeEnd;
    QPushButton *addPushButton;
    QHBoxLayout *hboxLayout;
    QSpacerItem *spacerItem;
    QPushButton *okButton;
    QPushButton *cancelButton;

    void setupUi(QDialog *NopSectionSelectorDialog)
    {
        if (NopSectionSelectorDialog->objectName().isEmpty())
            NopSectionSelectorDialog->setObjectName("NopSectionSelectorDialog");
        NopSectionSelectorDialog->resize(628, 384);
        verticalLayout = new QVBoxLayout(NopSectionSelectorDialog);
        verticalLayout->setObjectName("verticalLayout");
        label = new QLabel(NopSectionSelectorDialog);
        label->setObjectName("label");

        verticalLayout->addWidget(label);

        treeWidget = new QTreeWidget(NopSectionSelectorDialog);
        QTreeWidgetItem *__qtreewidgetitem = new QTreeWidgetItem();
        __qtreewidgetitem->setText(0, QString::fromUtf8("1"));
        treeWidget->setHeaderItem(__qtreewidgetitem);
        treeWidget->setObjectName("treeWidget");

        verticalLayout->addWidget(treeWidget);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName("horizontalLayout");
        lineEditDll = new QLineEdit(NopSectionSelectorDialog);
        lineEditDll->setObjectName("lineEditDll");

        horizontalLayout->addWidget(lineEditDll);

        lineEditRangeStart = new QLineEdit(NopSectionSelectorDialog);
        lineEditRangeStart->setObjectName("lineEditRangeStart");

        horizontalLayout->addWidget(lineEditRangeStart);

        lineEditRangeEnd = new QLineEdit(NopSectionSelectorDialog);
        lineEditRangeEnd->setObjectName("lineEditRangeEnd");

        horizontalLayout->addWidget(lineEditRangeEnd);

        addPushButton = new QPushButton(NopSectionSelectorDialog);
        addPushButton->setObjectName("addPushButton");

        horizontalLayout->addWidget(addPushButton);


        verticalLayout->addLayout(horizontalLayout);

        hboxLayout = new QHBoxLayout();
#ifndef Q_OS_MAC
        hboxLayout->setSpacing(6);
#endif
        hboxLayout->setContentsMargins(0, 0, 0, 0);
        hboxLayout->setObjectName("hboxLayout");
        spacerItem = new QSpacerItem(131, 31, QSizePolicy::Expanding, QSizePolicy::Minimum);

        hboxLayout->addItem(spacerItem);

        okButton = new QPushButton(NopSectionSelectorDialog);
        okButton->setObjectName("okButton");

        hboxLayout->addWidget(okButton);

        cancelButton = new QPushButton(NopSectionSelectorDialog);
        cancelButton->setObjectName("cancelButton");

        hboxLayout->addWidget(cancelButton);


        verticalLayout->addLayout(hboxLayout);


        retranslateUi(NopSectionSelectorDialog);

        QMetaObject::connectSlotsByName(NopSectionSelectorDialog);
    } // setupUi

    void retranslateUi(QDialog *NopSectionSelectorDialog)
    {
        NopSectionSelectorDialog->setWindowTitle(QCoreApplication::translate("NopSectionSelectorDialog", "Dialog", nullptr));
        label->setText(QCoreApplication::translate("NopSectionSelectorDialog", "Select ranges of instructions to avoid executing at a certain image.", nullptr));
        lineEditDll->setText(QString());
        lineEditDll->setPlaceholderText(QCoreApplication::translate("NopSectionSelectorDialog", "DLL path", nullptr));
        lineEditRangeStart->setText(QString());
        lineEditRangeStart->setPlaceholderText(QCoreApplication::translate("NopSectionSelectorDialog", "First RVA in range", nullptr));
        lineEditRangeEnd->setPlaceholderText(QCoreApplication::translate("NopSectionSelectorDialog", "Last RVA in range", nullptr));
        addPushButton->setText(QCoreApplication::translate("NopSectionSelectorDialog", "Add", nullptr));
        okButton->setText(QCoreApplication::translate("NopSectionSelectorDialog", "OK", nullptr));
        cancelButton->setText(QCoreApplication::translate("NopSectionSelectorDialog", "Cancel", nullptr));
    } // retranslateUi

};

namespace Ui {
    class NopSectionSelectorDialog: public Ui_NopSectionSelectorDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_NOPSECTIONSELECTORDIALOG_H
