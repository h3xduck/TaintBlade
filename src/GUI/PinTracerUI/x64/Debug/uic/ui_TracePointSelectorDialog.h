/********************************************************************************
** Form generated from reading UI file 'TracePointSelectorDialog.ui'
**
** Created by: Qt User Interface Compiler version 6.5.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_TRACEPOINTSELECTORDIALOG_H
#define UI_TRACEPOINTSELECTORDIALOG_H

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

class Ui_TracePointSelectorDialog
{
public:
    QVBoxLayout *verticalLayout;
    QLabel *label;
    QTreeWidget *treeWidget;
    QHBoxLayout *horizontalLayout;
    QLineEdit *lineEditDll;
    QLineEdit *lineEditFunc;
    QLineEdit *lineEditArgs;
    QPushButton *addPushButton;
    QHBoxLayout *hboxLayout;
    QSpacerItem *spacerItem;
    QPushButton *okButton;
    QPushButton *cancelButton;

    void setupUi(QDialog *TracePointSelectorDialog)
    {
        if (TracePointSelectorDialog->objectName().isEmpty())
            TracePointSelectorDialog->setObjectName("TracePointSelectorDialog");
        TracePointSelectorDialog->resize(580, 337);
        verticalLayout = new QVBoxLayout(TracePointSelectorDialog);
        verticalLayout->setObjectName("verticalLayout");
        label = new QLabel(TracePointSelectorDialog);
        label->setObjectName("label");

        verticalLayout->addWidget(label);

        treeWidget = new QTreeWidget(TracePointSelectorDialog);
        QTreeWidgetItem *__qtreewidgetitem = new QTreeWidgetItem();
        __qtreewidgetitem->setText(0, QString::fromUtf8("1"));
        treeWidget->setHeaderItem(__qtreewidgetitem);
        treeWidget->setObjectName("treeWidget");

        verticalLayout->addWidget(treeWidget);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName("horizontalLayout");
        lineEditDll = new QLineEdit(TracePointSelectorDialog);
        lineEditDll->setObjectName("lineEditDll");

        horizontalLayout->addWidget(lineEditDll);

        lineEditFunc = new QLineEdit(TracePointSelectorDialog);
        lineEditFunc->setObjectName("lineEditFunc");

        horizontalLayout->addWidget(lineEditFunc);

        lineEditArgs = new QLineEdit(TracePointSelectorDialog);
        lineEditArgs->setObjectName("lineEditArgs");

        horizontalLayout->addWidget(lineEditArgs);

        addPushButton = new QPushButton(TracePointSelectorDialog);
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

        okButton = new QPushButton(TracePointSelectorDialog);
        okButton->setObjectName("okButton");

        hboxLayout->addWidget(okButton);

        cancelButton = new QPushButton(TracePointSelectorDialog);
        cancelButton->setObjectName("cancelButton");

        hboxLayout->addWidget(cancelButton);


        verticalLayout->addLayout(hboxLayout);


        retranslateUi(TracePointSelectorDialog);
        QObject::connect(okButton, &QPushButton::clicked, TracePointSelectorDialog, qOverload<>(&QDialog::accept));
        QObject::connect(cancelButton, &QPushButton::clicked, TracePointSelectorDialog, qOverload<>(&QDialog::reject));

        QMetaObject::connectSlotsByName(TracePointSelectorDialog);
    } // setupUi

    void retranslateUi(QDialog *TracePointSelectorDialog)
    {
        TracePointSelectorDialog->setWindowTitle(QCoreApplication::translate("TracePointSelectorDialog", "Dialog", nullptr));
        label->setText(QCoreApplication::translate("TracePointSelectorDialog", "Select here functions to trace, getting all arguments before and after they are called.", nullptr));
        lineEditDll->setText(QString());
        lineEditDll->setPlaceholderText(QCoreApplication::translate("TracePointSelectorDialog", "DLL path", nullptr));
        lineEditFunc->setText(QString());
        lineEditFunc->setPlaceholderText(QCoreApplication::translate("TracePointSelectorDialog", "Function name", nullptr));
        lineEditArgs->setPlaceholderText(QCoreApplication::translate("TracePointSelectorDialog", "Number of arguments", nullptr));
        addPushButton->setText(QCoreApplication::translate("TracePointSelectorDialog", "Add", nullptr));
        okButton->setText(QCoreApplication::translate("TracePointSelectorDialog", "OK", nullptr));
        cancelButton->setText(QCoreApplication::translate("TracePointSelectorDialog", "Cancel", nullptr));
    } // retranslateUi

};

namespace Ui {
    class TracePointSelectorDialog: public Ui_TracePointSelectorDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_TRACEPOINTSELECTORDIALOG_H
