/********************************************************************************
** Form generated from reading UI file 'TaintRoutinesWidget.ui'
**
** Created by: Qt User Interface Compiler version 6.5.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_TAINTROUTINESWIDGET_H
#define UI_TAINTROUTINESWIDGET_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_TaintRoutinesWidget
{
public:
    QVBoxLayout *verticalLayout;
    QLabel *label;
    QTreeWidget *treeWidget;

    void setupUi(QWidget *TaintRoutinesWidget)
    {
        if (TaintRoutinesWidget->objectName().isEmpty())
            TaintRoutinesWidget->setObjectName("TaintRoutinesWidget");
        TaintRoutinesWidget->resize(489, 346);
        verticalLayout = new QVBoxLayout(TaintRoutinesWidget);
        verticalLayout->setObjectName("verticalLayout");
        label = new QLabel(TaintRoutinesWidget);
        label->setObjectName("label");
        label->setAutoFillBackground(true);

        verticalLayout->addWidget(label);

        treeWidget = new QTreeWidget(TaintRoutinesWidget);
        treeWidget->setObjectName("treeWidget");
        treeWidget->setColumnCount(0);

        verticalLayout->addWidget(treeWidget);


        retranslateUi(TaintRoutinesWidget);

        QMetaObject::connectSlotsByName(TaintRoutinesWidget);
    } // setupUi

    void retranslateUi(QWidget *TaintRoutinesWidget)
    {
        TaintRoutinesWidget->setWindowTitle(QCoreApplication::translate("TaintRoutinesWidget", "Form", nullptr));
        label->setText(QCoreApplication::translate("TaintRoutinesWidget", "TAINTED ROUTINES", nullptr));
    } // retranslateUi

};

namespace Ui {
    class TaintRoutinesWidget: public Ui_TaintRoutinesWidget {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_TAINTROUTINESWIDGET_H
