/********************************************************************************
** Form generated from reading UI file 'TaintEventsWidget.ui'
**
** Created by: Qt User Interface Compiler version 6.5.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_TAINTEVENTSWIDGET_H
#define UI_TAINTEVENTSWIDGET_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_TaintEventsWidget
{
public:
    QVBoxLayout *verticalLayout_2;
    QLabel *label;
    QTreeWidget *treeWidget;

    void setupUi(QWidget *TaintEventsWidget)
    {
        if (TaintEventsWidget->objectName().isEmpty())
            TaintEventsWidget->setObjectName("TaintEventsWidget");
        TaintEventsWidget->resize(400, 300);
        verticalLayout_2 = new QVBoxLayout(TaintEventsWidget);
        verticalLayout_2->setObjectName("verticalLayout_2");
        label = new QLabel(TaintEventsWidget);
        label->setObjectName("label");

        verticalLayout_2->addWidget(label);

        treeWidget = new QTreeWidget(TaintEventsWidget);
        treeWidget->setObjectName("treeWidget");

        verticalLayout_2->addWidget(treeWidget);


        retranslateUi(TaintEventsWidget);

        QMetaObject::connectSlotsByName(TaintEventsWidget);
    } // setupUi

    void retranslateUi(QWidget *TaintEventsWidget)
    {
        TaintEventsWidget->setWindowTitle(QCoreApplication::translate("TaintEventsWidget", "Form", nullptr));
        label->setText(QCoreApplication::translate("TaintEventsWidget", "TAINT EVENTS (chronological)", nullptr));
    } // retranslateUi

};

namespace Ui {
    class TaintEventsWidget: public Ui_TaintEventsWidget {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_TAINTEVENTSWIDGET_H
