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
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_TaintEventsWidget
{
public:
    QVBoxLayout *verticalLayout;
    QLabel *label;
    QHBoxLayout *horizontalLayout;
    QCheckBox *checkBox;
    QCheckBox *checkBoxGroupEvents;
    QTreeWidget *treeWidget;

    void setupUi(QWidget *TaintEventsWidget)
    {
        if (TaintEventsWidget->objectName().isEmpty())
            TaintEventsWidget->setObjectName("TaintEventsWidget");
        TaintEventsWidget->resize(400, 300);
        verticalLayout = new QVBoxLayout(TaintEventsWidget);
        verticalLayout->setObjectName("verticalLayout");
        label = new QLabel(TaintEventsWidget);
        label->setObjectName("label");

        verticalLayout->addWidget(label);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName("horizontalLayout");
        checkBox = new QCheckBox(TaintEventsWidget);
        checkBox->setObjectName("checkBox");
        checkBox->setChecked(false);

        horizontalLayout->addWidget(checkBox);

        checkBoxGroupEvents = new QCheckBox(TaintEventsWidget);
        checkBoxGroupEvents->setObjectName("checkBoxGroupEvents");

        horizontalLayout->addWidget(checkBoxGroupEvents);


        verticalLayout->addLayout(horizontalLayout);

        treeWidget = new QTreeWidget(TaintEventsWidget);
        QTreeWidgetItem *__qtreewidgetitem = new QTreeWidgetItem();
        __qtreewidgetitem->setText(0, QString::fromUtf8("1"));
        treeWidget->setHeaderItem(__qtreewidgetitem);
        treeWidget->setObjectName("treeWidget");

        verticalLayout->addWidget(treeWidget);


        retranslateUi(TaintEventsWidget);

        QMetaObject::connectSlotsByName(TaintEventsWidget);
    } // setupUi

    void retranslateUi(QWidget *TaintEventsWidget)
    {
        TaintEventsWidget->setWindowTitle(QCoreApplication::translate("TaintEventsWidget", "Form", nullptr));
        label->setText(QCoreApplication::translate("TaintEventsWidget", "TAINT EVENTS (chronological)", nullptr));
        checkBox->setText(QCoreApplication::translate("TaintEventsWidget", "Show jumps from scoped routines", nullptr));
        checkBoxGroupEvents->setText(QCoreApplication::translate("TaintEventsWidget", "Group taint events", nullptr));
    } // retranslateUi

};

namespace Ui {
    class TaintEventsWidget: public Ui_TaintEventsWidget {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_TAINTEVENTSWIDGET_H
