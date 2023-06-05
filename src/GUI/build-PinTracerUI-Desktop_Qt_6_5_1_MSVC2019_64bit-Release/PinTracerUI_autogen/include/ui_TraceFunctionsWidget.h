/********************************************************************************
** Form generated from reading UI file 'TraceFunctionsWidget.ui'
**
** Created by: Qt User Interface Compiler version 6.5.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_TRACEFUNCTIONSWIDGET_H
#define UI_TRACEFUNCTIONSWIDGET_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_TraceFunctionsWidget
{
public:
    QVBoxLayout *verticalLayout;
    QLabel *label;
    QTreeWidget *treeWidget;

    void setupUi(QWidget *TraceFunctionsWidget)
    {
        if (TraceFunctionsWidget->objectName().isEmpty())
            TraceFunctionsWidget->setObjectName("TraceFunctionsWidget");
        TraceFunctionsWidget->resize(400, 300);
        verticalLayout = new QVBoxLayout(TraceFunctionsWidget);
        verticalLayout->setObjectName("verticalLayout");
        label = new QLabel(TraceFunctionsWidget);
        label->setObjectName("label");
        label->setAutoFillBackground(true);

        verticalLayout->addWidget(label);

        treeWidget = new QTreeWidget(TraceFunctionsWidget);
        treeWidget->setObjectName("treeWidget");
        treeWidget->setColumnCount(0);

        verticalLayout->addWidget(treeWidget);


        retranslateUi(TraceFunctionsWidget);

        QMetaObject::connectSlotsByName(TraceFunctionsWidget);
    } // setupUi

    void retranslateUi(QWidget *TraceFunctionsWidget)
    {
        TraceFunctionsWidget->setWindowTitle(QCoreApplication::translate("TraceFunctionsWidget", "Form", nullptr));
        label->setText(QCoreApplication::translate("TraceFunctionsWidget", "TRACED FUNCTIONS", nullptr));
    } // retranslateUi

};

namespace Ui {
    class TraceFunctionsWidget: public Ui_TraceFunctionsWidget {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_TRACEFUNCTIONSWIDGET_H
