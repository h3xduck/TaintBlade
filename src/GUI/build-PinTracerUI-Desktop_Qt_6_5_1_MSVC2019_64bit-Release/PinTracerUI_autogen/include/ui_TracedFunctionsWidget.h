/********************************************************************************
** Form generated from reading UI file 'TracedFunctionsWidget.ui'
**
** Created by: Qt User Interface Compiler version 6.5.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_TRACEDFUNCTIONSWIDGET_H
#define UI_TRACEDFUNCTIONSWIDGET_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_TracedFunctionsWidget
{
public:
    QVBoxLayout *verticalLayout;
    QLabel *label;
    QTreeWidget *treeWidget;

    void setupUi(QWidget *TracedFunctionsWidget)
    {
        if (TracedFunctionsWidget->objectName().isEmpty())
            TracedFunctionsWidget->setObjectName("TracedFunctionsWidget");
        TracedFunctionsWidget->resize(400, 300);
        verticalLayout = new QVBoxLayout(TracedFunctionsWidget);
        verticalLayout->setObjectName("verticalLayout");
        label = new QLabel(TracedFunctionsWidget);
        label->setObjectName("label");
        label->setAutoFillBackground(true);

        verticalLayout->addWidget(label);

        treeWidget = new QTreeWidget(TracedFunctionsWidget);
        treeWidget->setObjectName("treeWidget");
        treeWidget->setColumnCount(0);

        verticalLayout->addWidget(treeWidget);


        retranslateUi(TracedFunctionsWidget);

        QMetaObject::connectSlotsByName(TracedFunctionsWidget);
    } // setupUi

    void retranslateUi(QWidget *TracedFunctionsWidget)
    {
        TracedFunctionsWidget->setWindowTitle(QCoreApplication::translate("TracedFunctionsWidget", "Form", nullptr));
        label->setText(QCoreApplication::translate("TracedFunctionsWidget", "TRACED FUNCTIONS", nullptr));
    } // retranslateUi

};

namespace Ui {
    class TracedFunctionsWidget: public Ui_TracedFunctionsWidget {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_TRACEDFUNCTIONSWIDGET_H
