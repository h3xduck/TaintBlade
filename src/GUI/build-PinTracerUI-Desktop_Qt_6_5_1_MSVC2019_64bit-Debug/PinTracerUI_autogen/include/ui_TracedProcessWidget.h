/********************************************************************************
** Form generated from reading UI file 'TracedProcessWidget.ui'
**
** Created by: Qt User Interface Compiler version 6.5.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_TRACEDPROCESSWIDGET_H
#define UI_TRACEDPROCESSWIDGET_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_tracedProcessWidget
{
public:
    QVBoxLayout *verticalLayout;
    QListWidget *listWidget;

    void setupUi(QWidget *tracedProcessWidget)
    {
        if (tracedProcessWidget->objectName().isEmpty())
            tracedProcessWidget->setObjectName("tracedProcessWidget");
        tracedProcessWidget->resize(396, 209);
        QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(tracedProcessWidget->sizePolicy().hasHeightForWidth());
        tracedProcessWidget->setSizePolicy(sizePolicy);
        tracedProcessWidget->setBaseSize(QSize(7, 7));
        verticalLayout = new QVBoxLayout(tracedProcessWidget);
        verticalLayout->setObjectName("verticalLayout");
        listWidget = new QListWidget(tracedProcessWidget);
        listWidget->setObjectName("listWidget");

        verticalLayout->addWidget(listWidget);


        retranslateUi(tracedProcessWidget);

        QMetaObject::connectSlotsByName(tracedProcessWidget);
    } // setupUi

    void retranslateUi(QWidget *tracedProcessWidget)
    {
        tracedProcessWidget->setWindowTitle(QCoreApplication::translate("tracedProcessWidget", "Form", nullptr));
    } // retranslateUi

};

namespace Ui {
    class tracedProcessWidget: public Ui_tracedProcessWidget {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_TRACEDPROCESSWIDGET_H
