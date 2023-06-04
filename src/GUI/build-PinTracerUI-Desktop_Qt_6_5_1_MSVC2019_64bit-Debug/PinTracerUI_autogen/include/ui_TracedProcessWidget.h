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
#include <QtWidgets/QPushButton>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_tracedProcessWidget
{
public:
    QPushButton *pushButton;

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
        pushButton = new QPushButton(tracedProcessWidget);
        pushButton->setObjectName("pushButton");
        pushButton->setGeometry(QRect(20, 30, 75, 24));

        retranslateUi(tracedProcessWidget);

        QMetaObject::connectSlotsByName(tracedProcessWidget);
    } // setupUi

    void retranslateUi(QWidget *tracedProcessWidget)
    {
        tracedProcessWidget->setWindowTitle(QCoreApplication::translate("tracedProcessWidget", "Form", nullptr));
        pushButton->setText(QCoreApplication::translate("tracedProcessWidget", "PushButton", nullptr));
    } // retranslateUi

};

namespace Ui {
    class tracedProcessWidget: public Ui_tracedProcessWidget {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_TRACEDPROCESSWIDGET_H
