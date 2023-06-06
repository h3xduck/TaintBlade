/********************************************************************************
** Form generated from reading UI file 'ProtocolBufferWidget.ui'
**
** Created by: Qt User Interface Compiler version 6.5.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_PROTOCOLBUFFERWIDGET_H
#define UI_PROTOCOLBUFFERWIDGET_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_ProtocolBufferWidget
{
public:
    QHBoxLayout *horizontalLayout;

    void setupUi(QWidget *ProtocolBufferWidget)
    {
        if (ProtocolBufferWidget->objectName().isEmpty())
            ProtocolBufferWidget->setObjectName("ProtocolBufferWidget");
        ProtocolBufferWidget->resize(90, 130);
        QSizePolicy sizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(ProtocolBufferWidget->sizePolicy().hasHeightForWidth());
        ProtocolBufferWidget->setSizePolicy(sizePolicy);
        horizontalLayout = new QHBoxLayout(ProtocolBufferWidget);
        horizontalLayout->setObjectName("horizontalLayout");

        retranslateUi(ProtocolBufferWidget);

        QMetaObject::connectSlotsByName(ProtocolBufferWidget);
    } // setupUi

    void retranslateUi(QWidget *ProtocolBufferWidget)
    {
        ProtocolBufferWidget->setWindowTitle(QCoreApplication::translate("ProtocolBufferWidget", "Form", nullptr));
    } // retranslateUi

};

namespace Ui {
    class ProtocolBufferWidget: public Ui_ProtocolBufferWidget {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_PROTOCOLBUFFERWIDGET_H
