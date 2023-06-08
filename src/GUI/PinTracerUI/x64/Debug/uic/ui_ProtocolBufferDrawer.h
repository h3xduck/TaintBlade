/********************************************************************************
** Form generated from reading UI file 'ProtocolBufferDrawer.ui'
**
** Created by: Qt User Interface Compiler version 6.5.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_PROTOCOLBUFFERDRAWER_H
#define UI_PROTOCOLBUFFERDRAWER_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_ProtocolBufferDrawer
{
public:
    QHBoxLayout *horizontalLayout;

    void setupUi(QWidget *ProtocolBufferDrawer)
    {
        if (ProtocolBufferDrawer->objectName().isEmpty())
            ProtocolBufferDrawer->setObjectName("ProtocolBufferDrawer");
        ProtocolBufferDrawer->resize(90, 130);
        QSizePolicy sizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(ProtocolBufferDrawer->sizePolicy().hasHeightForWidth());
        ProtocolBufferDrawer->setSizePolicy(sizePolicy);
        horizontalLayout = new QHBoxLayout(ProtocolBufferDrawer);
        horizontalLayout->setObjectName("horizontalLayout");

        retranslateUi(ProtocolBufferDrawer);

        QMetaObject::connectSlotsByName(ProtocolBufferDrawer);
    } // setupUi

    void retranslateUi(QWidget *ProtocolBufferDrawer)
    {
        ProtocolBufferDrawer->setWindowTitle(QCoreApplication::translate("ProtocolBufferDrawer", "Form", nullptr));
    } // retranslateUi

};

namespace Ui {
    class ProtocolBufferDrawer: public Ui_ProtocolBufferDrawer {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_PROTOCOLBUFFERDRAWER_H
