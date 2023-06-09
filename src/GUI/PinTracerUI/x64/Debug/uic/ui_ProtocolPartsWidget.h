/********************************************************************************
** Form generated from reading UI file 'ProtocolPartsWidget.ui'
**
** Created by: Qt User Interface Compiler version 6.5.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_PROTOCOLPARTSWIDGET_H
#define UI_PROTOCOLPARTSWIDGET_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QSplitter>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_ProtocolPartsWidget
{
public:
    QVBoxLayout *verticalLayout_4;
    QSplitter *splitterTop;
    QListWidget *topListWidget;
    QListWidget *midListWidget;
    QListWidget *botListWidget;

    void setupUi(QWidget *ProtocolPartsWidget)
    {
        if (ProtocolPartsWidget->objectName().isEmpty())
            ProtocolPartsWidget->setObjectName("ProtocolPartsWidget");
        ProtocolPartsWidget->resize(605, 449);
        verticalLayout_4 = new QVBoxLayout(ProtocolPartsWidget);
        verticalLayout_4->setObjectName("verticalLayout_4");
        splitterTop = new QSplitter(ProtocolPartsWidget);
        splitterTop->setObjectName("splitterTop");
        splitterTop->setOrientation(Qt::Vertical);
        topListWidget = new QListWidget(splitterTop);
        topListWidget->setObjectName("topListWidget");
        splitterTop->addWidget(topListWidget);
        midListWidget = new QListWidget(splitterTop);
        midListWidget->setObjectName("midListWidget");
        splitterTop->addWidget(midListWidget);
        botListWidget = new QListWidget(splitterTop);
        botListWidget->setObjectName("botListWidget");
        splitterTop->addWidget(botListWidget);

        verticalLayout_4->addWidget(splitterTop);


        retranslateUi(ProtocolPartsWidget);

        QMetaObject::connectSlotsByName(ProtocolPartsWidget);
    } // setupUi

    void retranslateUi(QWidget *ProtocolPartsWidget)
    {
        ProtocolPartsWidget->setWindowTitle(QCoreApplication::translate("ProtocolPartsWidget", "Form", nullptr));
    } // retranslateUi

};

namespace Ui {
    class ProtocolPartsWidget: public Ui_ProtocolPartsWidget {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_PROTOCOLPARTSWIDGET_H
