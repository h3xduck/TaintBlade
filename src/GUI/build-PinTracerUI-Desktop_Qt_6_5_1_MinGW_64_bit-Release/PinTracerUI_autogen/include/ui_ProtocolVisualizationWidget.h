/********************************************************************************
** Form generated from reading UI file 'ProtocolVisualizationWidget.ui'
**
** Created by: Qt User Interface Compiler version 6.5.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_PROTOCOLVISUALIZATIONWIDGET_H
#define UI_PROTOCOLVISUALIZATIONWIDGET_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QLabel>
#include <QtWidgets/QScrollArea>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_ProtocolVisualizationWidget
{
public:
    QVBoxLayout *verticalLayout;
    QLabel *label;
    QScrollArea *scrollArea;
    QWidget *scrollAreaWidgetContents;

    void setupUi(QWidget *ProtocolVisualizationWidget)
    {
        if (ProtocolVisualizationWidget->objectName().isEmpty())
            ProtocolVisualizationWidget->setObjectName("ProtocolVisualizationWidget");
        ProtocolVisualizationWidget->resize(1029, 587);
        verticalLayout = new QVBoxLayout(ProtocolVisualizationWidget);
        verticalLayout->setObjectName("verticalLayout");
        label = new QLabel(ProtocolVisualizationWidget);
        label->setObjectName("label");

        verticalLayout->addWidget(label);

        scrollArea = new QScrollArea(ProtocolVisualizationWidget);
        scrollArea->setObjectName("scrollArea");
        scrollArea->setWidgetResizable(true);
        scrollAreaWidgetContents = new QWidget();
        scrollAreaWidgetContents->setObjectName("scrollAreaWidgetContents");
        scrollAreaWidgetContents->setGeometry(QRect(0, 0, 1005, 536));
        scrollArea->setWidget(scrollAreaWidgetContents);

        verticalLayout->addWidget(scrollArea);


        retranslateUi(ProtocolVisualizationWidget);

        QMetaObject::connectSlotsByName(ProtocolVisualizationWidget);
    } // setupUi

    void retranslateUi(QWidget *ProtocolVisualizationWidget)
    {
        ProtocolVisualizationWidget->setWindowTitle(QCoreApplication::translate("ProtocolVisualizationWidget", "Form", nullptr));
        label->setText(QCoreApplication::translate("ProtocolVisualizationWidget", "PROTOCOL", nullptr));
    } // retranslateUi

};

namespace Ui {
    class ProtocolVisualizationWidget: public Ui_ProtocolVisualizationWidget {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_PROTOCOLVISUALIZATIONWIDGET_H
