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
#include <QtWidgets/QButtonGroup>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QRadioButton>
#include <QtWidgets/QScrollArea>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_ProtocolVisualizationWidget
{
public:
    QVBoxLayout *verticalLayout;
    QLabel *label;
    QHBoxLayout *horizontalLayout;
    QVBoxLayout *leftButtonColumn;
    QLabel *radioButtonLabel;
    QRadioButton *radioButton_3;
    QRadioButton *radioButton_4;
    QVBoxLayout *rightButtonColumn;
    QCheckBox *checkBox;
    QScrollArea *scrollArea;
    QWidget *scrollAreaWidgetContents;
    QButtonGroup *buttonGroup;

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

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName("horizontalLayout");
        leftButtonColumn = new QVBoxLayout();
        leftButtonColumn->setObjectName("leftButtonColumn");
        radioButtonLabel = new QLabel(ProtocolVisualizationWidget);
        radioButtonLabel->setObjectName("radioButtonLabel");

        leftButtonColumn->addWidget(radioButtonLabel);

        radioButton_3 = new QRadioButton(ProtocolVisualizationWidget);
        buttonGroup = new QButtonGroup(ProtocolVisualizationWidget);
        buttonGroup->setObjectName("buttonGroup");
        buttonGroup->addButton(radioButton_3);
        radioButton_3->setObjectName("radioButton_3");

        leftButtonColumn->addWidget(radioButton_3);

        radioButton_4 = new QRadioButton(ProtocolVisualizationWidget);
        buttonGroup->addButton(radioButton_4);
        radioButton_4->setObjectName("radioButton_4");

        leftButtonColumn->addWidget(radioButton_4);


        horizontalLayout->addLayout(leftButtonColumn);

        rightButtonColumn = new QVBoxLayout();
        rightButtonColumn->setObjectName("rightButtonColumn");
        checkBox = new QCheckBox(ProtocolVisualizationWidget);
        checkBox->setObjectName("checkBox");

        rightButtonColumn->addWidget(checkBox);


        horizontalLayout->addLayout(rightButtonColumn);


        verticalLayout->addLayout(horizontalLayout);

        scrollArea = new QScrollArea(ProtocolVisualizationWidget);
        scrollArea->setObjectName("scrollArea");
        scrollArea->setWidgetResizable(true);
        scrollAreaWidgetContents = new QWidget();
        scrollAreaWidgetContents->setObjectName("scrollAreaWidgetContents");
        scrollAreaWidgetContents->setGeometry(QRect(0, 0, 1009, 467));
        scrollArea->setWidget(scrollAreaWidgetContents);

        verticalLayout->addWidget(scrollArea);


        retranslateUi(ProtocolVisualizationWidget);

        QMetaObject::connectSlotsByName(ProtocolVisualizationWidget);
    } // setupUi

    void retranslateUi(QWidget *ProtocolVisualizationWidget)
    {
        ProtocolVisualizationWidget->setWindowTitle(QCoreApplication::translate("ProtocolVisualizationWidget", "Form", nullptr));
        label->setText(QCoreApplication::translate("ProtocolVisualizationWidget", "PROTOCOL", nullptr));
        radioButtonLabel->setText(QCoreApplication::translate("ProtocolVisualizationWidget", "Color buffer bytes by...", nullptr));
        radioButton_3->setText(QCoreApplication::translate("ProtocolVisualizationWidget", "By word type", nullptr));
        radioButton_4->setText(QCoreApplication::translate("ProtocolVisualizationWidget", "By purpose", nullptr));
        checkBox->setText(QCoreApplication::translate("ProtocolVisualizationWidget", "CheckBox", nullptr));
    } // retranslateUi

};

namespace Ui {
    class ProtocolVisualizationWidget: public Ui_ProtocolVisualizationWidget {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_PROTOCOLVISUALIZATIONWIDGET_H
