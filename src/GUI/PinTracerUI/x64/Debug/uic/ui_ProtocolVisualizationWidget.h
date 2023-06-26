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
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QRadioButton>
#include <QtWidgets/QScrollArea>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_ProtocolVisualizationWidget
{
public:
    QVBoxLayout *verticalLayout;
    QHBoxLayout *horizontalLayout_2;
    QLabel *label;
    QPushButton *viewRawProtocolButton;
    QHBoxLayout *horizontalLayout;
    QVBoxLayout *leftButtonColumn;
    QLabel *radioButtonLabel;
    QRadioButton *buttonColorWordType;
    QRadioButton *buttonColorPurpose;
    QVBoxLayout *rightButtonColumn;
    QScrollArea *scrollArea;
    QWidget *scrollAreaWidgetContents;
    QButtonGroup *buttonGroup;

    void setupUi(QWidget *ProtocolVisualizationWidget)
    {
        if (ProtocolVisualizationWidget->objectName().isEmpty())
            ProtocolVisualizationWidget->setObjectName("ProtocolVisualizationWidget");
        ProtocolVisualizationWidget->resize(929, 587);
        verticalLayout = new QVBoxLayout(ProtocolVisualizationWidget);
        verticalLayout->setObjectName("verticalLayout");
        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName("horizontalLayout_2");
        label = new QLabel(ProtocolVisualizationWidget);
        label->setObjectName("label");

        horizontalLayout_2->addWidget(label);

        viewRawProtocolButton = new QPushButton(ProtocolVisualizationWidget);
        viewRawProtocolButton->setObjectName("viewRawProtocolButton");
        QSizePolicy sizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(viewRawProtocolButton->sizePolicy().hasHeightForWidth());
        viewRawProtocolButton->setSizePolicy(sizePolicy);

        horizontalLayout_2->addWidget(viewRawProtocolButton);


        verticalLayout->addLayout(horizontalLayout_2);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName("horizontalLayout");
        leftButtonColumn = new QVBoxLayout();
        leftButtonColumn->setObjectName("leftButtonColumn");
        radioButtonLabel = new QLabel(ProtocolVisualizationWidget);
        radioButtonLabel->setObjectName("radioButtonLabel");

        leftButtonColumn->addWidget(radioButtonLabel);

        buttonColorWordType = new QRadioButton(ProtocolVisualizationWidget);
        buttonGroup = new QButtonGroup(ProtocolVisualizationWidget);
        buttonGroup->setObjectName("buttonGroup");
        buttonGroup->addButton(buttonColorWordType);
        buttonColorWordType->setObjectName("buttonColorWordType");
        buttonColorWordType->setChecked(true);

        leftButtonColumn->addWidget(buttonColorWordType);

        buttonColorPurpose = new QRadioButton(ProtocolVisualizationWidget);
        buttonGroup->addButton(buttonColorPurpose);
        buttonColorPurpose->setObjectName("buttonColorPurpose");

        leftButtonColumn->addWidget(buttonColorPurpose);


        horizontalLayout->addLayout(leftButtonColumn);

        rightButtonColumn = new QVBoxLayout();
        rightButtonColumn->setObjectName("rightButtonColumn");

        horizontalLayout->addLayout(rightButtonColumn);


        verticalLayout->addLayout(horizontalLayout);

        scrollArea = new QScrollArea(ProtocolVisualizationWidget);
        scrollArea->setObjectName("scrollArea");
        scrollArea->setWidgetResizable(true);
        scrollAreaWidgetContents = new QWidget();
        scrollAreaWidgetContents->setObjectName("scrollAreaWidgetContents");
        scrollAreaWidgetContents->setGeometry(QRect(0, 0, 909, 457));
        scrollArea->setWidget(scrollAreaWidgetContents);

        verticalLayout->addWidget(scrollArea);


        retranslateUi(ProtocolVisualizationWidget);

        QMetaObject::connectSlotsByName(ProtocolVisualizationWidget);
    } // setupUi

    void retranslateUi(QWidget *ProtocolVisualizationWidget)
    {
        ProtocolVisualizationWidget->setWindowTitle(QCoreApplication::translate("ProtocolVisualizationWidget", "Form", nullptr));
        label->setText(QCoreApplication::translate("ProtocolVisualizationWidget", "PROTOCOL", nullptr));
        viewRawProtocolButton->setText(QCoreApplication::translate("ProtocolVisualizationWidget", "View raw protocol", nullptr));
        radioButtonLabel->setText(QCoreApplication::translate("ProtocolVisualizationWidget", "Color buffer bytes by...", nullptr));
        buttonColorWordType->setText(QCoreApplication::translate("ProtocolVisualizationWidget", "By word type", nullptr));
        buttonColorPurpose->setText(QCoreApplication::translate("ProtocolVisualizationWidget", "By purpose", nullptr));
    } // retranslateUi

};

namespace Ui {
    class ProtocolVisualizationWidget: public Ui_ProtocolVisualizationWidget {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_PROTOCOLVISUALIZATIONWIDGET_H
