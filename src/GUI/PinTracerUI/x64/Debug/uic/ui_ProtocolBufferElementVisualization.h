/********************************************************************************
** Form generated from reading UI file 'ProtocolBufferElementVisualization.ui'
**
** Created by: Qt User Interface Compiler version 6.5.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_PROTOCOLBUFFERELEMENTVISUALIZATION_H
#define UI_PROTOCOLBUFFERELEMENTVISUALIZATION_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QScrollArea>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_ProtocolBufferElementVisualization
{
public:
    QVBoxLayout *verticalLayout_2;
    QLabel *label;
    QVBoxLayout *mainItemsLayout;
    QHBoxLayout *horizontalLayout;
    QLabel *bufferIndexLabel;
    QHBoxLayout *horizontalLayout_2;
    QLabel *wordTypeLabel;
    QPushButton *pointedByteButton;
    QScrollArea *scrollArea;
    QWidget *scrollAreaWidgetContents;
    QVBoxLayout *detailsLayout;
    QLabel *label_2;
    QTreeWidget *treeWidget;

    void setupUi(QWidget *ProtocolBufferElementVisualization)
    {
        if (ProtocolBufferElementVisualization->objectName().isEmpty())
            ProtocolBufferElementVisualization->setObjectName("ProtocolBufferElementVisualization");
        ProtocolBufferElementVisualization->resize(450, 592);
        verticalLayout_2 = new QVBoxLayout(ProtocolBufferElementVisualization);
        verticalLayout_2->setObjectName("verticalLayout_2");
        label = new QLabel(ProtocolBufferElementVisualization);
        label->setObjectName("label");
        QSizePolicy sizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(label->sizePolicy().hasHeightForWidth());
        label->setSizePolicy(sizePolicy);

        verticalLayout_2->addWidget(label);

        mainItemsLayout = new QVBoxLayout();
        mainItemsLayout->setObjectName("mainItemsLayout");
        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName("horizontalLayout");

        mainItemsLayout->addLayout(horizontalLayout);


        verticalLayout_2->addLayout(mainItemsLayout);

        bufferIndexLabel = new QLabel(ProtocolBufferElementVisualization);
        bufferIndexLabel->setObjectName("bufferIndexLabel");

        verticalLayout_2->addWidget(bufferIndexLabel);

        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName("horizontalLayout_2");
        wordTypeLabel = new QLabel(ProtocolBufferElementVisualization);
        wordTypeLabel->setObjectName("wordTypeLabel");

        horizontalLayout_2->addWidget(wordTypeLabel);

        pointedByteButton = new QPushButton(ProtocolBufferElementVisualization);
        pointedByteButton->setObjectName("pointedByteButton");
        QSizePolicy sizePolicy1(QSizePolicy::Fixed, QSizePolicy::Fixed);
        sizePolicy1.setHorizontalStretch(0);
        sizePolicy1.setVerticalStretch(0);
        sizePolicy1.setHeightForWidth(pointedByteButton->sizePolicy().hasHeightForWidth());
        pointedByteButton->setSizePolicy(sizePolicy1);

        horizontalLayout_2->addWidget(pointedByteButton);


        verticalLayout_2->addLayout(horizontalLayout_2);

        scrollArea = new QScrollArea(ProtocolBufferElementVisualization);
        scrollArea->setObjectName("scrollArea");
        scrollArea->setWidgetResizable(true);
        scrollAreaWidgetContents = new QWidget();
        scrollAreaWidgetContents->setObjectName("scrollAreaWidgetContents");
        scrollAreaWidgetContents->setGeometry(QRect(0, 0, 430, 239));
        scrollArea->setWidget(scrollAreaWidgetContents);

        verticalLayout_2->addWidget(scrollArea);

        detailsLayout = new QVBoxLayout();
        detailsLayout->setObjectName("detailsLayout");
        label_2 = new QLabel(ProtocolBufferElementVisualization);
        label_2->setObjectName("label_2");

        detailsLayout->addWidget(label_2);

        treeWidget = new QTreeWidget(ProtocolBufferElementVisualization);
        QTreeWidgetItem *__qtreewidgetitem = new QTreeWidgetItem();
        __qtreewidgetitem->setText(0, QString::fromUtf8("1"));
        treeWidget->setHeaderItem(__qtreewidgetitem);
        treeWidget->setObjectName("treeWidget");

        detailsLayout->addWidget(treeWidget);


        verticalLayout_2->addLayout(detailsLayout);


        retranslateUi(ProtocolBufferElementVisualization);

        QMetaObject::connectSlotsByName(ProtocolBufferElementVisualization);
    } // setupUi

    void retranslateUi(QWidget *ProtocolBufferElementVisualization)
    {
        ProtocolBufferElementVisualization->setWindowTitle(QCoreApplication::translate("ProtocolBufferElementVisualization", "Form", nullptr));
        label->setText(QCoreApplication::translate("ProtocolBufferElementVisualization", "PROTOCOL ELEMENT DETAILS:", nullptr));
        bufferIndexLabel->setText(QCoreApplication::translate("ProtocolBufferElementVisualization", "BUFFER INDEX: ", nullptr));
        wordTypeLabel->setText(QCoreApplication::translate("ProtocolBufferElementVisualization", "WORD TYPE: ", nullptr));
        pointedByteButton->setText(QCoreApplication::translate("ProtocolBufferElementVisualization", "Highlight pointed byte", nullptr));
        label_2->setText(QCoreApplication::translate("ProtocolBufferElementVisualization", "BYTES:", nullptr));
    } // retranslateUi

};

namespace Ui {
    class ProtocolBufferElementVisualization: public Ui_ProtocolBufferElementVisualization {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_PROTOCOLBUFFERELEMENTVISUALIZATION_H
