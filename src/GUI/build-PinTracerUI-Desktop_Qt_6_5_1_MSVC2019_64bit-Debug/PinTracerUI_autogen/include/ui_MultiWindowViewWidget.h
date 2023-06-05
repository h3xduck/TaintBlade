/********************************************************************************
** Form generated from reading UI file 'MultiWindowViewWidget.ui'
**
** Created by: Qt User Interface Compiler version 6.5.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MULTIWINDOWVIEWWIDGET_H
#define UI_MULTIWINDOWVIEWWIDGET_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QFrame>
#include <QtWidgets/QSplitter>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MultiWindowViewWidget
{
public:
    QVBoxLayout *verticalLayout;
    QSplitter *splitter_8;
    QSplitter *splitter_3;
    QSplitter *splitter;
    QFrame *frameTracedProcess;
    QVBoxLayout *verticalLayout_3;
    QFrame *frame_2;
    QSplitter *splitter_2;
    QSplitter *splitter_4;
    QWidget *widget;
    QFrame *frame;
    QFrame *frame_4;
    QSplitter *splitter_5;
    QSplitter *splitter_6;
    QFrame *frame_13;
    QFrame *frame_14;
    QSplitter *splitter_7;
    QFrame *frame_15;
    QFrame *frame_16;

    void setupUi(QWidget *MultiWindowViewWidget)
    {
        if (MultiWindowViewWidget->objectName().isEmpty())
            MultiWindowViewWidget->setObjectName("MultiWindowViewWidget");
        MultiWindowViewWidget->resize(689, 341);
        QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(MultiWindowViewWidget->sizePolicy().hasHeightForWidth());
        MultiWindowViewWidget->setSizePolicy(sizePolicy);
        verticalLayout = new QVBoxLayout(MultiWindowViewWidget);
        verticalLayout->setObjectName("verticalLayout");
        splitter_8 = new QSplitter(MultiWindowViewWidget);
        splitter_8->setObjectName("splitter_8");
        splitter_8->setOrientation(Qt::Horizontal);
        splitter_3 = new QSplitter(splitter_8);
        splitter_3->setObjectName("splitter_3");
        splitter_3->setOrientation(Qt::Vertical);
        splitter = new QSplitter(splitter_3);
        splitter->setObjectName("splitter");
        splitter->setOrientation(Qt::Horizontal);
        frameTracedProcess = new QFrame(splitter);
        frameTracedProcess->setObjectName("frameTracedProcess");
        frameTracedProcess->setFrameShape(QFrame::StyledPanel);
        frameTracedProcess->setFrameShadow(QFrame::Raised);
        verticalLayout_3 = new QVBoxLayout(frameTracedProcess);
        verticalLayout_3->setObjectName("verticalLayout_3");
        splitter->addWidget(frameTracedProcess);
        frame_2 = new QFrame(splitter);
        frame_2->setObjectName("frame_2");
        frame_2->setFrameShape(QFrame::StyledPanel);
        frame_2->setFrameShadow(QFrame::Raised);
        splitter->addWidget(frame_2);
        splitter_3->addWidget(splitter);
        splitter_2 = new QSplitter(splitter_3);
        splitter_2->setObjectName("splitter_2");
        splitter_2->setOrientation(Qt::Horizontal);
        splitter_4 = new QSplitter(splitter_2);
        splitter_4->setObjectName("splitter_4");
        splitter_4->setOrientation(Qt::Vertical);
        widget = new QWidget(splitter_4);
        widget->setObjectName("widget");
        frame = new QFrame(widget);
        frame->setObjectName("frame");
        frame->setGeometry(QRect(10, 10, 120, 80));
        frame->setFrameShape(QFrame::StyledPanel);
        frame->setFrameShadow(QFrame::Raised);
        splitter_4->addWidget(widget);
        frame_4 = new QFrame(splitter_4);
        frame_4->setObjectName("frame_4");
        frame_4->setFrameShape(QFrame::StyledPanel);
        frame_4->setFrameShadow(QFrame::Raised);
        splitter_4->addWidget(frame_4);
        splitter_2->addWidget(splitter_4);
        splitter_3->addWidget(splitter_2);
        splitter_8->addWidget(splitter_3);
        splitter_5 = new QSplitter(splitter_8);
        splitter_5->setObjectName("splitter_5");
        splitter_5->setOrientation(Qt::Vertical);
        splitter_6 = new QSplitter(splitter_5);
        splitter_6->setObjectName("splitter_6");
        splitter_6->setOrientation(Qt::Horizontal);
        frame_13 = new QFrame(splitter_6);
        frame_13->setObjectName("frame_13");
        frame_13->setFrameShape(QFrame::StyledPanel);
        frame_13->setFrameShadow(QFrame::Raised);
        splitter_6->addWidget(frame_13);
        frame_14 = new QFrame(splitter_6);
        frame_14->setObjectName("frame_14");
        frame_14->setFrameShape(QFrame::StyledPanel);
        frame_14->setFrameShadow(QFrame::Raised);
        splitter_6->addWidget(frame_14);
        splitter_5->addWidget(splitter_6);
        splitter_7 = new QSplitter(splitter_5);
        splitter_7->setObjectName("splitter_7");
        splitter_7->setOrientation(Qt::Horizontal);
        frame_15 = new QFrame(splitter_7);
        frame_15->setObjectName("frame_15");
        frame_15->setFrameShape(QFrame::StyledPanel);
        frame_15->setFrameShadow(QFrame::Raised);
        splitter_7->addWidget(frame_15);
        frame_16 = new QFrame(splitter_7);
        frame_16->setObjectName("frame_16");
        frame_16->setFrameShape(QFrame::StyledPanel);
        frame_16->setFrameShadow(QFrame::Raised);
        splitter_7->addWidget(frame_16);
        splitter_5->addWidget(splitter_7);
        splitter_8->addWidget(splitter_5);

        verticalLayout->addWidget(splitter_8);


        retranslateUi(MultiWindowViewWidget);

        QMetaObject::connectSlotsByName(MultiWindowViewWidget);
    } // setupUi

    void retranslateUi(QWidget *MultiWindowViewWidget)
    {
        MultiWindowViewWidget->setWindowTitle(QCoreApplication::translate("MultiWindowViewWidget", "Form", nullptr));
    } // retranslateUi

};

namespace Ui {
    class MultiWindowViewWidget: public Ui_MultiWindowViewWidget {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MULTIWINDOWVIEWWIDGET_H
