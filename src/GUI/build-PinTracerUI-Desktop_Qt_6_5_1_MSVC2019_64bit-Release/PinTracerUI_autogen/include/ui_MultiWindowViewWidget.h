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
    QSplitter *level1VSplitter;
    QSplitter *level2HSplitterLeft;
    QSplitter *level3VSplitterLeftUp;
    QFrame *frameLeftUpLeft;
    QVBoxLayout *verticalLayout_3;
    QFrame *frameLeftUpRight;
    QVBoxLayout *verticalLayout_4;
    QSplitter *level3VSplitterLeftDown;
    QFrame *frameLeftDownLeft;
    QVBoxLayout *verticalLayout_7;
    QFrame *frameLeftDownRight;
    QVBoxLayout *verticalLayout_5;
    QSplitter *level2HSplitterRight;
    QSplitter *level3VSplitterRightUp;
    QFrame *frameRightUpLeft;
    QVBoxLayout *verticalLayout_11;
    QFrame *frameRightUpRight;
    QVBoxLayout *verticalLayout_12;
    QSplitter *level3VSplitterRightDown;
    QFrame *frameRightDownLeft;
    QVBoxLayout *verticalLayout_13;
    QFrame *frameRightDownRight;
    QVBoxLayout *verticalLayout_14;

    void setupUi(QWidget *MultiWindowViewWidget)
    {
        if (MultiWindowViewWidget->objectName().isEmpty())
            MultiWindowViewWidget->setObjectName("MultiWindowViewWidget");
        MultiWindowViewWidget->resize(708, 353);
        QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(MultiWindowViewWidget->sizePolicy().hasHeightForWidth());
        MultiWindowViewWidget->setSizePolicy(sizePolicy);
        verticalLayout = new QVBoxLayout(MultiWindowViewWidget);
        verticalLayout->setObjectName("verticalLayout");
        level1VSplitter = new QSplitter(MultiWindowViewWidget);
        level1VSplitter->setObjectName("level1VSplitter");
        level1VSplitter->setOrientation(Qt::Horizontal);
        level2HSplitterLeft = new QSplitter(level1VSplitter);
        level2HSplitterLeft->setObjectName("level2HSplitterLeft");
        level2HSplitterLeft->setOrientation(Qt::Vertical);
        level3VSplitterLeftUp = new QSplitter(level2HSplitterLeft);
        level3VSplitterLeftUp->setObjectName("level3VSplitterLeftUp");
        level3VSplitterLeftUp->setOrientation(Qt::Horizontal);
        frameLeftUpLeft = new QFrame(level3VSplitterLeftUp);
        frameLeftUpLeft->setObjectName("frameLeftUpLeft");
        frameLeftUpLeft->setFrameShape(QFrame::StyledPanel);
        frameLeftUpLeft->setFrameShadow(QFrame::Raised);
        verticalLayout_3 = new QVBoxLayout(frameLeftUpLeft);
        verticalLayout_3->setObjectName("verticalLayout_3");
        level3VSplitterLeftUp->addWidget(frameLeftUpLeft);
        frameLeftUpRight = new QFrame(level3VSplitterLeftUp);
        frameLeftUpRight->setObjectName("frameLeftUpRight");
        frameLeftUpRight->setFrameShape(QFrame::StyledPanel);
        frameLeftUpRight->setFrameShadow(QFrame::Raised);
        verticalLayout_4 = new QVBoxLayout(frameLeftUpRight);
        verticalLayout_4->setObjectName("verticalLayout_4");
        level3VSplitterLeftUp->addWidget(frameLeftUpRight);
        level2HSplitterLeft->addWidget(level3VSplitterLeftUp);
        level3VSplitterLeftDown = new QSplitter(level2HSplitterLeft);
        level3VSplitterLeftDown->setObjectName("level3VSplitterLeftDown");
        level3VSplitterLeftDown->setOrientation(Qt::Horizontal);
        frameLeftDownLeft = new QFrame(level3VSplitterLeftDown);
        frameLeftDownLeft->setObjectName("frameLeftDownLeft");
        frameLeftDownLeft->setFrameShape(QFrame::StyledPanel);
        frameLeftDownLeft->setFrameShadow(QFrame::Raised);
        verticalLayout_7 = new QVBoxLayout(frameLeftDownLeft);
        verticalLayout_7->setObjectName("verticalLayout_7");
        level3VSplitterLeftDown->addWidget(frameLeftDownLeft);
        frameLeftDownRight = new QFrame(level3VSplitterLeftDown);
        frameLeftDownRight->setObjectName("frameLeftDownRight");
        frameLeftDownRight->setFrameShape(QFrame::StyledPanel);
        frameLeftDownRight->setFrameShadow(QFrame::Raised);
        verticalLayout_5 = new QVBoxLayout(frameLeftDownRight);
        verticalLayout_5->setObjectName("verticalLayout_5");
        level3VSplitterLeftDown->addWidget(frameLeftDownRight);
        level2HSplitterLeft->addWidget(level3VSplitterLeftDown);
        level1VSplitter->addWidget(level2HSplitterLeft);
        level2HSplitterRight = new QSplitter(level1VSplitter);
        level2HSplitterRight->setObjectName("level2HSplitterRight");
        level2HSplitterRight->setOrientation(Qt::Vertical);
        level3VSplitterRightUp = new QSplitter(level2HSplitterRight);
        level3VSplitterRightUp->setObjectName("level3VSplitterRightUp");
        level3VSplitterRightUp->setOrientation(Qt::Horizontal);
        frameRightUpLeft = new QFrame(level3VSplitterRightUp);
        frameRightUpLeft->setObjectName("frameRightUpLeft");
        frameRightUpLeft->setFrameShape(QFrame::StyledPanel);
        frameRightUpLeft->setFrameShadow(QFrame::Raised);
        verticalLayout_11 = new QVBoxLayout(frameRightUpLeft);
        verticalLayout_11->setObjectName("verticalLayout_11");
        level3VSplitterRightUp->addWidget(frameRightUpLeft);
        frameRightUpRight = new QFrame(level3VSplitterRightUp);
        frameRightUpRight->setObjectName("frameRightUpRight");
        frameRightUpRight->setFrameShape(QFrame::StyledPanel);
        frameRightUpRight->setFrameShadow(QFrame::Raised);
        verticalLayout_12 = new QVBoxLayout(frameRightUpRight);
        verticalLayout_12->setObjectName("verticalLayout_12");
        level3VSplitterRightUp->addWidget(frameRightUpRight);
        level2HSplitterRight->addWidget(level3VSplitterRightUp);
        level3VSplitterRightDown = new QSplitter(level2HSplitterRight);
        level3VSplitterRightDown->setObjectName("level3VSplitterRightDown");
        level3VSplitterRightDown->setOrientation(Qt::Horizontal);
        frameRightDownLeft = new QFrame(level3VSplitterRightDown);
        frameRightDownLeft->setObjectName("frameRightDownLeft");
        frameRightDownLeft->setFrameShape(QFrame::StyledPanel);
        frameRightDownLeft->setFrameShadow(QFrame::Raised);
        verticalLayout_13 = new QVBoxLayout(frameRightDownLeft);
        verticalLayout_13->setObjectName("verticalLayout_13");
        level3VSplitterRightDown->addWidget(frameRightDownLeft);
        frameRightDownRight = new QFrame(level3VSplitterRightDown);
        frameRightDownRight->setObjectName("frameRightDownRight");
        frameRightDownRight->setFrameShape(QFrame::StyledPanel);
        frameRightDownRight->setFrameShadow(QFrame::Raised);
        verticalLayout_14 = new QVBoxLayout(frameRightDownRight);
        verticalLayout_14->setObjectName("verticalLayout_14");
        level3VSplitterRightDown->addWidget(frameRightDownRight);
        level2HSplitterRight->addWidget(level3VSplitterRightDown);
        level1VSplitter->addWidget(level2HSplitterRight);

        verticalLayout->addWidget(level1VSplitter);


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
