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
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSplitter>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MultiWindowViewWidget
{
public:
    QVBoxLayout *verticalLayout_2;
    QSplitter *splitter;
    QFrame *frameUp;
    QVBoxLayout *verticalLayout_4;
    QFrame *frameDown;
    QVBoxLayout *verticalLayout_3;
    QPushButton *pushButton_2;

    void setupUi(QWidget *MultiWindowViewWidget)
    {
        if (MultiWindowViewWidget->objectName().isEmpty())
            MultiWindowViewWidget->setObjectName("MultiWindowViewWidget");
        MultiWindowViewWidget->resize(481, 338);
        QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(MultiWindowViewWidget->sizePolicy().hasHeightForWidth());
        MultiWindowViewWidget->setSizePolicy(sizePolicy);
        verticalLayout_2 = new QVBoxLayout(MultiWindowViewWidget);
        verticalLayout_2->setObjectName("verticalLayout_2");
        splitter = new QSplitter(MultiWindowViewWidget);
        splitter->setObjectName("splitter");
        splitter->setOrientation(Qt::Vertical);
        frameUp = new QFrame(splitter);
        frameUp->setObjectName("frameUp");
        verticalLayout_4 = new QVBoxLayout(frameUp);
        verticalLayout_4->setObjectName("verticalLayout_4");
        splitter->addWidget(frameUp);
        frameDown = new QFrame(splitter);
        frameDown->setObjectName("frameDown");
        frameDown->setFrameShape(QFrame::StyledPanel);
        frameDown->setFrameShadow(QFrame::Raised);
        verticalLayout_3 = new QVBoxLayout(frameDown);
        verticalLayout_3->setObjectName("verticalLayout_3");
        pushButton_2 = new QPushButton(frameDown);
        pushButton_2->setObjectName("pushButton_2");

        verticalLayout_3->addWidget(pushButton_2);

        splitter->addWidget(frameDown);

        verticalLayout_2->addWidget(splitter);


        retranslateUi(MultiWindowViewWidget);

        QMetaObject::connectSlotsByName(MultiWindowViewWidget);
    } // setupUi

    void retranslateUi(QWidget *MultiWindowViewWidget)
    {
        MultiWindowViewWidget->setWindowTitle(QCoreApplication::translate("MultiWindowViewWidget", "Form", nullptr));
        pushButton_2->setText(QCoreApplication::translate("MultiWindowViewWidget", "PushButton", nullptr));
    } // retranslateUi

};

namespace Ui {
    class MultiWindowViewWidget: public Ui_MultiWindowViewWidget {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MULTIWINDOWVIEWWIDGET_H
