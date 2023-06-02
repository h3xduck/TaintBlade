/********************************************************************************
** Form generated from reading UI file 'mainwindow.ui'
**
** Created by: Qt User Interface Compiler version 6.5.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenu>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QToolBar>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QAction *actionProperties;
    QAction *actionExit;
    QAction *actionOpen;
    QAction *actionSelect_configuration;
    QAction *actionRun;
    QAction *actionStop;
    QAction *actionTracepoints;
    QAction *actionTaint_sources;
    QAction *actionNOP_sections;
    QAction *actionAuthors;
    QWidget *centralWidget;
    QMenuBar *menubar;
    QMenu *menuFile;
    QMenu *menuAbout;
    QMenu *menuView;
    QMenu *menuTracer;
    QMenu *menuOptions;
    QMenu *menuAdvanced;
    QStatusBar *statusbar;
    QToolBar *toolBar;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName("MainWindow");
        MainWindow->resize(808, 588);
        actionProperties = new QAction(MainWindow);
        actionProperties->setObjectName("actionProperties");
        QIcon icon;
        QString iconThemeName = QString::fromUtf8("audio-volume-medium");
        if (QIcon::hasThemeIcon(iconThemeName)) {
            icon = QIcon::fromTheme(iconThemeName);
        } else {
            icon.addFile(QString::fromUtf8(":/res/icons/icons8-dll-26.png"), QSize(), QIcon::Normal, QIcon::Off);
        }
        actionProperties->setIcon(icon);
        actionExit = new QAction(MainWindow);
        actionExit->setObjectName("actionExit");
        actionOpen = new QAction(MainWindow);
        actionOpen->setObjectName("actionOpen");
        QIcon icon1;
        icon1.addFile(QString::fromUtf8(":/res/icons/icons8-opened-folder-26.png"), QSize(), QIcon::Normal, QIcon::Off);
        actionOpen->setIcon(icon1);
        actionSelect_configuration = new QAction(MainWindow);
        actionSelect_configuration->setObjectName("actionSelect_configuration");
        QIcon icon2;
        icon2.addFile(QString::fromUtf8(":/res/icons/icons8-log-26.png"), QSize(), QIcon::Normal, QIcon::Off);
        actionSelect_configuration->setIcon(icon2);
        actionRun = new QAction(MainWindow);
        actionRun->setObjectName("actionRun");
        QIcon icon3;
        icon3.addFile(QString::fromUtf8(":/res/icons/icons8-start-26.png"), QSize(), QIcon::Normal, QIcon::Off);
        actionRun->setIcon(icon3);
        actionStop = new QAction(MainWindow);
        actionStop->setObjectName("actionStop");
        QIcon icon4;
        icon4.addFile(QString::fromUtf8(":/res/icons/icons8-stop-26.png"), QSize(), QIcon::Normal, QIcon::Off);
        actionStop->setIcon(icon4);
        actionTracepoints = new QAction(MainWindow);
        actionTracepoints->setObjectName("actionTracepoints");
        QIcon icon5;
        icon5.addFile(QString::fromUtf8(":/res/icons/icons8-select-26.png"), QSize(), QIcon::Normal, QIcon::Off);
        actionTracepoints->setIcon(icon5);
        actionTaint_sources = new QAction(MainWindow);
        actionTaint_sources->setObjectName("actionTaint_sources");
        QIcon icon6;
        icon6.addFile(QString::fromUtf8(":/res/icons/icons8-flag-filled-26.png"), QSize(), QIcon::Normal, QIcon::Off);
        actionTaint_sources->setIcon(icon6);
        actionNOP_sections = new QAction(MainWindow);
        actionNOP_sections->setObjectName("actionNOP_sections");
        QIcon icon7;
        icon7.addFile(QString::fromUtf8(":/res/icons/icons8-knight-26.png"), QSize(), QIcon::Normal, QIcon::Off);
        actionNOP_sections->setIcon(icon7);
        actionAuthors = new QAction(MainWindow);
        actionAuthors->setObjectName("actionAuthors");
        centralWidget = new QWidget(MainWindow);
        centralWidget->setObjectName("centralWidget");
        MainWindow->setCentralWidget(centralWidget);
        menubar = new QMenuBar(MainWindow);
        menubar->setObjectName("menubar");
        menubar->setGeometry(QRect(0, 0, 808, 26));
        menuFile = new QMenu(menubar);
        menuFile->setObjectName("menuFile");
        menuAbout = new QMenu(menubar);
        menuAbout->setObjectName("menuAbout");
        menuView = new QMenu(menubar);
        menuView->setObjectName("menuView");
        menuTracer = new QMenu(menubar);
        menuTracer->setObjectName("menuTracer");
        menuOptions = new QMenu(menubar);
        menuOptions->setObjectName("menuOptions");
        menuAdvanced = new QMenu(menubar);
        menuAdvanced->setObjectName("menuAdvanced");
        MainWindow->setMenuBar(menubar);
        statusbar = new QStatusBar(MainWindow);
        statusbar->setObjectName("statusbar");
        MainWindow->setStatusBar(statusbar);
        toolBar = new QToolBar(MainWindow);
        toolBar->setObjectName("toolBar");
        MainWindow->addToolBar(Qt::TopToolBarArea, toolBar);

        menubar->addAction(menuFile->menuAction());
        menubar->addAction(menuView->menuAction());
        menubar->addAction(menuTracer->menuAction());
        menubar->addAction(menuOptions->menuAction());
        menubar->addAction(menuAdvanced->menuAction());
        menubar->addAction(menuAbout->menuAction());
        menuFile->addAction(actionOpen);
        menuFile->addAction(actionSelect_configuration);
        menuFile->addSeparator();
        menuFile->addAction(actionProperties);
        menuFile->addSeparator();
        menuFile->addAction(actionExit);
        menuAbout->addAction(actionAuthors);
        menuTracer->addAction(actionRun);
        menuTracer->addAction(actionStop);
        menuOptions->addAction(actionTracepoints);
        menuOptions->addAction(actionTaint_sources);
        menuAdvanced->addAction(actionNOP_sections);
        toolBar->addAction(actionOpen);
        toolBar->addAction(actionSelect_configuration);
        toolBar->addSeparator();
        toolBar->addAction(actionRun);
        toolBar->addAction(actionStop);
        toolBar->addSeparator();
        toolBar->addAction(actionTaint_sources);
        toolBar->addAction(actionTracepoints);
        toolBar->addAction(actionNOP_sections);
        toolBar->addAction(actionProperties);

        retranslateUi(MainWindow);

        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        MainWindow->setWindowTitle(QCoreApplication::translate("MainWindow", "MainWindow", nullptr));
        actionProperties->setText(QCoreApplication::translate("MainWindow", "DLL selector", nullptr));
        actionExit->setText(QCoreApplication::translate("MainWindow", "Exit", nullptr));
        actionOpen->setText(QCoreApplication::translate("MainWindow", "Open", nullptr));
        actionSelect_configuration->setText(QCoreApplication::translate("MainWindow", "PIN configuration", nullptr));
#if QT_CONFIG(tooltip)
        actionSelect_configuration->setToolTip(QCoreApplication::translate("MainWindow", "PIN configuration", nullptr));
#endif // QT_CONFIG(tooltip)
        actionRun->setText(QCoreApplication::translate("MainWindow", "Run", nullptr));
        actionStop->setText(QCoreApplication::translate("MainWindow", "Stop", nullptr));
        actionTracepoints->setText(QCoreApplication::translate("MainWindow", "Tracepoints", nullptr));
        actionTaint_sources->setText(QCoreApplication::translate("MainWindow", "Taint sources", nullptr));
        actionNOP_sections->setText(QCoreApplication::translate("MainWindow", "NOP sections", nullptr));
        actionAuthors->setText(QCoreApplication::translate("MainWindow", "About", nullptr));
        menuFile->setTitle(QCoreApplication::translate("MainWindow", "File", nullptr));
        menuAbout->setTitle(QCoreApplication::translate("MainWindow", "Help", nullptr));
        menuView->setTitle(QCoreApplication::translate("MainWindow", "View", nullptr));
        menuTracer->setTitle(QCoreApplication::translate("MainWindow", "Tracer", nullptr));
        menuOptions->setTitle(QCoreApplication::translate("MainWindow", "Options", nullptr));
        menuAdvanced->setTitle(QCoreApplication::translate("MainWindow", "Advanced", nullptr));
        toolBar->setWindowTitle(QCoreApplication::translate("MainWindow", "toolBar", nullptr));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H