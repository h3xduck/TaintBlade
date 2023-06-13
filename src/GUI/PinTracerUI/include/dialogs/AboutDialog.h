#ifndef ABOUTDIALOG_H
#define ABOUTDIALOG_H

#include <QDialog>
#include <QLineEdit>
#include <QFileDialog>
#include "common/Globals.h"
#include <QObject>
#include <QGraphicsRectItem>
#include <QLabel>
#include <QHBoxLayout>

QT_BEGIN_NAMESPACE
namespace Ui { class AboutDialog; }
QT_END_NAMESPACE

class AboutDialog : public QDialog
{
    //Q_OBJECT

public:
    AboutDialog(QWidget* parent = nullptr);
    ~AboutDialog();

private:
    Ui::AboutDialog* ui;
};

#endif
