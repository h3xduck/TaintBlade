#ifndef COLORANIMABLETREEWIDGETITEM_H
#define COLORANIMABLETREEWIDGETITEM_H

#include <QTreeWidget>
#include <QStyledItemDelegate>
#include <QPainter>

//DEPRECATED, NOT USED
class ColorAnimableTreeWidgetItem : public QWidget, public QTreeWidgetItem
{
    Q_OBJECT
    Q_PROPERTY(QColor color READ getColor WRITE setColor)
public:
    ColorAnimableTreeWidgetItem() : QTreeWidgetItem() {}
    
    void setColor(QColor color) 
    {
        QString styleSheet = QString("background-color: rgb(%1, %2, %3);").arg(color.red()).arg(color.green()).arg(color.blue());
        this->setStyleSheet(styleSheet);
        this->color_ = color;
    }
    QColor getColor() { return this->color_; }

private:
    QColor color_ = Qt::white;
};


#endif // !TREEWIDGETITEMHEADER_H
