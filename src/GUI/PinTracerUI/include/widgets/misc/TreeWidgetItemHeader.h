#ifndef TREEWIDGETHEADERITEMDELEGATE_H
#define TREEWIDGETHEADERITEMDELEGATE_H

#include <QTreeWidget>
#include <QStyledItemDelegate>
#include <QPainter>

class TreeWidgetHeaderItemDelegate : public QStyledItemDelegate
{
public:
    TreeWidgetHeaderItemDelegate(QObject* parent = nullptr) : QStyledItemDelegate(parent) {}

    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override
    {
        // Check if the item is the first child
        if (index.row() == 0 && index.parent().isValid())
        {
            //Background for the header elements
            painter->fillRect(option.rect, QColor(230, 230, 230)); 
        }
        
        // Call the base class paint method
        QStyledItemDelegate::paint(painter, option, index);
    }
};


#endif // !TREEWIDGETITEMHEADER_H
