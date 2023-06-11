#ifndef TREEWIDGETITEMCOLOURABLEDELEGATE_H
#define TREEWIDGETITEMCOLOURABLEDELEGATE_H

#include <QTreeWidget>
#include <QStyledItemDelegate>
#include <QPainter>

class TreeWidgetItemColourableDelegate : public QStyledItemDelegate
{
public:
    QList<QModelIndex>* coloredIndexes;

	TreeWidgetItemColourableDelegate(QList<QModelIndex>* indexes) {
		this->coloredIndexes = indexes;
	}

	void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override
	{
		int row = index.row();

		if (this->coloredIndexes->contains(index)) {
			painter->fillRect(option.rect, QColor(254, 130, 0));
		}

		QStyledItemDelegate::paint(painter, option, index);
	}
};


#endif // !TREEWIDGETITEMHEADER_H
