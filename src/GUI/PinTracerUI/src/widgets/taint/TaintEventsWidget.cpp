#include "widgets/taint/TaintEventsWidget.h"
#include "ui_TaintEventsWidget.h"

TaintEventsWidget::TaintEventsWidget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::TaintEventsWidget)
{
    ui->setupUi(this);
    this->layout()->setContentsMargins(0,0,0,0);
    globalDBManager.buildTaintEventsTree(ui->treeWidget, false);

    connect(ui->checkBox, SIGNAL(toggled(bool)), this, SLOT(toggleIndirectRoutinesVisualization(bool)));
    connect(ui->checkBoxGroupEvents, SIGNAL(toggled(bool)), this, SLOT(toggleGroupTaintEvents(bool)));
}

TaintEventsWidget::~TaintEventsWidget()
{
    delete ui;
}

void TaintEventsWidget::toggleIndirectRoutinesVisualization(bool activate)
{
    //Triggers when the user toggles the state of the checbox
    ui->treeWidget->clear();
    this->indirectRoutinesShow = activate;
    globalDBManager.buildTaintEventsTree(ui->treeWidget, this->indirectRoutinesShow);
    //Redirect to the slot where we check all checkboxes and hide some elements if the group checkbox is selected
    //This is needed in case we are already in group mode and we toggle the indirect routines button
    if (this->groupTaintEvents) {
        toggleGroupTaintEvents(this->groupTaintEvents);
    }
}

void TaintEventsWidget::toggleGroupTaintEvents(bool setting)
{
    //We will have to either hide some items from the tree or show them case the user wants the data back
    this->groupTaintEvents = setting;
    if (this->groupTaintEvents)
    {
        //We will have to group the events
        if (this->indirectRoutinesShow)
        {
            //If the indirect routines are being shown
            for (int ii = 0; ii < ui->treeWidget->topLevelItemCount(); ii++)
            {
                QTreeWidgetItem* item = ui->treeWidget->topLevelItem(ii);

                QString lastRoutineName = "";
                QString lastAddress = "";
                for (int jj = 0; jj < item->childCount(); jj++)
                {
                    QTreeWidgetItem* child = item->child(jj);
                    if (child->text(0) == lastRoutineName && child->text(1) == lastAddress)
                    {
                        //Hide the item
                        child->setHidden(true);
                        //Hide the taint details (not the direct child, but the second grandgrandchild) of the previous child, 
                        //not valid data when events are grouped. Not possible that we end up here for the first item.
                        item->child(jj - 1)->child(1)->child(1)->child(0)->setHidden(true);
                        item->child(jj - 1)->child(1)->child(1)->child(1)->setHidden(true);
                        //Also hide the color, no longer valid data. Just say it was "grouped"
                        item->child(jj - 1)->child(1)->child(1)->setText(1, "Grouped");
                    }

                    lastRoutineName = child->text(0);
                    lastAddress = child->text(1);
                }
            }
        }
        else
        {
            //If the indirect routines are hidden
            for (int ii = 0; ii < ui->treeWidget->topLevelItemCount(); ii++)
            {
                QTreeWidgetItem* item = ui->treeWidget->topLevelItem(ii);

                QString lastRoutineName = "";
                QString lastAddress = "";
                for (int jj = 0; jj < item->childCount(); jj++)
                {
                    QTreeWidgetItem* child = item->child(jj);
                    if (child->text(0) == lastRoutineName && child->text(1) == lastAddress)
                    {
                        //Hide the item
                        child->setHidden(true);
                        //Hide the taint details (not the direct child, but the second grandchild) of the previous child, 
                        //not valid data when events are grouped. Not possible that we end up here for the first item.
                        item->child(jj - 1)->child(1)->child(0)->setHidden(true);
                        item->child(jj - 1)->child(1)->child(1)->setHidden(true);
                        //Also hide the color, no longer valid data. Just say it was "grouped"
                        item->child(jj - 1)->child(1)->setText(1, "Grouped");
                    }

                    lastRoutineName = child->text(0);
                    lastAddress = child->text(1);
                }
            }
        }

    }
    else
    {
        //We will have to ungroup the events
        //Just query results from the DB. Not efficient, will do for now.
        globalDBManager.buildTaintEventsTree(ui->treeWidget, this->indirectRoutinesShow);
    }
}
