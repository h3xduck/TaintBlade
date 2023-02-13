package tracerplugin;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import java.awt.BorderLayout;
import javax.swing.BoxLayout;
import javax.swing.JTextField;

import docking.actions.DockingToolActions;

import java.awt.GridLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.Box;
import javax.swing.AbstractAction;
import java.awt.event.ActionEvent;
import javax.swing.Action;
import javax.swing.JTable;

public class TracerPanel extends JPanel {
	private JTextField txtLibr;
	private final Action action = new SwingAction();
	private JTable table;

	/**
	 * Create the panel.
	 */
	public TracerPanel() {
		setLayout(null);
		
		txtLibr = new JTextField();
		txtLibr.setToolTipText("SQLite Database");
		txtLibr.setBounds(20, 10, 333, 19);
		add(txtLibr);
		txtLibr.setColumns(10);
		
		JButton btnNewButton = new JButton("Load DB");
		btnNewButton.setAction(action);
		btnNewButton.setBounds(355, 9, 85, 21);
		add(btnNewButton);
		
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setBounds(20, 39, 420, 251);
		add(scrollPane);
		
		table = new JTable();
		scrollPane.setColumnHeaderView(table);
		
		JButton btnNewButton_1 = new JButton("Show in code");
		btnNewButton_1.setBounds(20, 300, 105, 21);
		add(btnNewButton_1);

	}
	private class SwingAction extends AbstractAction {
		public SwingAction() {
			putValue(NAME, "SwingAction");
			putValue(SHORT_DESCRIPTION, "Some short description");
		}
		public void actionPerformed(ActionEvent e) {
		}
	}
}
