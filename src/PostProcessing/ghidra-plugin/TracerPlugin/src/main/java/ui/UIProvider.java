package ui;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;

import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableModel;

import db.DatabaseManager;
import db.TaintEvent;
import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import program.ProgramOperator;
import resources.Icons;
import java.sql.*;

public class UIProvider extends ComponentProvider {

	private DatabaseManager dbManager;
	private ProgramOperator progOperator = null;
	ArrayList<TaintEvent> eventList;
	
	private JPanel mainPanel;
	private DockingAction action;
	private Program currentProgram;
	private ProgramLocation currentLocation;
	private JLabel label;
	private JTextField textSelectedDB;
	private JTable table;
	JButton btnOpenDB;
	private JScrollPane scrollPane;
	
	public UIProvider(Plugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		buildPanel();
		//createActions();
	}

	// Customize GUI
	private void buildPanel() {
		this.mainPanel = new JPanel();
		this.mainPanel.setLayout(null);
		
		textSelectedDB = new JTextField();
		textSelectedDB.setToolTipText("SQLite Database");
		textSelectedDB.setBounds(20, 10, 333, 19);
		this.mainPanel.add(textSelectedDB);
		textSelectedDB.setColumns(10);
		
		
		btnOpenDB = new JButton("Select DB...");
		btnOpenDB.addActionListener(new SelectDB());
		btnOpenDB.setBounds(355, 9, 85, 21);
		this.mainPanel.add(btnOpenDB);
		
		setVisible(true);
		
	}

	@Override
	public JComponent getComponent() {
		return this.mainPanel;
	}
	
	
	private class SelectDB implements ActionListener {
		public void actionPerformed(ActionEvent e) {
			System.out.println("Button clicked");
			JFileChooser c = new JFileChooser();
			// Demonstrate "Open" dialog:
			int rVal = c.showOpenDialog(UIProvider.this.getComponent());
			if (rVal == JFileChooser.APPROVE_OPTION) {
				textSelectedDB.setText(c.getCurrentDirectory().toString()+"\\"+c.getSelectedFile().getName());
			}
			if (rVal == JFileChooser.CANCEL_OPTION) {
				textSelectedDB.setText("");
			}
			
			//Finished loading DB, now set it to load DB contents
			btnOpenDB.setText("Load DB contents");
			btnOpenDB.removeActionListener(this);
			btnOpenDB.addActionListener(new LoadDBContents());
		}	
	}
	
	private class LoadDBContents implements ActionListener {
		public void actionPerformed(ActionEvent e) {
			System.out.println("Loading DB contents...");
			
			JButton btnProgramTaintEvents = new JButton("Show in code");
			btnProgramTaintEvents.setBounds(20, 300, 105, 21);
			btnProgramTaintEvents.addActionListener(new ExecuteProgramTaintEvents());
			mainPanel.add(btnProgramTaintEvents);
			
			try {
		        Class.forName("org.sqlite.JDBC");		        
		        System.out.println("Connecting to jdbc:sqlite:"+textSelectedDB.getText());
		        
		        dbManager = new DatabaseManager(textSelectedDB.getText());
		        eventList = dbManager.getTaintEvents();

		        table = new JTable(new DefaultTableModel(new Object[]{"EVENT TYPE", "INDEX", "INST ADDRESS", "MEM ADDRESS", "COLOR", "PARENT COLOR 1", "PARENT COLOR 2"}, 0));
		        DefaultTableModel model = (DefaultTableModel) table.getModel();
		        
		        // Put events into table
		        for(TaintEvent event : eventList) {
		            model.addRow(new Object[]{
		            		event.getEventType(), 
		            		event.getFuncIndex(),
		            		event.getInstAddress(),
		            		event.getMemAddress(),
		            		event.getColor(),
		            		event.getParentColor1(),
		            		event.getParentColor2()
		            });
		        }
		        
		        scrollPane = new JScrollPane(table);
				scrollPane.setBounds(20, 39, 420, 251);
				table.setFillsViewportHeight(true);
				mainPanel.add(scrollPane);
				
				mainPanel.setVisible(true);
				progOperator = new ProgramOperator(dockingTool);
		        
			}catch(Exception ex) {
				System.out.println("Error querying database: "+ex.getMessage());
				ex.printStackTrace();
			}
		}	
	}
	
	private class ExecuteProgramTaintEvents implements ActionListener {
		public void actionPerformed(ActionEvent e) {
			System.out.println("Tainting program instructions with database events...");
			
			try {
				eventList = dbManager.getTaintEvents();
				progOperator.taintGhidraInstructionsWithTaintEvents(eventList);
			} catch (Exception ex) {
				System.err.println("Error tainting ghidra program using taint events");
				ex.printStackTrace();
			}
			
		}	
	}
}