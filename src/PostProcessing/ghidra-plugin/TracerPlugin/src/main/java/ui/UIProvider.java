package ui;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JToolTip;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;

import org.apache.commons.lang3.StringUtils;

import db.DatabaseManager;
import docking.ActionContext;
import docking.ComponentProvider;
import docking.DialogComponentProvider;
import docking.DialogComponentProviderPopupActionManager;
import docking.DockingWindowManager;
import docking.action.DockingAction;
import docking.action.ToggleDockingAction;
import docking.action.ToolBarData;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.DataToStringConverter;
import docking.widgets.DefaultDropDownSelectionDataModel;
import docking.widgets.DropDownSelectionTextField;
import docking.widgets.DropDownTextFieldDataModel;
import docking.widgets.EventTrigger;
import docking.widgets.button.GRadioButton;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.Plugin;
import ghidra.graph.job.FilterVerticesJob;
import ghidra.graph.viewer.GraphViewer;
import ghidra.graph.viewer.PathHighlightMode;
import ghidra.graph.viewer.VisualGraphView;
import ghidra.graph.viewer.VisualGraphViewUpdater;
import ghidra.graph.viewer.event.mouse.VertexTooltipProvider;
import ghidra.graph.viewer.layout.JungLayoutProvider;
import ghidra.graph.viewer.layout.JungLayoutProviderFactory;
import ghidra.graph.viewer.layout.LayoutProvider;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.SwingUpdateManager;
import ghidra.util.task.TaskMonitor;
import graph.TaintEdge;
import graph.TaintGraph;
import graph.TaintGraphProvider;
import graph.TaintPlugin;
import graph.TaintVertex;
import graph.layout.TaintGraphPluginDependencyLayoutProvider;
import program.ProgramOperator;
import resources.Icons;
import taint.TaintData;
import taint.TaintEvent;

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
	private Plugin plugin;
	
	public UIProvider(Plugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		this.plugin = plugin;
		
		buildPanel();
		//addToTool();
		
		//createActions();
		//buildComponent();
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
				List<CodeUnit> taintedCodeUnits = progOperator.taintGhidraInstructionsWithTaintEvents(eventList);
				TaintData tData = new TaintData();
				tData.setCodeUnitList(taintedCodeUnits);
				tData.setTaintEventList(eventList);
				progOperator.drawTaintEventsGraph(plugin, mainPanel, tData);
			} catch (Exception ex) {
				System.err.println("Error tainting ghidra program using taint events");
				ex.printStackTrace();
			}
		}	
	}
}