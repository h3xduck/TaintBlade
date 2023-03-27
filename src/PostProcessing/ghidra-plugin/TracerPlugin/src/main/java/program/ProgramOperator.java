package program;

import java.util.ArrayList;
import java.util.List;

import javax.swing.JPanel;

import docking.DockingWindowManager;
import docking.Tool;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.GraphException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
//import graph.CodeGraphManager;
import graph.GraphManager;
import graph.TaintGraphProvider;
import taint.TaintData;
import taint.TaintEvent;
import taint.TaintManager;

public class ProgramOperator {
	private Program currentProgram;
	private Tool tool;
	private TaintManager taintManager;
	
	public ProgramOperator(Tool tool) {
		this.tool = tool;
		ProgramManager programManager = this.tool.getService(ProgramManager.class);
		if (programManager == null) {
            System.err.println("Could not access ProgramManager service");
            return;
        }
		this.currentProgram = programManager.getCurrentProgram();
		if (currentProgram == null) {
            System.err.println("Could not open ghidra program");
            return;
        }
		this.taintManager = new TaintManager(tool);
	}
	
	/**
	 * Taints program instructions on display with colors and comments depending on the taint events
	 * in the DB. Returns list of CodeUnits that were tainted, ordered.
	 * @param eventList
	 * @return
	 */
	public List<CodeUnit> taintGhidraInstructionsWithTaintEvents(ArrayList<TaintEvent> eventList) {
		if(this.tool == null || this.currentProgram == null) {
			throw new IllegalStateException("Cannot operate with the program, it was not correctly initialized");
		}
		
		List<CodeUnit> taintedCodeUnits = new ArrayList<CodeUnit>();
		
		Address baseOffsetAddress = currentProgram.getImageBase();
		AddressFactory addrFactory = this.currentProgram.getAddressFactory();
		for(TaintEvent event : eventList) {
			Address address = addrFactory.getAddress(Long.toHexString(event.getInstAddress())); 
			address = address.add(baseOffsetAddress.getOffset());
			//System.out.println("Searching at address "+address+ " from event address "+event.getInstAddress());
			CodeUnit codeUnit = currentProgram.getListing().getCodeUnitAt(address);
			taintedCodeUnits.add(codeUnit);
			this.taintManager.taintCodeUnit(codeUnit, taintManager.getColorFromEventType(event.getEventType()), true, taintManager.getCommentFromEventType(event.getEventType()));
			//System.out.println("MIN: "+codeUnit.getMinAddress()+" | MAX: "+codeUnit.getMaxAddress());
		}
		return taintedCodeUnits;
	}
	
	/**
	 * Spawns new window and draws the taint graph, or reuses existing window with already drawn graph
	 * @param plugin
	 * @param mainPanel
	 * @param taintData
	 */
	public void drawTaintEventsGraph(Plugin plugin, JPanel mainPanel, TaintData taintData) {
		/*try {
			GraphManager gManager = new GraphManager(this.tool);
			gManager.generateGraphFromTaintEvents();
		} catch (GraphException | CancelledException e) {
			e.printStackTrace();
		}*/
		DockingWindowManager dockWinManager = DockingWindowManager.getInstance(mainPanel);
		TaintGraphProvider provider = dockWinManager.getComponentProvider(TaintGraphProvider.class);
		if(provider == null) {
			TaintGraphProvider taintGraphProvider = new TaintGraphProvider(plugin.getTool(), plugin, taintData);
			dockWinManager.addComponent(taintGraphProvider);
		}else {
			dockWinManager.toFront(provider);
		}
		System.out.println(provider);
	}
}
