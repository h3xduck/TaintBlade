package program;

import java.util.ArrayList;

import db.TaintEvent;
import docking.Tool;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;

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
	
	public void taintGhidraInstructionsWithTaintEvents(ArrayList<TaintEvent> eventList) {
		if(this.tool == null || this.currentProgram == null) {
			throw new IllegalStateException("Cannot operate with the program, it was not correctly initialized");
		}
		
		Address baseOffsetAddress = currentProgram.getImageBase();
		AddressFactory addrFactory = this.currentProgram.getAddressFactory();
		for(TaintEvent event : eventList) {
			Address address = addrFactory.getAddress(Long.toHexString(event.getInstAddress())); 
			address = address.add(baseOffsetAddress.getOffset());
			//System.out.println("Searching at address "+address+ " from event address "+event.getInstAddress());
			CodeUnit codeUnit = currentProgram.getListing().getCodeUnitAt(address);
			this.taintManager.taintCodeUnit(codeUnit, taintManager.getColorFromEventType(event.getEventType()), true, taintManager.getCommentFromEventType(event.getEventType()));
			//System.out.println("MIN: "+codeUnit.getMinAddress()+" | MAX: "+codeUnit.getMaxAddress());
		}
	}
}
