package taint;

import java.awt.Color;

import docking.Tool;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;

public class TaintManager {
	public static final Color UNDEFINED_TAINTCOLOR = new Color(214, 214, 214); 
	public static final Color UNTAINT_TAINTCOLOR = new Color(150, 150, 150); 
	public static final Color TAINT_TAINTCOLOR = new Color(250, 170, 100);
	public static final Color CHANGE_TAINTCOLOR = new Color(100, 252, 252); 
	public static final Color MIX_TAINTCOLOR = new Color(130, 255, 1); 
	public static final Color TAINTGEN_TAINTCOLOR = new Color(255, 0, 0); 
	public static final Color CHANGEGEN_TAINTCOLOR = new Color(255, 255, 0); 

	private Tool tool;

	public TaintManager(Tool tool){
		this.tool = tool;
	}
	
	public Color getColorFromEventType(Integer eventType) {
		switch(eventType) {
		case 1:
			return UNTAINT_TAINTCOLOR;
		case 2:
			return TAINT_TAINTCOLOR;
		case 3:
			return CHANGE_TAINTCOLOR;
		case 4:
			return MIX_TAINTCOLOR;
		case 5:
			return TAINTGEN_TAINTCOLOR;
		case 0:
		default:
			return CHANGEGEN_TAINTCOLOR;
		}
	}
	
	public String getCommentFromEventType(Integer eventType) {
		switch(eventType) {
		case 1:
			return "UNTAINT EVENT";
		case 2:
			return "TAINT EVENT";
		case 3:
			return "CHANGE EVENT";
		case 4:
			return "MIX EVENT";
		case 5:
			return "RULE TAINT EVENT";
		case 0:
		default:
			return "RULE CHANGE EVENT";
		}
	}
	
	public void taintCodeUnit(CodeUnit codeUnit, Color color, boolean includeComment, String comment) {
		Address addressMin = codeUnit.getMinAddress();
		Address addressMax = codeUnit.getMaxAddress();
		Program currentProgram = this.tool.getService(ProgramManager.class).getCurrentProgram();
		int transaction = currentProgram.startTransaction("Coloring code according to taint events");
		ColorizingService service = tool.getService(ColorizingService.class);
		if(service == null) {
			System.err.println("Could not get colorizing service");
			currentProgram.endTransaction(transaction, false);
			return;
		}
		if(includeComment) {
			codeUnit.setComment(CodeUnit.PRE_COMMENT, comment);
		}
		service.setBackgroundColor(addressMin, addressMax, color);
		currentProgram.endTransaction(transaction, true);

	}
}
