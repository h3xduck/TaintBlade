package taint;

import java.util.List;

import ghidra.program.model.listing.CodeUnit;

public class TaintData {
	private List<TaintEvent> taintEventList;
	private List<CodeUnit> codeUnitList;
	
	public List<TaintEvent> getTaintEventList() {
		return taintEventList;
	}
	public void setTaintEventList(List<TaintEvent> taintEventList) {
		this.taintEventList = taintEventList;
	}
	public List<CodeUnit> getCodeUnitList() {
		return codeUnitList;
	}
	public void setCodeUnitList(List<CodeUnit> codeUnitList) {
		this.codeUnitList = codeUnitList;
	}
	public boolean contains(CodeUnit o) {
		return codeUnitList.contains(o);
	}
	public boolean add(CodeUnit e) {
		return codeUnitList.add(e);
	}
	public boolean remove(CodeUnit o) {
		return codeUnitList.remove(o);
	}
	public boolean contains(TaintEvent o) {
		return taintEventList.contains(o);
	}
	public boolean add(TaintEvent e) {
		return taintEventList.add(e);
	}
	public boolean remove(TaintEvent o) {
		return taintEventList.remove(o);
	}

}
