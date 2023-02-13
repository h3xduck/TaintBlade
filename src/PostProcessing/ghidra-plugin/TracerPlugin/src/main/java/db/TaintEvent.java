package db;

public class TaintEvent {
	private Integer eventType = null;
	private Long funcIndex = null;
	private Long instAddress = null;
	private Long memAddress = null;
	private Integer color = null;
	private Integer parentColor1 = null;
	private Integer parentColor2;
	
	public Integer getEventType() {
		return eventType;
	}
	public void setEventType(Integer eventType) {
		this.eventType = eventType;
	}
	public Long getFuncIndex() {
		return funcIndex;
	}
	public void setFuncIndex(Long funcIndex) {
		this.funcIndex = funcIndex;
	}
	public Long getInstAddress() {
		return instAddress;
	}
	public void setInstAddress(Long instAddress) {
		this.instAddress = instAddress;
	}
	public Long getMemAddress() {
		return memAddress;
	}
	public void setMemAddress(Long memAddress) {
		this.memAddress = memAddress;
	}
	public Integer getColor() {
		return color;
	}
	public void setColor(Integer color) {
		this.color = color;
	}
	public Integer getParentColor1() {
		return parentColor1;
	}
	public void setParentColor1(Integer parentColor1) {
		this.parentColor1 = parentColor1;
	}
	public Integer getParentColor2() {
		return parentColor2;
	}
	public void setParentColor2(Integer parentColor2) {
		this.parentColor2 = parentColor2;
	}
	
	public TaintEvent(Integer eventType, Long funcIndex, Long instAddress, Long memAddress, Integer color,
			Integer parentColor1, Integer parentColor2) {
		this.eventType = eventType;
		this.funcIndex = funcIndex;
		this.instAddress = instAddress;
		this.memAddress = memAddress;
		this.color = color;
		this.parentColor1 = parentColor1;
		this.parentColor2 = parentColor2;
	}

}
