package graph;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;

public class GraphTaskMonitor implements TaskMonitor {

	@Override
	public boolean isCancelled() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void setShowProgressValue(boolean showProgressValue) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setMessage(String message) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public String getMessage() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setProgress(long value) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void initialize(long max) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setMaximum(long max) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public long getMaximum() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public void setIndeterminate(boolean indeterminate) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public boolean isIndeterminate() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void checkCanceled() throws CancelledException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void incrementProgress(long incrementAmount) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public long getProgress() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public void cancel() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void addCancelledListener(CancelledListener listener) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void removeCancelledListener(CancelledListener listener) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setCancelEnabled(boolean enable) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public boolean isCancelEnabled() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void clearCanceled() {
		// TODO Auto-generated method stub
		
	}

}
