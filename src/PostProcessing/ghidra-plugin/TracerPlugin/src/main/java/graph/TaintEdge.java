package graph;

import ghidra.graph.viewer.edge.AbstractVisualEdge;

public class TaintEdge extends AbstractVisualEdge<TaintVertex> {

	public TaintEdge(TaintVertex start, TaintVertex end) {
		super(start, end);
	}

	public TaintEdge cloneEdge(TaintVertex start, TaintVertex end) {
		return new TaintEdge(start, end);
	}
}