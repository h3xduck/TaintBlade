package graph;

import ghidra.graph.graphs.FilteringVisualGraph;
import ghidra.graph.viewer.layout.VisualGraphLayout;

public class TaintGraph extends FilteringVisualGraph<TaintVertex, TaintEdge>{

	private VisualGraphLayout<TaintVertex, TaintEdge> layout;

	@Override
	public VisualGraphLayout<TaintVertex, TaintEdge> getLayout() {
		return layout;
	}

	@Override
	public TaintGraph copy() {
		TaintGraph newGraph = new TaintGraph();

		for (TaintVertex v : vertices.keySet()) {
			newGraph.addVertex(v);
		}

		for (TaintEdge e : edges.keySet()) {
			newGraph.addEdge(e);
		}

		return newGraph;
	}

	public void setLayout(VisualGraphLayout<TaintVertex, TaintEdge> layout) {
		this.layout = layout;
	}

}
