package graph;

import docking.Tool;
import functioncalls.graph.FunctionCallGraph;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.graph.BlockFlowGraphType;
import ghidra.graph.CallGraphType;
import ghidra.service.graph.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.GraphException;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

/**
 * Example script for creating and displaying a graph in ghidra
 */
public class GraphManager {
	private AttributedGraph graph;
	//private FunctionGraph graph = new FunctionGraph();
	private int nextEdgeID = 1;
	private Tool tool;
	GraphTaskMonitor monitor;
	
	public GraphManager(Tool tool){
		this.monitor = new GraphTaskMonitor();
		this.tool = tool;
	}
	
	public void generateGraphFromTaintEvents() throws GraphException, CancelledException {
		GraphDisplayBroker service = tool.getService(GraphDisplayBroker.class);
		GraphDisplay display = service.getDefaultGraphDisplay(false, monitor);
		
		this.graph = new AttributedGraph(null, new BlockFlowGraphType());
		generateGraph();
		display.setGraph(graph, "Test", false, monitor);
		
	}

	private void generateGraph() {

		AttributedVertex A = vertex("A");
		AttributedVertex B = vertex("B");
		AttributedVertex C = vertex("C");
		AttributedVertex D = vertex("D");
		AttributedVertex z = new AttributedVertex("a");

		edge(A, B);
		edge(A, C);
		edge(B, D);
		edge(C, D);
		edge(D, A);
	}

	private AttributedVertex vertex(String name) {
		return graph.addVertex(name, "sub rax, rax");
	}

	private AttributedEdge edge(AttributedVertex v1, AttributedVertex v2) {
		return graph.addEdge(v1, v2);
	}

}

