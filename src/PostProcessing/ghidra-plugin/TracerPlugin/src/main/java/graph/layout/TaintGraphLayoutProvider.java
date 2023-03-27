/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package graph.layout;

import java.awt.geom.Point2D;
import java.util.Collection;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import edu.uci.ics.jung.algorithms.layout.Layout;
import ghidra.graph.viewer.layout.AbstractLayoutProvider;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import graph.TaintEdge;
import graph.TaintGraph;
import graph.TaintVertex;

/**
 * The layout provider for the {@link TaintGraphPlugin}.
 */
public abstract class TaintGraphLayoutProvider
		extends AbstractLayoutProvider<TaintVertex, TaintEdge, TaintGraph> {

	private static final Icon DEFAULT_ICON = new ImageIcon("icon.Taint.provider.graph");

	@Override
	public abstract VisualGraphLayout<TaintVertex, TaintEdge> getLayout(TaintGraph g,
			TaskMonitor monitor) throws CancelledException;

	protected void initVertexLocations(TaintGraph g, Layout<TaintVertex, TaintEdge> layout) {
		Collection<TaintVertex> vertices = g.getVertices();
		for (TaintVertex v : vertices) {
			Point2D p = layout.apply(v);
			v.setLocation(p);
		}
	}

	// Note: each provider really should load its own icon so that the toolbar item can 
	//       signal to the user which layout is active
	@Override
	public Icon getActionIcon() {
		return DEFAULT_ICON;
	}
}