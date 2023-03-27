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

import javax.swing.Icon;

import ghidra.graph.viewer.layout.AbstractLayoutProvider;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import graph.TaintEdge;
import graph.TaintGraph;
import graph.TaintVertex;

/**
 * A layout provider for the {@link TaintGraphPlugin}
 */
public class TaintGraphPluginDependencyLayoutProvider
		extends AbstractLayoutProvider<TaintVertex, TaintEdge, TaintGraph> {

	private static final String NAME = "Plugin Dependency Layout";
	private static final Icon DEFAULT_ICON = null;

	@Override
	public VisualGraphLayout<TaintVertex, TaintEdge> getLayout(TaintGraph g, TaskMonitor monitor)
			throws CancelledException {

		TaintGraphPluginDependencyLayout layout = new TaintGraphPluginDependencyLayout(g, NAME);
		initVertexLocations(g, layout);
		return layout;
	}

	@Override
	public String getLayoutName() {
		return NAME;
	}

	// Note: each provider really should load its own icon so that the toolbar item can 
	//       signal to the user which layout is active
	@Override
	public Icon getActionIcon() {
		return DEFAULT_ICON;
	}
}