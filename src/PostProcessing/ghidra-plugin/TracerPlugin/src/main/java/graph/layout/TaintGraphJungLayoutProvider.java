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

import edu.uci.ics.jung.algorithms.layout.Layout;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import graph.TaintEdge;
import graph.TaintGraph;
import graph.TaintVertex;

public abstract class TaintGraphJungLayoutProvider extends TaintGraphLayoutProvider {

	protected abstract Layout<TaintVertex, TaintEdge> createLayout(TaintGraph g);

	@Override
	public VisualGraphLayout<TaintVertex, TaintEdge> getLayout(TaintGraph g, TaskMonitor monitor)
			throws CancelledException {

		Layout<TaintVertex, TaintEdge> jungLayout = createLayout(g);

		initVertexLocations(g, jungLayout);

		return new TaintGraphLayout(jungLayout);
	}

}
