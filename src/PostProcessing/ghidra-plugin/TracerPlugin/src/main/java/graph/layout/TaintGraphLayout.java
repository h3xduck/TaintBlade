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
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.layout.JungWrappingVisualGraphLayoutAdapter;
import graph.TaintEdge;
import graph.TaintVertex;

/**
 * A {@link TaintGraphPlugin} layout that can be used to apply existing Jung layouts.
 */
public class TaintGraphLayout
		extends JungWrappingVisualGraphLayoutAdapter<TaintVertex, TaintEdge> {

	public TaintGraphLayout(Layout<TaintVertex, TaintEdge> jungLayout) {
		super(jungLayout);
	}

	@Override
	protected Layout<TaintVertex, TaintEdge> cloneJungLayout(
			VisualGraph<TaintVertex, TaintEdge> newGraph) {

		Layout<TaintVertex, TaintEdge> newJungLayout = cloneJungLayout(newGraph);
		return new TaintGraphLayout(newJungLayout);
	}

	Layout<?, ?> getJungLayout() {
		return delegate;
	}
}