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
package graph;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;

/**
 * Taint plugin to demonstrate a plugin with a dockable GUI graph component
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Taint Graph Display Plugin",
	description = "Taint plugin to demonstrate a plugin with a dockable GUI graph component."
)
//@formatter:on
public class TaintPlugin extends Plugin {

	/*package*/ static final String SHOW_PROVIDER_ACTION_NAME = "Display Taint Graph";

	// Note: this help location is here to satisfy our requirement that all actions have help,
	//       but is not actual help content.  For your plugin, you must create your own content.
	/*package*/ public static final HelpLocation DEFAULT_HELP =
		new HelpLocation("TaintHelpTopic", "TaintHelpTopic_Anchor_Name");

	private TaintGraphProvider provider;

	public TaintPlugin(PluginTool tool) {
		super(tool);

		provider = new TaintGraphProvider(tool, this, null);
		createActions();
	}

	private void createActions() {
		DockingAction showProviderAction = new DockingAction(SHOW_PROVIDER_ACTION_NAME, getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				showProvider();
			}
		};
		Icon icon = new ImageIcon("icon.Taint.action.show.graph");
		//showProviderAction.setToolBarData(new ToolBarData(icon, "View"));
		showProviderAction.setHelpLocation(DEFAULT_HELP);
		tool.addAction(showProviderAction);
	}

	private void showProvider() {
		provider.setVisible(true);
	}

	@Override
	protected void dispose() {
		provider.dispose();
	}
}