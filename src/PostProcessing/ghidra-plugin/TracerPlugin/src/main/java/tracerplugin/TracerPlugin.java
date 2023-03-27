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
package tracerplugin;

import java.awt.BorderLayout;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

import javax.swing.*;

import com.google.common.util.concurrent.Monitor;

import aQute.bnd.osgi.Instruction;
import docking.ActionContext;
import docking.ComponentProvider;
import docking.DockingWindowManager;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import graph.TaintGraphProvider;
import graph.TaintPlugin;
import resources.Icons;
import ui.UIProvider;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Plugin short description goes here.",
	description = "Plugin long description goes here."
)
//@formatter:on
public class TracerPlugin extends ProgramPlugin {

	UIProvider provider;
	private ProgramManager programManager;
	static final String SHOW_PROVIDER_ACTION_NAME = "Display Taint Graph";

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public TracerPlugin(PluginTool tool) {
		super(tool);

		String pluginName = getName();
		provider = new UIProvider(this, pluginName);
		DockingAction showProviderAction = new DockingAction(SHOW_PROVIDER_ACTION_NAME, getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				showProvider();
			}
		};
		tool.addAction(showProviderAction);
		
	}

	@Override
	public void init() {
		super.init();
		System.out.println("TracerPlugin initialized");
	}
	
	private void showProvider() {
		provider.setVisible(true);
	}

}
