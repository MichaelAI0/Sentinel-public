/* ###
 * SENTINEL JavaScript Extension Plugin
 *
 * Main plugin class that registers the JavaScript script provider.
 * ###
 */
package sentinel.ghidra.js;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

/**
 * Plugin that enables JavaScript scripting in Ghidra using GraalJS.
 * 
 * This plugin automatically registers the SentinelJSScriptProvider,
 * allowing .js files to be recognized and executed as Ghidra scripts.
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "SENTINEL",
    category = PluginCategoryNames.COMMON,
    shortDescription = "JavaScript Scripting (GraalJS)",
    description = "Enables JavaScript scripting support using GraalJS engine. " +
                  "Allows running .js scripts compiled from TypeScript."
)
//@formatter:on
public class SentinelJSPlugin extends ProgramPlugin {

    public SentinelJSPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "SENTINEL JavaScript Extension loaded - GraalJS engine ready");
    }

    @Override
    protected void init() {
        super.init();
        // Script provider is auto-registered via META-INF/services
    }

    @Override
    protected void dispose() {
        super.dispose();
        Msg.info(this, "SENTINEL JavaScript Extension unloaded");
    }
}
