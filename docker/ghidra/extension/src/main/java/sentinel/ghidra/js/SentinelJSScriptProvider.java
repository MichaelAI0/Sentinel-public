/* ###
 * SENTINEL JavaScript Script Provider for Ghidra
 *
 * Enables running JavaScript (.js) scripts in Ghidra using GraalJS engine.
 * TypeScript files should be compiled to JavaScript before use.
 *
 * This is a clean-room implementation for Ghidra 12.x compatibility.
 * ###
 */
package sentinel.ghidra.js;

import java.io.*;
import java.util.*;

import ghidra.app.script.*;
import ghidra.util.Msg;
import generic.jar.ResourceFile;

/**
 * Script provider that adds JavaScript support to Ghidra via GraalJS.
 * 
 * This registers .js files as valid Ghidra scripts and provides
 * the runtime environment for executing them.
 */
public class SentinelJSScriptProvider extends GhidraScriptProvider {

    private static final String DESCRIPTION = "JavaScript (SENTINEL/GraalJS)";
    private static final String EXTENSION = ".js";

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    @Override
    public String getExtension() {
        return EXTENSION;
    }

    @Override
    public GhidraScript getScriptInstance(ResourceFile sourceFile, PrintWriter writer)
            throws GhidraScriptLoadException {
        try {
            return new SentinelJSScript(sourceFile, writer);
        } catch (Exception e) {
            throw new GhidraScriptLoadException("Failed to load JavaScript script: " + e.getMessage(), e);
        }
    }

    @Override
    public void createNewScript(ResourceFile newScript, String category) throws IOException {
        String filename = newScript.getName();
        PrintWriter writer = new PrintWriter(new FileWriter(newScript.getFile(false)));
        
        writer.println("// " + getDescription() + " script");
        writer.println("// @author SENTINEL");
        writer.println("// @category " + category);
        writer.println("");
        writer.println("// SENTINEL JavaScript Script");
        writer.println("// @category " + category);
        writer.println("");
        writer.println("// Ghidra globals available:");
        writer.println("//   currentProgram - The program being analyzed");
        writer.println("//   monitor        - Task monitor for progress/cancellation");
        writer.println("//   println(msg)   - Print to console");
        writer.println("");
        writer.println("println('Hello from JavaScript!');");
        writer.println("println('Program: ' + currentProgram.getName());");
        writer.println("");
        
        writer.close();
    }

    @Override
    public String getCommentCharacter() {
        return "//";
    }
}
