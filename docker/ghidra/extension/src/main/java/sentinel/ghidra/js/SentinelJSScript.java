/* ###
 * SENTINEL JavaScript Script Implementation
 *
 * Executes JavaScript code using GraalJS engine with Ghidra API bindings.
 * ###
 */
package sentinel.ghidra.js;

import java.io.*;
import java.nio.file.*;

import org.graalvm.polyglot.*;
import org.graalvm.polyglot.io.IOAccess;

import ghidra.app.script.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import generic.jar.ResourceFile;

/**
 * GhidraScript implementation that executes JavaScript via GraalJS.
 * 
 * Exposes the following globals to JavaScript:
 *   - currentProgram: The Program being analyzed
 *   - currentAddress: Current cursor address (may be null in headless)
 *   - monitor: TaskMonitor for progress and cancellation
 *   - println(msg): Print to Ghidra console
 *   - getScriptArgs(): Get command-line script arguments
 *   - JavaHelper.getClass(name): Load a Java class for advanced usage
 */
public class SentinelJSScript extends GhidraScript {

    private final ResourceFile sourceFile;
    private final PrintWriter outputWriter;
    
    // GraalJS context - created fresh for each script execution
    private Context jsContext;

    public SentinelJSScript(ResourceFile sourceFile, PrintWriter writer) {
        this.sourceFile = sourceFile;
        this.outputWriter = writer;
    }

    @Override
    protected void run() throws Exception {
        String scriptContent = readScriptContent();
        
        try {
            // Create GraalJS context with Java interop enabled
            jsContext = Context.newBuilder("js")
                .allowAllAccess(true)
                .allowHostAccess(HostAccess.ALL)
                .allowHostClassLookup(className -> true)
                .allowIO(IOAccess.ALL)
                .option("js.ecmascript-version", "2022")
                .option("js.strict", "true")
                .out(new PrintStream(new WriterOutputStream(outputWriter)))
                .err(new PrintStream(new WriterOutputStream(outputWriter)))
                .build();

            // Bind Ghidra globals to JavaScript context
            Value bindings = jsContext.getBindings("js");
            
            // Core Ghidra objects
            bindings.putMember("currentProgram", currentProgram);
            bindings.putMember("currentAddress", currentAddress);
            bindings.putMember("monitor", monitor);
            bindings.putMember("state", state);
            
            // Utility functions
            bindings.putMember("println", (PrintFunction) this::println);
            bindings.putMember("print", (PrintFunction) this::printMsg);
            bindings.putMember("getScriptArgs", (GetArgsFunction) this::getScriptArgs);
            bindings.putMember("askString", (AskStringFunction) this::askStringWrapper);
            
            // Java interop helper
            bindings.putMember("JavaHelper", new JavaHelper());
            
            // Flat API methods commonly used
            bindings.putMember("toAddr", (ToAddrFunction) this::toAddr);
            bindings.putMember("getBytes", (GetBytesFunction) this::getBytesWrapper);
            bindings.putMember("getFunctionAt", (GetFunctionAtFunction) this::getFunctionAt);
            bindings.putMember("createFunction", (CreateFunctionFunction) this::createFunctionWrapper);
            
            // Execute the script
            jsContext.eval("js", scriptContent);
            
        } catch (PolyglotException e) {
            String errorMsg = formatPolyglotError(e);
            println("JavaScript Error: " + errorMsg);
            Msg.error(this, "JavaScript execution failed", e);
            throw new Exception("JavaScript execution failed: " + errorMsg, e);
        } finally {
            if (jsContext != null) {
                jsContext.close();
            }
        }
    }

    /**
     * Read the JavaScript source file content
     */
    private String readScriptContent() throws IOException {
        return new String(Files.readAllBytes(sourceFile.getFile(false).toPath()));
    }

    /**
     * Format a PolyglotException for display
     */
    private String formatPolyglotError(PolyglotException e) {
        StringBuilder sb = new StringBuilder();
        sb.append(e.getMessage());
        
        if (e.getSourceLocation() != null) {
            sb.append(" at line ");
            sb.append(e.getSourceLocation().getStartLine());
            sb.append(", column ");
            sb.append(e.getSourceLocation().getStartColumn());
        }
        
        return sb.toString();
    }

    // ========================================================================
    // Wrapper methods for JavaScript bindings
    // ========================================================================

    private void printMsg(String msg) {
        outputWriter.print(msg);
        outputWriter.flush();
    }

    private String askStringWrapper(String title, String message) {
        try {
            return askString(title, message);
        } catch (Exception e) {
            return null;
        }
    }

    private byte[] getBytesWrapper(Address addr, int length) {
        try {
            byte[] bytes = new byte[length];
            currentProgram.getMemory().getBytes(addr, bytes);
            return bytes;
        } catch (Exception e) {
            return new byte[0];
        }
    }

    private Function createFunctionWrapper(Address entryPoint, String name) {
        try {
            return createFunction(entryPoint, name);
        } catch (Exception e) {
            return null;
        }
    }

    // ========================================================================
    // Functional interfaces for JavaScript bindings
    // ========================================================================

    @FunctionalInterface
    public interface PrintFunction {
        void apply(String msg);
    }

    @FunctionalInterface
    public interface GetArgsFunction {
        String[] apply();
    }

    @FunctionalInterface
    public interface AskStringFunction {
        String apply(String title, String message);
    }

    @FunctionalInterface
    public interface ToAddrFunction {
        Address apply(long offset);
    }

    @FunctionalInterface
    public interface GetBytesFunction {
        byte[] apply(Address addr, int length);
    }

    @FunctionalInterface
    public interface GetFunctionAtFunction {
        Function apply(Address addr);
    }

    @FunctionalInterface
    public interface CreateFunctionFunction {
        Function apply(Address entryPoint, String name);
    }

    // ========================================================================
    // Java interop helper
    // ========================================================================

    /**
     * Helper class for loading Java classes from JavaScript
     */
    public static class JavaHelper {
        @SuppressWarnings("unchecked")
        public <T> Class<T> getClass(String className) throws ClassNotFoundException {
            return (Class<T>) Class.forName(className);
        }
    }

    // ========================================================================
    // Writer adapter for GraalJS output streams
    // ========================================================================

    private static class WriterOutputStream extends OutputStream {
        private final PrintWriter writer;
        private final StringBuilder buffer = new StringBuilder();

        public WriterOutputStream(PrintWriter writer) {
            this.writer = writer;
        }

        @Override
        public void write(int b) throws IOException {
            char c = (char) b;
            if (c == '\n') {
                writer.println(buffer.toString());
                buffer.setLength(0);
            } else {
                buffer.append(c);
            }
        }

        @Override
        public void flush() throws IOException {
            if (buffer.length() > 0) {
                writer.print(buffer.toString());
                buffer.setLength(0);
            }
            writer.flush();
        }
    }
}
