# Ghidra Integration - Implementation Complete

> **Purpose**: Document our Ghidra integration approach
> **Status**: ✅ Complete  
> **Last Updated**: January 17, 2026

---

## Summary

We replaced the originally planned Ghidra.js (V8-based) approach with a **custom GraalJS extension** for better stability with Ghidra 12.0.1.

---

## Why GraalJS Instead of Ghidra.js

### Ghidra.js Limitations

**Ghidra.js** (https://github.com/vaguue/Ghidra.js) had issues:

1. **Last updated 2+ years ago** - Compatibility concerns with Ghidra 12.0.1
2. **V8 via Javet** - Complex native dependency chain
3. **Installation issues** - Extension ZIP structure problems
4. **Node.js globals** - Sometimes interfered with Ghidra's environment

### GraalJS Advantages

**GraalJS 24.1.1** (from GraalVM) provides:

1. **Pure Java implementation** - No native dependencies
2. **Actively maintained** - Regular releases from Oracle
3. **ECMAScript 2023** - Modern JavaScript support
4. **Simple integration** - Just add JARs to classpath

---

## Our Implementation: sentinel-js Extension

### Extension Structure

```
docker/ghidra/extension/
├── Module.manifest                    # Extension metadata
├── build.gradle                       # Build configuration
├── extension.properties               # Extension info
├── lib/                               # GraalJS JARs (17 total)
│   ├── graal-js-24.1.1.jar
│   ├── graal-sdk-24.1.1.jar
│   ├── truffle-api-24.1.1.jar
│   ├── icu4j-*.jar
│   └── ... (other GraalVM components)
└── src/main/java/sentinel/ghidra/js/
    ├── SentinelJSPlugin.java          # Extension plugin registration
    ├── SentinelJSScriptProvider.java  # .js script type provider
    └── SentinelJSScript.java          # GraalJS script runner
```

### Key Classes

**SentinelJSPlugin.java**

```java
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "sentinel.ghidra.js",
    category = PluginCategoryNames.MISC,
    shortDescription = "JavaScript support for Ghidra",
    description = "Enables .js script execution via GraalJS"
)
public class SentinelJSPlugin extends Plugin {
    public SentinelJSPlugin(PluginTool tool) {
        super(tool);
    }
}
```

**SentinelJSScriptProvider.java**

```java
public class SentinelJSScriptProvider extends GhidraScriptProvider {
    @Override
    public String getDescription() {
        return "JavaScript (GraalJS)";
    }

    @Override
    public String getExtension() {
        return ".js";
    }

    @Override
    public GhidraScript getScriptInstance(ResourceFile sourceFile, PrintWriter writer)
            throws GhidraScriptLoadException {
        return new SentinelJSScript();
    }
}
```

**SentinelJSScript.java**

```java
public class SentinelJSScript extends GhidraScript {
    @Override
    public void run() throws Exception {
        try (Context context = Context.newBuilder("js")
                .allowAllAccess(true)
                .build()) {

            // Bind Ghidra globals
            Value bindings = context.getBindings("js");
            bindings.putMember("currentProgram", currentProgram);
            bindings.putMember("currentAddress", currentAddress);
            bindings.putMember("monitor", monitor);
            bindings.putMember("state", state);
            bindings.putMember("print", (Consumer<Object>) this::println);

            // Execute script
            String source = new String(Files.readAllBytes(sourceFile.toPath()));
            context.eval("js", source);
        }
    }
}
```

### Critical Implementation Detail: JAR Naming

Ghidra's `ClassSearcher` uses `ClassJar.isModuleDependencyJar()` which checks:

```java
return jarName.startsWith(moduleName)
```

**Solution**: Set `archiveBaseName = 'sentinel-js'` in build.gradle so the JAR becomes `sentinel-js-1.0.0.jar`, which matches the module name `sentinel-js`.

---

## Ghidra Scripts

### Script Location

Scripts are placed in:

```
/opt/ghidra/Ghidra/Features/sentinel-js/ghidra_scripts/
```

This path is automatically added to Ghidra's script search paths.

### Available Scripts

**analyze.js** - Full binary analysis

```javascript
// analyze.js - Get binary metadata, imports, exports, sections
var result = {
  name: currentProgram.getName(),
  format: currentProgram.getExecutableFormat(),
  // ... imports, exports, sections
};
print(JSON.stringify(result));
```

**extract-functions.js** - Function extraction

```javascript
// extract-functions.js - Get all functions with details
var fm = currentProgram.getFunctionManager();
var iter = fm.getFunctions(true);
var functions = [];
while (iter.hasNext()) {
  var func = iter.next();
  functions.push({
    name: func.getName(),
    address: func.getEntryPoint().toString(),
    // ... size, parameters
  });
}
print(JSON.stringify({ functions: functions }));
```

**extract-strings.js** - String extraction

```javascript
// extract-strings.js - Get defined strings
var listing = currentProgram.getListing();
var dataIter = listing.getDefinedData(true);
var strings = [];
while (dataIter.hasNext()) {
  var data = dataIter.next();
  if (data.hasStringValue()) {
    strings.push({
      value: data.getValue().toString(),
      address: data.getAddress().toString(),
    });
  }
}
print(JSON.stringify({ strings: strings }));
```

---

## MCP Server Integration

### ghidra-bridge.ts

The MCP server communicates with Ghidra via Docker:

```typescript
async function runGhidraAnalysis(binaryPath: string, scriptName: string) {
  // Spawn Ghidra container
  const cmd = [
    "docker",
    "run",
    "--rm",
    "-v",
    `${binaryPath}:/binary:ro`,
    "sentinel-ghidra:latest",
    "/opt/ghidra/support/analyzeHeadless",
    "/tmp/sentinel",
    "temp_project",
    "-import",
    "/binary",
    "-postScript",
    scriptName,
    "-deleteProject",
  ];

  // Execute and parse JSON output
  const output = await exec(cmd);
  return parseGhidraOutput(output);
}
```

### Output Parsing

Ghidra wraps script output with log messages. We strip them:

```typescript
function parseGhidraOutput(output: string): object {
  const lines = output.split("\n");
  for (const line of lines) {
    // Strip log prefixes like "INFO SentinelJSScript.class>"
    const clean = line
      .replace(/^.*SentinelJSScript\.class>\s*/, "")
      .replace(/\s*\(GhidraScript\)$/, "")
      .trim();

    if (clean.startsWith("{")) {
      return JSON.parse(clean);
    }
  }
  throw new Error("No JSON found in Ghidra output");
}
```

---

## Ghidra API Reference

### Key Objects Available in Scripts

| Object           | Type          | Description               |
| ---------------- | ------------- | ------------------------- |
| `currentProgram` | `Program`     | The binary being analyzed |
| `currentAddress` | `Address`     | Current cursor position   |
| `monitor`        | `TaskMonitor` | Progress/cancellation     |
| `state`          | `GhidraState` | Script state              |
| `print(msg)`     | Function      | Output (use for JSON)     |

### Commonly Used APIs

```javascript
// Program info
currentProgram.getName();
currentProgram.getExecutableFormat();
currentProgram.getLanguage().getProcessor().toString();

// Memory
var memory = currentProgram.getMemory();
var blocks = memory.getBlocks();

// Functions
var fm = currentProgram.getFunctionManager();
var functions = fm.getFunctions(true); // Iterator

// Symbols (imports/exports)
var st = currentProgram.getSymbolTable();
var externalSymbols = st.getExternalSymbols();
var definedSymbols = st.getDefinedSymbols();

// Strings
var listing = currentProgram.getListing();
var data = listing.getDefinedData(true);
```

---

## Docker Configuration

### Dockerfile

```dockerfile
FROM eclipse-temurin:17-jdk AS builder

# Download and install Ghidra 12.0.1
RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.0.1_build/ghidra_12.0.1_PUBLIC_20260114.zip \
    && unzip ghidra_*.zip -d /opt \
    && mv /opt/ghidra_* /opt/ghidra

# Copy and build extension
COPY extension/ /tmp/extension/
WORKDIR /tmp/extension
RUN gradle buildExtension

# Install extension
RUN unzip dist/sentinel-js.zip -d /opt/ghidra/Ghidra/Extensions/

# Copy scripts
COPY ghidra_scripts/ /opt/ghidra/Ghidra/Features/sentinel-js/ghidra_scripts/

FROM eclipse-temurin:17-jdk
COPY --from=builder /opt/ghidra /opt/ghidra
WORKDIR /opt/ghidra
```

### Headless Execution

```bash
/opt/ghidra/support/analyzeHeadless \
    /tmp/sentinel temp_project \
    -import /path/to/binary \
    -postScript analyze.js \
    -deleteProject \
    -noanalysis  # Optional: skip auto-analysis for speed
```

---

## Lessons Learned

1. **JAR naming matters** - Ghidra's ClassSearcher requires specific naming
2. **Log prefix stripping** - Ghidra wraps output with logging
3. **Java iterators** - Use `while (iter.hasNext())` pattern in JS
4. **Error handling** - Ghidra may not find all symbols; handle gracefully
5. **Import format** - Ghidra returns objects, not strings for imports

---

## Future Enhancements

- **Decompilation**: Add `DecompInterface` for pseudo-C output
- **Control Flow**: Use `BasicBlockModel` for CFG analysis
- **Data Types**: Extract structs and enums
- **Cross-references**: Map code/data references

---

## References

- **Ghidra API Docs**: https://ghidra.re/ghidra_docs/api/
- **GraalJS**: https://www.graalvm.org/latest/reference-manual/js/
- **Ghidra Scripting**: https://ghidra.re/courses/GhidraClass/Intermediate/Scripting.html
