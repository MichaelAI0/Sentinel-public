/**
 * Ghidra.js API Type Definitions
 *
 * Minimal type definitions for the Ghidra Java API as exposed through Ghidra.js.
 * These types cover ONLY what SENTINEL actually uses.
 *
 * Ghidra.js embeds V8 into Ghidra via Javet, exposing Java objects to JavaScript.
 * The actual API comes from Ghidra's Java packages:
 *   - ghidra.program.model.listing
 *   - ghidra.program.model.symbol
 *   - ghidra.program.model.mem
 *   - ghidra.program.model.address
 *
 * Style: Uses type aliases exclusively (no interfaces) per project conventions.
 *
 * @see https://github.com/vaguue/Ghidra.js
 * @see https://ghidra.re/ghidra_docs/api/
 */

// ============================================================================
// GLOBALS - Provided by Ghidra.js runtime
// ============================================================================

/** The program currently being analyzed */
declare const currentProgram: GhidraProgram;

/** Task monitor for progress reporting and cancellation */
declare const monitor: GhidraMonitor;

/** Current cursor address (may be null in headless mode) */
declare const currentAddress: GhidraAddress | null;

/** Print to Ghidra console (captured by analyzeHeadless) */
declare function println(message: string): void;

/** Get script arguments passed via -scriptArgs */
declare function getScriptArgs(): string[];

/** Helper for importing Java classes */
declare const JavaHelper: {
  getClass: <T>(className: string) => T;
};

// ============================================================================
// CORE TYPES
// ============================================================================

/**
 * The main Program type - entry point for all analysis
 * @see https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html
 */
type GhidraProgram = {
  // Basic info
  getName: () => string;
  getExecutablePath: () => string;
  getExecutableFormat: () => string;
  getExecutableMD5: () => string | null;
  getExecutableSHA256: () => string | null;

  // Language/Architecture
  getLanguage: () => GhidraLanguage;

  // Managers
  getMemory: () => GhidraMemory;
  getFunctionManager: () => GhidraFunctionManager;
  getSymbolTable: () => GhidraSymbolTable;
  getListing: () => GhidraListing;
  getAddressFactory: () => GhidraAddressFactory;
};

/**
 * Language/Processor information
 */
type GhidraLanguage = {
  getProcessor: () => { toString: () => string };
  getLanguageID: () => { getIdAsString: () => string };
};

/**
 * Task monitor for progress and cancellation
 */
type GhidraMonitor = {
  isCancelled: () => boolean;
  setMessage: (message: string) => void;
  setProgress: (value: number) => void;
  setMaximum: (max: number) => void;
};

// ============================================================================
// ADDRESS TYPES
// ============================================================================

type GhidraAddress = {
  toString: () => string;
  getOffset: () => number;
  add: (displacement: number) => GhidraAddress;
  subtract: (displacement: number) => GhidraAddress;
  equals: (other: GhidraAddress) => boolean;
};

type GhidraAddressFactory = {
  getAddress: (addrString: string) => GhidraAddress | null;
  getDefaultAddressSpace: () => GhidraAddressSpace;
};

type GhidraAddressSpace = {
  getName: () => string;
  getMinAddress: () => GhidraAddress;
  getMaxAddress: () => GhidraAddress;
};

type GhidraAddressSetView = {
  getNumAddresses: () => number;
  getMinAddress: () => GhidraAddress;
  getMaxAddress: () => GhidraAddress;
  contains: (addr: GhidraAddress) => boolean;
};

// ============================================================================
// MEMORY TYPES
// ============================================================================

type GhidraMemory = {
  getBlocks: () => GhidraMemoryBlock[];
  getBlock: (addr: GhidraAddress) => GhidraMemoryBlock | null;
  getSize: () => number;
  getByte: (addr: GhidraAddress) => number;
  getBytes: (addr: GhidraAddress, dest: number[]) => number;
};

type GhidraMemoryBlock = {
  getName: () => string;
  getStart: () => GhidraAddress;
  getEnd: () => GhidraAddress;
  getSize: () => number;
  isRead: () => boolean;
  isWrite: () => boolean;
  isExecute: () => boolean;
  isInitialized: () => boolean;
  getBytes: (addr: GhidraAddress, dest: number[]) => number;
};

// ============================================================================
// FUNCTION TYPES
// ============================================================================

type GhidraFunctionManager = {
  getFunctionAt: (addr: GhidraAddress) => GhidraFunction | null;
  getFunctionContaining: (addr: GhidraAddress) => GhidraFunction | null;
  getFunctions: (forward: boolean) => GhidraFunctionIterator;
  getFunctionCount: () => number;
};

type GhidraFunctionIterator = {
  hasNext: () => boolean;
  next: () => GhidraFunction;
};

type GhidraFunction = {
  getName: () => string;
  getEntryPoint: () => GhidraAddress;
  getBody: () => GhidraAddressSetView;
  getComment: () => string | null;
  getSignature: () => { getPrototypeString: () => string };
  getCallingFunctions: (monitor: GhidraMonitor) => Iterable<GhidraFunction>;
  getCalledFunctions: (monitor: GhidraMonitor) => Iterable<GhidraFunction>;
  isThunk: () => boolean;
  isExternal: () => boolean;
  hasVarArgs: () => boolean;
  getCallingConventionName: () => string | null;
  getPrototypeString: (includeCallingConvention: boolean, formal: boolean) => string;
  getParameters: () => GhidraParameter[];
  getLocalVariables: () => GhidraVariable[];
  getReturnType: () => GhidraDataType;
  getStackFrame: () => GhidraStackFrame;
};

type GhidraParameter = {
  getName: () => string;
  getDataType: () => GhidraDataType;
  getOrdinal: () => number;
};

type GhidraVariable = {
  getName: () => string;
  getDataType: () => GhidraDataType;
  getStackOffset: () => number;
};

type GhidraStackFrame = {
  getFrameSize: () => number;
  getLocalSize: () => number;
  getParameterSize: () => number;
};

// ============================================================================
// SYMBOL TYPES
// ============================================================================

type GhidraSymbolTable = {
  getSymbols: (addr: GhidraAddress) => GhidraSymbol[];
  getPrimarySymbol: (addr: GhidraAddress) => GhidraSymbol | null;
  getExternalSymbols: () => GhidraSymbolIterator;
  getDefinedSymbols: () => GhidraSymbolIterator;
  getGlobalSymbols: (name: string) => GhidraSymbol[];
  getNumSymbols: () => number;
};

type GhidraSymbolIterator = {
  hasNext: () => boolean;
  next: () => GhidraSymbol;
};

type GhidraSymbol = {
  getName: () => string;
  getAddress: () => GhidraAddress;
  getSymbolType: () => GhidraSymbolType;
  getParentNamespace: () => GhidraNamespace;
  isExternal: () => boolean;
  isPrimary: () => boolean;
  isGlobal: () => boolean;
};

type GhidraSymbolType = {
  toString: () => string;
  getID: () => number;
};

type GhidraNamespace = {
  getName: () => string;
  isGlobal: () => boolean;
};

// ============================================================================
// LISTING TYPES (for data/strings/instructions)
// ============================================================================

type GhidraListing = {
  getDefinedData: (forward: boolean) => GhidraDataIterator;
  getDataAt: (addr: GhidraAddress) => GhidraData | null;
  getInstructionAt: (addr: GhidraAddress) => GhidraInstruction | null;
  getInstructions: (
    addressSet: GhidraAddressSetView,
    forward: boolean,
  ) => GhidraInstructionIterator;
};

type GhidraInstructionIterator = {
  hasNext: () => boolean;
  next: () => GhidraInstruction;
};

type GhidraDataIterator = {
  hasNext: () => boolean;
  next: () => GhidraData;
};

type GhidraData = {
  getAddress: () => GhidraAddress;
  getValue: () => unknown;
  getDataType: () => GhidraDataType;
  getLength: () => number;
};

type GhidraDataType = {
  getName: () => string;
  getLength: () => number;
  getDescription: () => string;
};

type GhidraInstruction = {
  getAddress: () => GhidraAddress;
  getMnemonicString: () => string;
  getNumOperands: () => number;
  getDefaultOperandRepresentation: (opIndex: number) => string;
  getFlows: () => GhidraAddress[];
  getFallThrough: () => GhidraAddress | null;
  getFlowType: () => { isCall: () => boolean; isJump: () => boolean; isTerminal: () => boolean };
};

// Type aliases for script compatibility (short names used in analysis scripts)
type _Address = GhidraAddress;
type _AddressSetView = GhidraAddressSetView;
type _Data = GhidraData;
type _FlowType = ReturnType<GhidraInstruction['getFlowType']>;
type _FunctionManager = GhidraFunctionManager;
type _Listing = GhidraListing;
type _Memory = GhidraMemory;
type _MemoryBlock = GhidraMemoryBlock;
