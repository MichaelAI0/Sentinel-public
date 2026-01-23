/**
 * SENTINEL Analysis Workflow
 * LangGraph-based multi-agent orchestration for malware analysis
 *
 * Uses LangGraph's StateGraph with Annotation for proper state management,
 * conditional routing, and workflow orchestration.
 */

import { Annotation, END, START, StateGraph } from '@langchain/langgraph';
import { runAnalyzerAgent } from '../agents/analyzer-agent.js';
import { runReportAgent } from '../agents/report-agent.js';
import { runTriageAgent } from '../agents/triage-agent.js';
import type { AnalysisResults, AnalysisState, ReportPaths, TriageResults } from '../types.js';
import { logger } from '../utils/logger.js';

/**
 * State Annotation for LangGraph
 * Defines how each channel is reduced when updated
 */
const AnalysisStateAnnotation = Annotation.Root({
  // Input
  binaryPath: Annotation<string>({
    reducer: (_, b) => b,
    default: () => '',
  }),
  filename: Annotation<string>({
    reducer: (_, b) => b,
    default: () => '',
  }),

  // Triage Phase
  triageResults: Annotation<TriageResults | null>({
    reducer: (a, b) => b ?? a,
    default: () => null,
  }),
  triageComplete: Annotation<boolean>({
    reducer: (_, b) => b,
    default: () => false,
  }),

  // Analysis Phase
  analysisResults: Annotation<AnalysisResults | null>({
    reducer: (a, b) => b ?? a,
    default: () => null,
  }),
  analysisComplete: Annotation<boolean>({
    reducer: (_, b) => b,
    default: () => false,
  }),

  // Report Phase
  reportPaths: Annotation<ReportPaths | null>({
    reducer: (a, b) => b ?? a,
    default: () => null,
  }),
  reportsComplete: Annotation<boolean>({
    reducer: (_, b) => b,
    default: () => false,
  }),

  // Metadata
  startTime: Annotation<Date>({
    reducer: (a, b) => b ?? a,
    default: () => new Date(),
  }),
  endTime: Annotation<Date | undefined>({
    reducer: (_, b) => b,
    default: () => undefined,
  }),
  errors: Annotation<string[]>({
    reducer: (a, b) => [...a, ...(b ?? [])],
    default: () => [],
  }),
  status: Annotation<AnalysisState['status']>({
    reducer: (_, b) => b,
    default: () => 'pending',
  }),
});

type StateType = typeof AnalysisStateAnnotation.State;

/**
 * Triage node - fast initial assessment
 */
async function triageNode(state: StateType): Promise<Partial<StateType>> {
  logger.info`[WORKFLOW] Entering triage node`;
  return runTriageAgent(state as AnalysisState);
}

/**
 * Analyzer node - deep Ghidra analysis
 */
async function analyzerNode(state: StateType): Promise<Partial<StateType>> {
  logger.info`[WORKFLOW] Entering analyzer node`;
  return runAnalyzerAgent(state as AnalysisState);
}

/**
 * Report node - generate outputs
 */
async function reportNode(state: StateType): Promise<Partial<StateType>> {
  logger.info`[WORKFLOW] Entering report node`;
  return runReportAgent(state as AnalysisState);
}

/**
 * Routing function after triage
 * Decides whether to proceed with deep analysis or skip to reporting
 */
function routeAfterTriage(state: StateType): 'analyze' | 'report' {
  const recommendation = state.triageResults?.recommendation;

  if (recommendation === 'IGNORE') {
    logger.info`[WORKFLOW] Triage: IGNORE - skipping deep analysis`;
    return 'report';
  }

  logger.info`[WORKFLOW] Triage: ${recommendation} - proceeding to deep analysis`;
  return 'analyze';
}

/**
 * Build the analysis workflow graph
 */
export function buildAnalysisWorkflow() {
  // Create the state graph with annotation
  const workflow = new StateGraph(AnalysisStateAnnotation)
    // Add nodes
    .addNode('triage', triageNode)
    .addNode('analyze', analyzerNode)
    .addNode('report', reportNode)
    // Add edges
    .addEdge(START, 'triage')
    .addConditionalEdges('triage', routeAfterTriage, {
      analyze: 'analyze',
      report: 'report',
    })
    .addEdge('analyze', 'report')
    .addEdge('report', END);

  // Compile and return the graph
  return workflow.compile();
}

/**
 * Run the analysis workflow on a binary
 */
export async function analyzeWithWorkflow(
  binaryPath: string,
  filename?: string,
): Promise<AnalysisState> {
  logger.info`Starting analysis workflow for: ${binaryPath}`;

  const workflow = buildAnalysisWorkflow();

  const initialState: Partial<StateType> = {
    binaryPath,
    filename: filename ?? binaryPath.split('/').pop() ?? 'unknown',
    startTime: new Date(),
    status: 'triaging',
  };

  try {
    const finalState = await workflow.invoke(initialState);

    logger.info`Analysis workflow complete: status=${finalState.status}`;

    return finalState as AnalysisState;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logger.error`Workflow failed: ${errorMessage}`;

    return {
      binaryPath,
      filename: filename ?? binaryPath.split('/').pop() ?? 'unknown',
      triageResults: null,
      triageComplete: false,
      analysisResults: null,
      analysisComplete: false,
      reportPaths: null,
      reportsComplete: false,
      startTime: new Date(),
      endTime: new Date(),
      status: 'failed',
      errors: [errorMessage],
    };
  }
}
