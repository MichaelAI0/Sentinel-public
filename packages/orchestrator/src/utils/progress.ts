/**
 * CLI Progress Indicators
 *
 * Simple terminal progress display for long-running operations.
 * Respects quiet/json modes by checking options.
 */

export type ProgressOptions = {
  quiet?: boolean;
  json?: boolean;
  verbose?: boolean;
};

const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const CHECK = '✓';
const CROSS = '✗';
const ARROW = '→';

/**
 * Progress tracker for multi-step operations
 */
export class Progress {
  private current = 0;
  private spinnerFrame = 0;
  private spinnerInterval: ReturnType<typeof setInterval> | null = null;
  private startTime: number;
  private stepStartTime: number;

  constructor(
    private steps: string[],
    private options: ProgressOptions = {},
  ) {
    this.startTime = Date.now();
    this.stepStartTime = this.startTime;
  }

  private shouldShow(): boolean {
    return !this.options.quiet && !this.options.json;
  }

  private clearLine(): void {
    if (process.stdout.isTTY) {
      process.stdout.write('\r\x1b[K');
    }
  }

  private formatDuration(ms: number): string {
    if (ms < 1000) return `${ms}ms`;
    return `${(ms / 1000).toFixed(1)}s`;
  }

  /**
   * Start showing progress for the current step
   */
  start(): void {
    if (!this.shouldShow()) return;

    const step = this.steps[this.current];
    if (!step) return;

    if (process.stdout.isTTY) {
      // Animated spinner for TTY
      this.spinnerInterval = setInterval(() => {
        this.spinnerFrame = (this.spinnerFrame + 1) % SPINNER_FRAMES.length;
        const spinner = SPINNER_FRAMES[this.spinnerFrame];
        this.clearLine();
        process.stdout.write(`${spinner} ${step}...`);
      }, 80);
    } else {
      // Simple output for non-TTY
      console.log(`${ARROW} ${step}...`);
    }
  }

  /**
   * Mark current step as complete and move to next
   */
  complete(detail?: string): void {
    if (!this.shouldShow()) {
      this.current += 1;
      this.stepStartTime = Date.now();
      return;
    }

    if (this.spinnerInterval) {
      clearInterval(this.spinnerInterval);
      this.spinnerInterval = null;
    }

    const step = this.steps[this.current];
    const elapsed = this.formatDuration(Date.now() - this.stepStartTime);
    this.clearLine();

    if (step) {
      const detailStr = detail ? ` (${detail})` : '';
      console.log(`${CHECK} ${step}${detailStr} [${elapsed}]`);
    }

    this.current += 1;
    this.stepStartTime = Date.now();

    // Auto-start next step if there is one
    if (this.current < this.steps.length) {
      this.start();
    }
  }

  /**
   * Mark current step as failed
   */
  fail(error?: string): void {
    if (!this.shouldShow()) return;

    if (this.spinnerInterval) {
      clearInterval(this.spinnerInterval);
      this.spinnerInterval = null;
    }

    const step = this.steps[this.current];
    this.clearLine();

    if (step) {
      const errStr = error ? `: ${error}` : '';
      console.log(`${CROSS} ${step}${errStr}`);
    }
  }

  /**
   * Print verbose detail (only in verbose mode)
   */
  verbose(message: string): void {
    if (!this.options.verbose || this.options.quiet || this.options.json) return;

    if (this.spinnerInterval) {
      // Pause spinner, print, resume
      clearInterval(this.spinnerInterval);
      this.clearLine();
      console.log(`  ${message}`);
      this.start();
    } else {
      console.log(`  ${message}`);
    }
  }

  /**
   * Finish progress tracking
   */
  finish(success = true): void {
    if (this.spinnerInterval) {
      clearInterval(this.spinnerInterval);
      this.spinnerInterval = null;
    }

    if (!this.shouldShow()) return;

    const total = this.formatDuration(Date.now() - this.startTime);
    const status = success ? 'Complete' : 'Failed';
    console.log(`\n${status} in ${total}`);
  }
}

/**
 * Create a progress tracker for the analyze workflow
 */
export function createAnalyzeProgress(options: ProgressOptions): Progress {
  return new Progress(
    [
      'Calculating file hashes',
      'Detecting file type',
      'Extracting headers',
      'Running triage analysis',
      'Performing deep analysis',
      'Extracting functions',
      'Extracting strings',
      'Mapping MITRE techniques',
      'Generating reports',
    ],
    options,
  );
}

/**
 * Create a progress tracker for the triage workflow
 */
export function createTriageProgress(options: ProgressOptions): Progress {
  return new Progress(
    ['Calculating file hashes', 'Detecting file type', 'Extracting headers', 'Analyzing risk'],
    options,
  );
}
