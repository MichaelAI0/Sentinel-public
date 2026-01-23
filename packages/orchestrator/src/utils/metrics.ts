/**
 * Prometheus Metrics
 * Simple Prometheus-compatible metrics collection
 *
 * @module utils/metrics
 */

/**
 * Metric types
 */
export type MetricType = 'counter' | 'gauge' | 'histogram';

/**
 * Histogram bucket configuration
 */
export type HistogramBuckets = number[];

/**
 * Label set for metrics
 */
type Labels = Record<string, string>;

/**
 * Counter metric
 */
class Counter {
  private value = 0;
  private labeledValues: Map<string, number> = new Map();

  constructor(
    public readonly name: string,
    public readonly help: string,
  ) {}

  inc(labels?: Labels, value = 1): void {
    if (labels) {
      const key = this.labelsToKey(labels);
      this.labeledValues.set(key, (this.labeledValues.get(key) ?? 0) + value);
    } else {
      this.value += value;
    }
  }

  get(labels?: Labels): number {
    if (labels) {
      return this.labeledValues.get(this.labelsToKey(labels)) ?? 0;
    }
    return this.value;
  }

  toPrometheus(): string {
    const lines: string[] = [`# HELP ${this.name} ${this.help}`, `# TYPE ${this.name} counter`];

    if (this.labeledValues.size > 0) {
      for (const [key, value] of this.labeledValues) {
        lines.push(`${this.name}${key} ${value}`);
      }
    } else {
      lines.push(`${this.name} ${this.value}`);
    }

    return lines.join('\n');
  }

  private labelsToKey(labels: Labels): string {
    const sorted = Object.entries(labels).sort(([a], [b]) => a.localeCompare(b));
    return `{${sorted.map(([k, v]) => `${k}="${v}"`).join(',')}}`;
  }
}

/**
 * Gauge metric
 */
class Gauge {
  private value = 0;
  private labeledValues: Map<string, number> = new Map();

  constructor(
    public readonly name: string,
    public readonly help: string,
  ) {}

  set(value: number, labels?: Labels): void {
    if (labels) {
      this.labeledValues.set(this.labelsToKey(labels), value);
    } else {
      this.value = value;
    }
  }

  inc(labels?: Labels, value = 1): void {
    if (labels) {
      const key = this.labelsToKey(labels);
      this.labeledValues.set(key, (this.labeledValues.get(key) ?? 0) + value);
    } else {
      this.value += value;
    }
  }

  dec(labels?: Labels, value = 1): void {
    this.inc(labels, -value);
  }

  get(labels?: Labels): number {
    if (labels) {
      return this.labeledValues.get(this.labelsToKey(labels)) ?? 0;
    }
    return this.value;
  }

  toPrometheus(): string {
    const lines: string[] = [`# HELP ${this.name} ${this.help}`, `# TYPE ${this.name} gauge`];

    if (this.labeledValues.size > 0) {
      for (const [key, value] of this.labeledValues) {
        lines.push(`${this.name}${key} ${value}`);
      }
    } else {
      lines.push(`${this.name} ${this.value}`);
    }

    return lines.join('\n');
  }

  private labelsToKey(labels: Labels): string {
    const sorted = Object.entries(labels).sort(([a], [b]) => a.localeCompare(b));
    return `{${sorted.map(([k, v]) => `${k}="${v}"`).join(',')}}`;
  }
}

/**
 * Histogram metric
 */
class Histogram {
  private bucketCounts: Map<string, Map<number, number>> = new Map();
  private sums: Map<string, number> = new Map();
  private counts: Map<string, number> = new Map();
  private buckets: number[];

  constructor(
    public readonly name: string,
    public readonly help: string,
    buckets: number[] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
  ) {
    this.buckets = [...buckets].sort((a, b) => a - b);
  }

  observe(value: number, labels?: Labels): void {
    const key = labels ? this.labelsToKey(labels) : '';

    // Initialize buckets if needed
    if (!this.bucketCounts.has(key)) {
      const bucketMap = new Map<number, number>();
      for (const bucket of this.buckets) {
        bucketMap.set(bucket, 0);
      }
      this.bucketCounts.set(key, bucketMap);
    }

    // Increment appropriate buckets
    const bucketMap = this.bucketCounts.get(key);
    if (!bucketMap) return;
    for (const bucket of this.buckets) {
      if (value <= bucket) {
        bucketMap.set(bucket, (bucketMap.get(bucket) ?? 0) + 1);
      }
    }

    // Update sum and count
    this.sums.set(key, (this.sums.get(key) ?? 0) + value);
    this.counts.set(key, (this.counts.get(key) ?? 0) + 1);
  }

  toPrometheus(): string {
    const lines: string[] = [`# HELP ${this.name} ${this.help}`, `# TYPE ${this.name} histogram`];

    for (const [key, bucketMap] of this.bucketCounts) {
      const labelSuffix = key ? `${key.slice(0, -1)},` : '{';

      for (const bucket of this.buckets) {
        const count = bucketMap.get(bucket) ?? 0;
        lines.push(`${this.name}_bucket${labelSuffix}le="${bucket}"} ${count}`);
      }
      lines.push(`${this.name}_bucket${labelSuffix}le="+Inf"} ${this.counts.get(key) ?? 0}`);
      lines.push(`${this.name}_sum${key || ''} ${this.sums.get(key) ?? 0}`);
      lines.push(`${this.name}_count${key || ''} ${this.counts.get(key) ?? 0}`);
    }

    return lines.join('\n');
  }

  private labelsToKey(labels: Labels): string {
    const sorted = Object.entries(labels).sort(([a], [b]) => a.localeCompare(b));
    return `{${sorted.map(([k, v]) => `${k}="${v}"`).join(',')}}`;
  }
}

/**
 * Metrics registry
 */
class MetricsRegistry {
  private counters: Map<string, Counter> = new Map();
  private gauges: Map<string, Gauge> = new Map();
  private histograms: Map<string, Histogram> = new Map();

  counter(name: string, help: string): Counter {
    let counter = this.counters.get(name);
    if (!counter) {
      counter = new Counter(name, help);
      this.counters.set(name, counter);
    }
    return counter;
  }

  gauge(name: string, help: string): Gauge {
    let gauge = this.gauges.get(name);
    if (!gauge) {
      gauge = new Gauge(name, help);
      this.gauges.set(name, gauge);
    }
    return gauge;
  }

  histogram(name: string, help: string, buckets?: number[]): Histogram {
    let histogram = this.histograms.get(name);
    if (!histogram) {
      histogram = new Histogram(name, help, buckets);
      this.histograms.set(name, histogram);
    }
    return histogram;
  }

  /**
   * Export all metrics in Prometheus format
   */
  toPrometheus(): string {
    const sections: string[] = [];

    for (const counter of this.counters.values()) {
      sections.push(counter.toPrometheus());
    }

    for (const gauge of this.gauges.values()) {
      sections.push(gauge.toPrometheus());
    }

    for (const histogram of this.histograms.values()) {
      sections.push(histogram.toPrometheus());
    }

    return `${sections.join('\n\n')}\n`;
  }
}

// Global registry
const registry = new MetricsRegistry();

// Pre-defined SENTINEL metrics
export const metrics = {
  // Request counters
  httpRequestsTotal: registry.counter(
    'sentinel_http_requests_total',
    'Total number of HTTP requests',
  ),

  // Analysis counters
  analysisTotal: registry.counter('sentinel_analysis_total', 'Total number of analyses performed'),

  triageTotal: registry.counter(
    'sentinel_triage_total',
    'Total number of triage operations performed',
  ),

  // Status gauges
  analysisInProgress: registry.gauge(
    'sentinel_analysis_in_progress',
    'Number of analyses currently in progress',
  ),

  llmAvailable: registry.gauge(
    'sentinel_llm_available',
    'Whether LLM provider is available (1=yes, 0=no)',
  ),

  // Duration histograms
  triageDuration: registry.histogram(
    'sentinel_triage_duration_seconds',
    'Triage duration in seconds',
    [0.5, 1, 2.5, 5, 10, 30, 60],
  ),

  analysisDuration: registry.histogram(
    'sentinel_analysis_duration_seconds',
    'Full analysis duration in seconds',
    [5, 10, 30, 60, 120, 300, 600],
  ),

  httpRequestDuration: registry.histogram(
    'sentinel_http_request_duration_seconds',
    'HTTP request duration in seconds',
    [0.01, 0.05, 0.1, 0.5, 1, 5, 10],
  ),
};

/**
 * Get the global metrics registry
 */
export function getRegistry(): MetricsRegistry {
  return registry;
}

/**
 * Export all metrics in Prometheus format
 */
export function exportMetrics(): string {
  // Add process metrics
  const processMetrics = [
    `# HELP process_uptime_seconds Process uptime in seconds`,
    `# TYPE process_uptime_seconds gauge`,
    `process_uptime_seconds ${process.uptime()}`,
    '',
    `# HELP process_heap_bytes Process heap memory usage`,
    `# TYPE process_heap_bytes gauge`,
    `process_heap_bytes ${process.memoryUsage().heapUsed}`,
  ].join('\n');

  return `${processMetrics}\n\n${registry.toPrometheus()}`;
}

/**
 * Create metrics endpoint response
 */
export function createMetricsResponse(): Response {
  return new Response(exportMetrics(), {
    headers: {
      'Content-Type': 'text/plain; version=0.0.4; charset=utf-8',
    },
  });
}
