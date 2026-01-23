/**
 * Metrics Tests
 */

import { describe, expect, test } from 'bun:test';
import { createMetricsResponse, exportMetrics, getRegistry, metrics } from '../utils/metrics.js';

describe('Metrics', () => {
  describe('Counter', () => {
    test('increments counter', () => {
      const registry = getRegistry();
      const counter = registry.counter('test_counter', 'Test counter');

      counter.inc();
      expect(counter.get()).toBe(1);

      counter.inc(undefined, 5);
      expect(counter.get()).toBe(6);
    });

    test('increments counter with labels', () => {
      const registry = getRegistry();
      const counter = registry.counter('test_labeled_counter', 'Test labeled counter');

      counter.inc({ method: 'GET', status: '200' });
      counter.inc({ method: 'GET', status: '200' });
      counter.inc({ method: 'POST', status: '201' });

      expect(counter.get({ method: 'GET', status: '200' })).toBe(2);
      expect(counter.get({ method: 'POST', status: '201' })).toBe(1);
    });
  });

  describe('Gauge', () => {
    test('sets and gets gauge value', () => {
      const registry = getRegistry();
      const gauge = registry.gauge('test_gauge', 'Test gauge');

      gauge.set(10);
      expect(gauge.get()).toBe(10);

      gauge.set(5);
      expect(gauge.get()).toBe(5);
    });

    test('increments and decrements gauge', () => {
      const registry = getRegistry();
      const gauge = registry.gauge('test_gauge_inc', 'Test gauge inc/dec');

      gauge.inc();
      expect(gauge.get()).toBe(1);

      gauge.inc(undefined, 5);
      expect(gauge.get()).toBe(6);

      gauge.dec();
      expect(gauge.get()).toBe(5);

      gauge.dec(undefined, 3);
      expect(gauge.get()).toBe(2);
    });
  });

  describe('Histogram', () => {
    test('observes values', () => {
      const registry = getRegistry();
      const histogram = registry.histogram('test_histogram', 'Test histogram', [0.1, 0.5, 1, 5]);

      histogram.observe(0.05);
      histogram.observe(0.3);
      histogram.observe(2);
      histogram.observe(10);

      const output = histogram.toPrometheus();
      expect(output).toContain('test_histogram_bucket');
      expect(output).toContain('test_histogram_sum');
      expect(output).toContain('test_histogram_count');
    });
  });

  describe('Pre-defined Metrics', () => {
    test('httpRequestsTotal exists', () => {
      expect(metrics.httpRequestsTotal).toBeDefined();
    });

    test('analysisTotal exists', () => {
      expect(metrics.analysisTotal).toBeDefined();
    });

    test('triageTotal exists', () => {
      expect(metrics.triageTotal).toBeDefined();
    });

    test('analysisInProgress exists', () => {
      expect(metrics.analysisInProgress).toBeDefined();
    });

    test('llmAvailable exists', () => {
      expect(metrics.llmAvailable).toBeDefined();
    });

    test('triageDuration exists', () => {
      expect(metrics.triageDuration).toBeDefined();
    });

    test('analysisDuration exists', () => {
      expect(metrics.analysisDuration).toBeDefined();
    });

    test('httpRequestDuration exists', () => {
      expect(metrics.httpRequestDuration).toBeDefined();
    });
  });

  describe('Prometheus Export', () => {
    test('exportMetrics returns valid Prometheus format', () => {
      const output = exportMetrics();

      // Should contain process metrics
      expect(output).toContain('process_uptime_seconds');
      expect(output).toContain('process_heap_bytes');

      // Should contain HELP and TYPE annotations
      expect(output).toContain('# HELP');
      expect(output).toContain('# TYPE');
    });

    test('createMetricsResponse returns correct content type', () => {
      const response = createMetricsResponse();

      expect(response.headers.get('Content-Type')).toContain('text/plain');
    });
  });
});
