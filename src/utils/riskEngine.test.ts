import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CONTROLS,
  DATA_SOURCES,
  INITIAL_AGENTS,
  INITIAL_FINDINGS,
  INITIAL_POLICY_RULES,
  MCP_SERVERS,
  POLICY_SIMULATION_EVENTS,
  TENANTS,
} from '../data/mockData';
import {
  buildExposurePathForAgent,
  computeComplianceCoverage,
  computeDashboardMetrics,
  createJiraTicketForFinding,
  filterAgents,
  summarizePolicySimulation,
} from './riskEngine';

test('filterAgents narrows by tenant, query, risk, and type', () => {
  const nwAll = filterAgents(INITIAL_AGENTS, 'tenant_northwind', {
    query: '',
    risk: 'all',
    type: 'all',
  });
  assert.equal(nwAll.length, 6);

  const shadowOnly = filterAgents(INITIAL_AGENTS, 'tenant_northwind', {
    query: '',
    risk: 'all',
    type: 'Shadow AI',
  });
  assert.equal(shadowOnly.length, 1);
  assert.equal(shadowOnly[0].name, 'Marketing Content Agent');

  const payrollQuery = filterAgents(INITIAL_AGENTS, 'tenant_northwind', {
    query: 'payroll',
    risk: 'critical',
    type: 'all',
  });
  assert.equal(payrollQuery.length, 1);
  assert.equal(payrollQuery[0].id, 'agent_finance_copilot');
});

test('computeDashboardMetrics produces all 8 executive KPI families accurately', () => {
  const northwind = TENANTS[0];
  const metrics = computeDashboardMetrics(
    northwind,
    INITIAL_AGENTS,
    INITIAL_FINDINGS,
    DATA_SOURCES,
    CONTROLS
  );
  assert.equal(metrics.totalAgents, 42);
  assert.equal(metrics.shadowAgents, 7);
  assert.equal(metrics.criticalFindingsCount, 2);
  assert.equal(metrics.reachableSensitiveSources, 5);
  assert.ok(metrics.complianceCoveragePct > 50 && metrics.complianceCoveragePct <= 100);
});

test('buildExposurePathForAgent builds 4-hop chain for Finance Copilot', () => {
  const finance = INITIAL_AGENTS.find((a) => a.id === 'agent_finance_copilot');
  assert.ok(finance);
  const path = buildExposurePathForAgent(finance, MCP_SERVERS, DATA_SOURCES);
  assert.equal(path.nodes.length, 4);
  assert.equal(path.nodes[0].label, 'Finance Copilot');
  assert.equal(path.nodes[1].label, 'svc-finance-copilot');
  assert.equal(path.nodes[2].label, 'finance-mcp');
  assert.equal(path.nodes[3].label, 'S3 payroll bucket');
});

test('createJiraTicketForFinding assigns Cloud Security and transitions open finding to in_progress', () => {
  const updated = createJiraTicketForFinding(
    INITIAL_FINDINGS,
    'finding_001',
    'SEC-4201',
    'Cloud Security'
  );
  const f1 = updated.find((f) => f.id === 'finding_001');
  assert.ok(f1);
  assert.equal(f1.jiraTicketKey, 'SEC-4201');
  assert.equal(f1.status, 'in_progress');
  assert.equal(f1.owner, 'Cloud Security');
});

test('computeComplianceCoverage calculates covered, partial, and gap counts', () => {
  const cov = computeComplianceCoverage(CONTROLS);
  assert.equal(cov.coveredCount, 3);
  assert.equal(cov.partialCount, 3);
  assert.equal(cov.gapCount, 2);
  assert.equal(cov.coveragePct, 56);
});

test('summarizePolicySimulation counts block, redact, and allow outcomes', () => {
  const summary = summarizePolicySimulation(
    'observe',
    INITIAL_POLICY_RULES,
    POLICY_SIMULATION_EVENTS
  );
  assert.equal(summary.modeLabel, 'Observe-Only (Audit)');
  assert.equal(summary.wouldBlockCount, 2);
  assert.equal(summary.wouldRedactCount, 1);
  assert.equal(summary.allowedCount, 1);
  assert.equal(summary.activeRuleCount, 4);
});
