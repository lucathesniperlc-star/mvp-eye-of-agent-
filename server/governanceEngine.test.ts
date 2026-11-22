import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'node:net';
import { createApiRouter } from './api.ts';
import {
  buildAuditorExportPackage,
  classifyContent,
  createChainedEvidenceRecord,
  DEFAULT_RETENTION_POLICY,
  GOVERNANCE_CONTROLS,
  inspectGatewayRequest,
  SEED_GATEWAY_POLICIES,
  verifyEvidenceHashChain,
} from './governanceEngine.ts';
import { computeWeightedRiskScore } from './riskScoringEngine.ts';
import { TenantDataStore } from './store.ts';
import type { Agent, EvidenceType } from '../src/types/security.ts';

test('6-factor weighted risk formula matches spec (87.5 High, boundaries, NIST AI RMF)', () => {
  const financeExample = computeWeightedRiskScore({
    dataSensitivity: 100,
    identityPrivilege: 90,
    exposureBreadth: 40,
    agentAutonomy: 100,
    governanceGap: 100,
    activity: 80,
  });
  assert.equal(financeExample.totalScore, 87.5);
  assert.equal(financeExample.level, 'high');
  assert.equal(financeExample.actionRequired, 'Remediate within 7 days');
  assert.equal(financeExample.factors.length, 6);
  assert.ok(financeExample.nistAiRmf.govern.length > 0);
  assert.ok(financeExample.nistAiRmf.map.length > 0);
  assert.ok(financeExample.nistAiRmf.measure.length > 0);
  assert.ok(financeExample.nistAiRmf.manage.length > 0);

  const critical = computeWeightedRiskScore({
    dataSensitivity: 100,
    identityPrivilege: 100,
    exposureBreadth: 90,
    agentAutonomy: 100,
    governanceGap: 100,
    activity: 90,
  });
  assert.equal(critical.level, 'critical');
  assert.equal(critical.actionRequired, 'Immediate remediation');

  const zero = computeWeightedRiskScore({
    dataSensitivity: 0,
    identityPrivilege: 0,
    exposureBreadth: 0,
    agentAutonomy: 0,
    governanceGap: 0,
    activity: 0,
  });
  assert.equal(zero.totalScore, 0);
  assert.equal(zero.level, 'informational');
  assert.equal(zero.actionRequired, 'No action');
});

test('Hash-chained EvidenceRecord vault covers 8 types, 9 controls across 5 frameworks, and redacts secrets', () => {
  const ds = new TenantDataStore();
  const controls = ds.getControlsForTenant('tenant_northwind');
  assert.equal(controls.length, GOVERNANCE_CONTROLS.length);
  assert.equal(controls.length, 9);

  const frameworks = new Set(controls.map((c) => c.framework));
  assert.ok(frameworks.has('SOC 2'));
  assert.ok(frameworks.has('ISO 27001'));
  assert.ok(frameworks.has('ISO 42001'));
  assert.ok(frameworks.has('GDPR'));
  assert.ok(frameworks.has('EU AI Act'));

  const records = ds.getEvidenceRecords('tenant_northwind');
  const seenTypes = new Set<EvidenceType>(records.map((r) => r.evidence_type));
  const expectedTypes: EvidenceType[] = [
    'identity_inventory',
    'permission_snapshot',
    'data_access_evidence',
    'agent_inventory',
    'policy_decision',
    'approval_record',
    'remediation_proof',
    'audit_event',
  ];
  for (const t of expectedTypes) {
    assert.ok(seenTypes.has(t), `Missing evidence type: ${t}`);
  }

  const chain = verifyEvidenceHashChain(records);
  assert.equal(chain.valid, true);
  assert.ok(chain.verifiedCount >= 8);

  const customEv = createChainedEvidenceRecord({
    tenantId: 'tenant_northwind',
    controlId: 'SOC2_CC6.1',
    framework: 'SOC 2',
    evidenceType: 'audit_event',
    source: 'entra_id',
    resourceId: 'sp_01',
    title: 'Redaction test',
    summary: 'Verify secret stripping',
    payload: { accessToken: 'secret-token-value', safeField: 'visible' },
    previousHash: chain.headHash,
  });
  assert.equal(customEv.redacted, true);
  assert.ok(customEv.content_hash.startsWith('sha256:'));
  assert.equal(customEv.previous_hash, chain.headHash);

  const pkg = buildAuditorExportPackage({
    tenantId: 'tenant_northwind',
    tenantName: 'Northwind Financial',
    framework: 'SOC 2',
    controls,
    evidenceRecords: records,
  });
  assert.equal(pkg.auditorScoped, true);
  assert.equal(pkg.hashChainIntegrity.valid, true);
  assert.ok(pkg.exportDurationMs < 300000);
  assert.ok(pkg.controls.every((c) => c.framework === 'SOC 2'));
});

test('Observe-mode gateway forwards 100% of traffic, runs DLP classification, and retains zero raw prompts', () => {
  const dlp = classifyContent({
    promptText: 'Send SSN 123-45-6789 and patient MRN payroll with sk-abc1234567890xyz',
    tool: 'export_payroll',
    targetResource: 's3://payroll-prod/employee_pii.csv',
  });
  assert.equal(dlp.pii, true);
  assert.equal(dlp.phi, true);
  assert.equal(dlp.financial, true);
  assert.equal(dlp.secrets, true);

  const sampleAgent: Agent = {
    id: 'agent_finance_copilot',
    tenantId: 'tenant_northwind',
    name: 'Finance Copilot',
    owner: 'Unassigned',
    ownerTeam: 'Finance Ops',
    type: 'Unowned',
    status: 'active',
    riskScore: 88,
    riskLevel: 'high',
    identity: 'svc-finance-copilot',
    identityType: 'Entra Service Principal',
    models: ['gpt-4.1'],
    mcpServers: ['finance-mcp'],
    tools: ['export_payroll'],
    dataSources: ['ds_payroll'],
    permissions: ['s3:GetObject'],
    businessService: 'Payroll Automation',
    lastSeen: 'Now',
    dailyCalls: 1200,
    findings: [],
  };

  const observeRes = inspectGatewayRequest({
    tenantId: 'tenant_northwind',
    agent: sampleAgent,
    provider: 'openai',
    model: 'gpt-4.1',
    tool: 'export_payroll',
    mcpServer: 'finance-mcp',
    mode: 'observe',
    policies: SEED_GATEWAY_POLICIES,
    retention: DEFAULT_RETENTION_POLICY,
    promptText: 'Export employee_pii SSN 123-45-6789 payroll',
    targetResource: 's3://payroll-prod/employee_pii.csv',
    previousEvidenceHash: 'sha256:genesis',
  });

  assert.equal(observeRes.event.forwarded, true);
  assert.equal(observeRes.event.policy_decision, 'would_block');
  assert.equal(observeRes.event.policy_rule, 'no_payroll_export');
  assert.equal(observeRes.event.content_retained, false);
  assert.equal(observeRes.event.redacted_excerpt, undefined);
  assert.ok(observeRes.evidenceRecord.id.startsWith('evidence_'));
});

test('HTTP E2E: Dynamic risk recalculation, time-bounded compliance export, and observe/enforce gateway', async () => {
  const app = express();
  app.use('/api', createApiRouter());
  const server = app.listen(0);
  const { port } = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'ciso@northwind.com', totpCode: '123456' }),
    });
    assert.equal(loginRes.status, 200);
    const cookie = loginRes.headers.get('set-cookie')!.split(';')[0];

    // 1. Dynamic risk recalculation on agent_finance_copilot
    const recalcRes = await fetch(
      `${baseUrl}/api/agents/agent_finance_copilot/risk-signals`,
      {
        method: 'POST',
        headers: { Cookie: cookie, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          owner: 'm.chen@northwind.com',
          overrides: { governanceGap: 10, identityPrivilege: 40, activity: 30 },
        }),
      }
    );
    assert.equal(recalcRes.status, 200);
    const recalcBody = (await recalcRes.json()) as {
      agent: { riskScore: number; riskAssessment: { totalScore: number; factors: unknown[] } };
    };
    assert.equal(recalcBody.agent.riskAssessment.factors.length, 6);
    assert.ok(recalcBody.agent.riskScore < 85);

    // 2. Time-bounded auditor export
    const exportRes = await fetch(`${baseUrl}/api/compliance/export`, {
      method: 'POST',
      headers: { Cookie: cookie, 'Content-Type': 'application/json' },
      body: JSON.stringify({ framework: 'EU AI Act' }),
    });
    assert.equal(exportRes.status, 200);
    const exportBody = (await exportRes.json()) as {
      exported: boolean;
      hashChainIntegrity: { valid: boolean };
      exportDurationMs: number;
      controls: Array<{ framework: string }>;
    };
    assert.equal(exportBody.exported, true);
    assert.equal(exportBody.hashChainIntegrity.valid, true);
    assert.ok(exportBody.exportDurationMs < 300000);
    assert.ok(exportBody.controls.length >= 1);
    assert.ok(exportBody.controls.every((c) => c.framework === 'EU AI Act'));

    // 3. Observe-mode gateway inspection forwards traffic without blocking
    const gwObs = await fetch(`${baseUrl}/api/gateway/inspect`, {
      method: 'POST',
      headers: { Cookie: cookie, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        agentId: 'agent_finance_copilot',
        tool: 'export_payroll',
        model: 'gpt-4.1',
        targetResource: 's3://payroll-prod/employee_pii.csv',
        promptText: 'Payroll SSN 123-45-6789 export',
      }),
    });
    assert.equal(gwObs.status, 200);
    const gwObsBody = (await gwObs.json()) as {
      event: { forwarded: boolean; policy_decision: string; content_retained: boolean };
    };
    assert.equal(gwObsBody.event.forwarded, true);
    assert.equal(gwObsBody.event.policy_decision, 'would_block');
    assert.equal(gwObsBody.event.content_retained, false);

    // 4. Retention policy update preserves rawPromptRetained=false
    const retRes = await fetch(`${baseUrl}/api/gateway/retention`, {
      method: 'POST',
      headers: { Cookie: cookie, 'Content-Type': 'application/json' },
      body: JSON.stringify({ redactedExcerptOptIn: false }),
    });
    assert.equal(retRes.status, 200);
    const retBody = (await retRes.json()) as {
      retentionConfig: { rawPromptRetained: boolean; rawResponseRetained: boolean };
    };
    assert.equal(retBody.retentionConfig.rawPromptRetained, false);
    assert.equal(retBody.retentionConfig.rawResponseRetained, false);

    // 5. Switch to enforce mode and verify block stops forwarding, then restore observe mode
    await fetch(`${baseUrl}/api/policy/mode`, {
      method: 'POST',
      headers: { Cookie: cookie, 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'enforce' }),
    });
    const gwEnf = await fetch(`${baseUrl}/api/gateway/inspect`, {
      method: 'POST',
      headers: { Cookie: cookie, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        agentId: 'agent_finance_copilot',
        tool: 'export_payroll',
        promptText: 'Payroll SSN 123-45-6789 export',
      }),
    });
    const gwEnfBody = (await gwEnf.json()) as {
      event: { forwarded: boolean; policy_decision: string };
    };
    assert.equal(gwEnfBody.event.forwarded, false);
    assert.equal(gwEnfBody.event.policy_decision, 'block');

    await fetch(`${baseUrl}/api/policy/mode`, {
      method: 'POST',
      headers: { Cookie: cookie, 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'observe' }),
    });
  } finally {
    server.close();
  }
});
