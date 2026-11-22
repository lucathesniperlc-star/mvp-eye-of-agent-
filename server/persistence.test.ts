import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import express from 'express';
import type { AddressInfo } from 'node:net';
import { createApiRouter } from './api.ts';
import { TenantDataStore } from './store.ts';

test('File persistence survives store restart for demo requests, agents, policies, and control attestations', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'eoa-persist-'));
  const stateFile = path.join(tmpDir, 'store.json');

  try {
    const store1 = new TenantDataStore({ persist: true, stateFilePath: stateFile });
    const actor = { id: 'usr_owner', email: 'ciso@northwind.com', role: 'owner' as const };

    const demoReq = store1.submitDemoRequest({
      name: 'Taylor Brooks',
      email: 'taylor@northwind.com',
      company: 'Northwind Financial',
    });
    assert.ok(demoReq.id.startsWith('req_'));

    const createdAgent = store1.createAgent(
      'tenant_northwind',
      {
        name: 'Treasury Wire Copilot',
        owner: 'unassigned',
        ownerTeam: 'Treasury Ops',
        type: 'Unowned',
        identity: 'svc-treasury-wire',
        businessService: 'Corporate Treasury',
        tools: ['execute_wire', 'read_ledger'],
        permissions: ['treasury:write', 'bank:wire'],
        dataSources: ['Treasury Ledger', 'Payroll S3'],
      },
      actor
    );
    assert.ok(createdAgent.id.startsWith('agent_'));
    assert.ok(createdAgent.riskScore >= 40);

    const updatedAgent = store1.updateAgentGovernance(
      'tenant_northwind',
      createdAgent.id,
      {
        owner: 'treasury-sec@northwind.com',
        status: 'restricted',
        businessService: 'Treasury Controlled Ops',
      },
      actor
    );
    assert.equal(updatedAgent.owner, 'treasury-sec@northwind.com');
    assert.equal(updatedAgent.status, 'restricted');
    assert.equal(updatedAgent.type, 'Internal agent');

    const createdRule = store1.createPolicyRule(
      'tenant_northwind',
      {
        name: 'Require dual control on wire transfers',
        scope: 'Treasury Wire Copilot · execute_wire',
        action: 'block',
        condition: 'tool == execute_wire && approval == missing',
      },
      actor
    );
    assert.ok(createdRule.id.startsWith('rule_'));

    const createdGwPolicy = store1.createGatewayPolicy(
      'tenant_northwind',
      {
        name: 'Block unredacted bank routing',
        agents: ['treasury-wire-copilot'],
        tools: ['execute_wire'],
        dataClassification: ['pii_financial'],
        decision: 'block',
      },
      actor
    );
    assert.equal(createdGwPolicy.id, 'block_unredacted_bank_routing');
    assert.ok(createdGwPolicy.yaml.includes('decision: block'));

    const attested = store1.attestComplianceControl(
      'tenant_northwind',
      'ctrl_eu_ai_act',
      {
        summary: 'Verified human-in-the-loop approval gate on all high-risk agent tool calls',
        source: 'CISO Quarterly Review',
      },
      actor
    );
    assert.ok(attested.evidenceRecord.id.startsWith('evidence_'));
    assert.ok(attested.control.evidenceCount >= 1);

    // Simulate process restart by instantiating a fresh store reading the same snapshot file
    const store2 = new TenantDataStore({ persist: true, stateFilePath: stateFile });
    assert.equal(store2.listDemoRequests().length, 1);
    assert.equal(store2.listDemoRequests()[0].id, demoReq.id);

    const bundle2 = store2.getSharedWorkspaceBundle('tenant_northwind', 'owner', 'ciso@northwind.com');
    const persistedAgent = bundle2.agents.find((a) => a.id === createdAgent.id);
    assert.ok(persistedAgent);
    assert.equal(persistedAgent?.owner, 'treasury-sec@northwind.com');
    assert.equal(persistedAgent?.status, 'restricted');

    const policy2 = store2.getPolicyState('tenant_northwind');
    assert.ok(policy2.rules.some((r) => r.id === createdRule.id));
    assert.ok(policy2.gatewayPolicies.some((p) => p.id === createdGwPolicy.id));

    assert.ok(bundle2.evidenceRecords.some((e) => e.id === attested.evidenceRecord.id));

    // Reset restores clean baseline and removes created artifacts
    store2.resetToSeedState(actor, 'tenant_northwind');
    assert.equal(store2.listDemoRequests().length, 0);
    const bundleReset = store2.getSharedWorkspaceBundle(
      'tenant_northwind',
      'owner',
      'ciso@northwind.com'
    );
    assert.ok(!bundleReset.agents.some((a) => a.id === createdAgent.id));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('HTTP endpoints support agent CRUD, policies, attestation, audit filter, demo requests, reset, and RBAC', async () => {
  const app = express();
  app.use('/api', createApiRouter());

  const server = await new Promise<ReturnType<typeof app.listen>>((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });

  const addr = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${addr.port}/api`;
  let ownerCookie = '';

  try {
    // 1. Health check
    const healthRes = await fetch(`${baseUrl}/health`);
    assert.equal(healthRes.status, 200);
    const healthBody = await healthRes.json();
    assert.equal(healthBody.ok, true);

    // 2. Public demo request submission
    const demoPost = await fetch(`${baseUrl}/demo-requests`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Morgan Vance',
        email: 'morgan@acme-security.io',
        company: 'Acme Security',
      }),
    });
    assert.equal(demoPost.status, 201);
    const demoPostBody = await demoPost.json();
    assert.ok(demoPostBody.request.id.startsWith('req_'));

    // 3. Login as Owner & Auditor
    const ownerLogin = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'ciso@northwind.com', totpCode: '123456' }),
    });
    assert.equal(ownerLogin.status, 200);
    ownerCookie = (ownerLogin.headers.get('set-cookie') || '').split(';')[0];

    const auditorLogin = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'external-audit@kpmg-sandbox.example', totpCode: '654321' }),
    });
    assert.equal(auditorLogin.status, 200);
    const auditorCookie = (auditorLogin.headers.get('set-cookie') || '').split(';')[0];

    // Verify demo request is listed when authenticated
    const demoList = await fetch(`${baseUrl}/demo-requests`, {
      headers: { Cookie: ownerCookie },
    });
    assert.equal(demoList.status, 200);
    const demoListBody = await demoList.json();
    assert.ok(demoListBody.requests.some((r: { id: string }) => r.id === demoPostBody.request.id));

    // 4. Auditor RBAC 403 checks on mutating endpoints
    const auditorAgentDeny = await fetch(`${baseUrl}/agents`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: auditorCookie },
      body: JSON.stringify({ name: 'Unauthorized Bot' }),
    });
    assert.equal(auditorAgentDeny.status, 403);

    const auditorRuleDeny = await fetch(`${baseUrl}/policy/rules`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: auditorCookie },
      body: JSON.stringify({
        name: 'Denied Rule',
        scope: 'All',
        action: 'block',
        condition: 'true',
      }),
    });
    assert.equal(auditorRuleDeny.status, 403);

    const auditorResetDeny = await fetch(`${baseUrl}/system/reset-demo`, {
      method: 'POST',
      headers: { Cookie: auditorCookie },
    });
    assert.equal(auditorResetDeny.status, 403);

    // 5. Owner creates & updates agent
    const createAgentRes = await fetch(`${baseUrl}/agents`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: ownerCookie },
      body: JSON.stringify({
        name: 'SOC Triage Assistant',
        owner: 'soc-lead@northwind.com',
        ownerTeam: 'SecOps',
        type: 'Internal agent',
        identity: 'svc-soc-triage',
        businessService: 'Security Operations',
        tools: ['read_alerts', 'create_tickets'],
        permissions: ['siem:read', 'jira:write'],
        dataSources: ['Payroll S3'],
      }),
    });
    assert.equal(createAgentRes.status, 201);
    const { agent } = await createAgentRes.json();
    assert.ok(agent.id.startsWith('agent_'));

    const patchAgentRes = await fetch(`${baseUrl}/agents/${agent.id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', Cookie: ownerCookie },
      body: JSON.stringify({ status: 'quarantined', owner: 'ciso@northwind.com' }),
    });
    assert.equal(patchAgentRes.status, 200);
    const patchedBody = await patchAgentRes.json();
    assert.equal(patchedBody.agent.status, 'quarantined');
    assert.equal(patchedBody.agent.owner, 'ciso@northwind.com');

    // 6. Create governance rule & custom YAML gateway policy
    const ruleRes = await fetch(`${baseUrl}/policy/rules`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: ownerCookie },
      body: JSON.stringify({
        name: 'Block SIEM token forwarding',
        scope: 'SOC Triage Assistant',
        action: 'block',
        condition: 'payload contains secret_key',
      }),
    });
    assert.equal(ruleRes.status, 201);

    const gwPolRes = await fetch(`${baseUrl}/enterprise/policies`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: ownerCookie },
      body: JSON.stringify({
        name: 'SOC Strict Output Filter',
        agents: ['soc-triage-assistant'],
        tools: ['read_alerts'],
        dataClassification: ['secrets'],
        decision: 'redact',
      }),
    });
    assert.equal(gwPolRes.status, 201);
    const gwPolBody = await gwPolRes.json();
    assert.equal(gwPolBody.policy.id, 'soc_strict_output_filter');

    // 7. Control attestation
    const attestRes = await fetch(`${baseUrl}/compliance/controls/ctrl_eu_ai_act/attest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: ownerCookie },
      body: JSON.stringify({
        summary: 'Human approval verified for SOC Triage Assistant containment actions',
        source: 'SecOps Audit',
      }),
    });
    assert.equal(attestRes.status, 201);
    const attestBody = await attestRes.json();
    assert.ok(attestBody.evidenceRecord.id.startsWith('evidence_'));

    // 8. Server-side audit search & outcome filter
    const filteredAuditRes = await fetch(
      `${baseUrl}/audit-events?search=SOC%20Triage&outcome=allowed`,
      { headers: { Cookie: ownerCookie } }
    );
    assert.equal(filteredAuditRes.status, 200);
    const filteredAuditBody = await filteredAuditRes.json();
    assert.ok(filteredAuditBody.events.length >= 1);
    assert.ok(
      filteredAuditBody.events.every((ev: { outcome: string }) => ev.outcome === 'allowed')
    );

    const deniedAuditRes = await fetch(`${baseUrl}/audit-events?outcome=denied`, {
      headers: { Cookie: ownerCookie },
    });
    assert.equal(deniedAuditRes.status, 200);
    const deniedAuditBody = await deniedAuditRes.json();
    assert.ok(
      deniedAuditBody.events.every((ev: { outcome: string }) => ev.outcome === 'denied')
    );
  } finally {
    if (ownerCookie) {
      await fetch(`${baseUrl}/system/reset-demo`, {
        method: 'POST',
        headers: { Cookie: ownerCookie },
      });
    }
    server.close();
  }
});
