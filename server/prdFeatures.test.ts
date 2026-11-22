import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import express from 'express';
import type { AddressInfo } from 'node:net';
import { createApiRouter } from './api.ts';
import { TenantDataStore } from './store.ts';

test('Store persistence: agent lifecycle, vertical pack, policy/compliance exceptions survive reload', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'eoa-prd-'));
  const stateFile = path.join(tmpDir, 'store.json');
  const actor = { id: 'usr_owner', email: 'ciso@northwind.com', role: 'owner' as const };

  try {
    const ds1 = new TenantDataStore({ persist: true, stateFilePath: stateFile });

    // 1. Agent lifecycle review on unverified agent_procurement
    const sanctioned = ds1.reviewAgentLifecycle(
      'tenant_northwind',
      'agent_procurement',
      { action: 'sanction', owner: 'procurement-sec@northwind.com', reason: 'Reviewed vendor contract scope' },
      actor
    );
    assert.equal(sanctioned.lifecycleState, 'sanctioned');
    assert.ok((sanctioned.confidenceScore ?? 0) >= 96);
    assert.equal(sanctioned.owner, 'procurement-sec@northwind.com');

    // 2. Vertical policy pack install & idempotency
    const packInstall1 = ds1.toggleVerticalPack('tenant_northwind', 'fintech', true, actor);
    assert.ok(packInstall1.activePackIds.includes('fintech'));
    assert.ok(packInstall1.rulesAdded >= 1);

    const packInstall2 = ds1.toggleVerticalPack('tenant_northwind', 'fintech', true, actor);
    assert.equal(packInstall2.rulesAdded, 0);

    // 3. Policy exception & Compliance exception + Gateway failover config
    const polExc = ds1.createPolicyException(
      'tenant_northwind',
      {
        policyId: 'prevent_payroll_exfiltration',
        agentId: 'agent_finance_copilot',
        justification: 'Quarterly tax reconciliation batch run',
        expiresInDays: 7,
      },
      actor
    );
    assert.equal(polExc.status, 'active');

    const compExc = ds1.createComplianceException(
      'tenant_northwind',
      {
        controlId: 'ctrl_soc2_cc62',
        reason: 'Legacy connector migration window',
        compensatingControl: 'Read-only IAM policy + hourly SIEM anomaly sweep',
        expiresInDays: 14,
      },
      actor
    );
    assert.equal(compExc.status, 'active');

    ds1.updateGatewayRuntimeConfig(
      'tenant_northwind',
      { failoverMode: 'fail_open', responseInspectionEnabled: true },
      actor
    );

    // 4. Reload from persisted snapshot
    const ds2 = new TenantDataStore({ persist: true, stateFilePath: stateFile });
    const bundle2 = ds2.getSharedWorkspaceBundle('tenant_northwind', 'owner', 'ciso@northwind.com');

    const reloadedAgent = bundle2.agents.find((a) => a.id === 'agent_procurement');
    assert.equal(reloadedAgent?.lifecycleState, 'sanctioned');
    assert.equal(reloadedAgent?.owner, 'procurement-sec@northwind.com');

    assert.ok(bundle2.activeVerticalPacks.includes('fintech'));
    assert.ok(bundle2.complianceExceptions.some((c) => c.id === compExc.id && c.status === 'active'));

    const policy2 = ds2.getPolicyState('tenant_northwind');
    assert.ok(policy2.policyExceptions.some((p) => p.id === polExc.id && p.status === 'active'));
    assert.equal(policy2.gatewayRuntimeConfig.failoverMode, 'fail_open');

    // 5. Exposure paths include 5th hop externalDestination and pathState
    const graph2 = ds2.getExposurePaths('tenant_northwind');
    assert.ok(graph2.paths.length > 0);
    const finPath = graph2.paths.find((p) => p.agentId === 'agent_finance_copilot');
    assert.ok(finPath);
    assert.ok(finPath.pathState);
    assert.ok(finPath.externalDestination);
    assert.equal(finPath.externalDestination.category, 'external_llm');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('HTTP E2E: lifecycle, packs, registry PEP enforcement, exceptions, failover, 8-action containment, CSV export, and auditor RBAC', async () => {
  const app = express();
  app.use('/api', createApiRouter());

  const server = await new Promise<ReturnType<typeof app.listen>>((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const { port } = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${port}/api`;
  let ownerCookie = '';

  try {
    // Login owner & auditor
    const ownerRes = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'ciso@northwind.com', totpCode: '123456' }),
    });
    assert.equal(ownerRes.status, 200);
    ownerCookie = (ownerRes.headers.get('set-cookie') || '').split(';')[0];

    const resetInit = await fetch(`${baseUrl}/system/reset-demo`, {
      method: 'POST',
      headers: { Cookie: ownerCookie },
    });
    assert.equal(resetInit.status, 200);

    const audRes = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'external-audit@kpmg-sandbox.example', totpCode: '654321' }),
    });
    assert.equal(audRes.status, 200);
    const auditorCookie = (audRes.headers.get('set-cookie') || '').split(';')[0];

    // 1. Auditor RBAC 403 checks across new write routes
    const rbacChecks: Array<{ method: string; url: string; body?: Record<string, unknown> }> = [
      { method: 'POST', url: '/agents/agent_procurement/lifecycle', body: { action: 'sanction' } },
      { method: 'POST', url: '/vertical-packs/healthcare/activate', body: { install: true } },
      { method: 'POST', url: '/registry/models/gpt-4.1/approval', body: { approvalStatus: 'unapproved' } },
      { method: 'POST', url: '/registry/mcp/finance-mcp/approval', body: { approvalStatus: 'disabled' } },
      {
        method: 'POST',
        url: '/policy/exceptions',
        body: { policyId: 'prevent_payroll_exfiltration', agentId: 'agent_finance_copilot', justification: 'test' },
      },
      { method: 'POST', url: '/enterprise/gateway-config', body: { failoverMode: 'fail_open' } },
      {
        method: 'POST',
        url: '/incidents/inc_nw_001/contain',
        body: { action: 'quarantine_agent', approve: true, dryRun: false },
      },
      {
        method: 'POST',
        url: '/compliance/exceptions',
        body: { controlId: 'ctrl_soc2_cc62', reason: 'test', compensatingControl: 'test' },
      },
    ];
    for (const chk of rbacChecks) {
      const r = await fetch(`${baseUrl}${chk.url}`, {
        method: chk.method,
        headers: { 'Content-Type': 'application/json', Cookie: auditorCookie },
        body: JSON.stringify(chk.body ?? {}),
      });
      assert.equal(r.status, 403, `Expected 403 for auditor on ${chk.url}`);
    }

    // 2. Workspace exposes new PRD fields including pathState + externalDestination
    const wsRes = await fetch(`${baseUrl}/workspace`, { headers: { Cookie: ownerCookie } });
    assert.equal(wsRes.status, 200);
    const ws = (await wsRes.json()) as {
      incidents: Array<{ id: string }>;
      containmentCatalog: Array<{ id: string }>;
      verticalPacksCatalog: Array<{ id: string }>;
      providerAdapters: Array<{ id: string }>;
      graph: { paths: Array<{ agentId: string; pathState?: string; externalDestination?: { label: string } }> };
    };
    assert.ok(ws.incidents.some((i) => i.id === 'inc_nw_001'));
    assert.equal(ws.containmentCatalog.length, 8);
    assert.equal(ws.verticalPacksCatalog.length, 10);
    assert.equal(ws.providerAdapters.length, 11);
    assert.ok(ws.graph.paths.some((p) => Boolean(p.pathState) && Boolean(p.externalDestination?.label)));

    // 3. Agent lifecycle review (verify/sanction -> unsanction -> retire)
    const unsancRes = await fetch(`${baseUrl}/agents/agent_marketing_content/lifecycle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: ownerCookie },
      body: JSON.stringify({ action: 'unsanction', reason: 'Shadow AI confirmation' }),
    });
    assert.equal(unsancRes.status, 200);
    const unsancBody = (await unsancRes.json()) as { agent: { lifecycleState: string; status: string } };
    assert.equal(unsancBody.agent.lifecycleState, 'unsanctioned');
    assert.equal(unsancBody.agent.status, 'restricted');

    // 4. Vertical Pack install & deactivate
    const packRes = await fetch(`${baseUrl}/vertical-packs/healthcare/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: ownerCookie },
      body: JSON.stringify({ install: true }),
    });
    assert.equal(packRes.status, 200);
    const packBody = (await packRes.json()) as { activePackIds: string[] };
    assert.ok(packBody.activePackIds.includes('healthcare'));

    // 5. Model/MCP Registry enforcement at PDP + Policy Exception override + Revoke
    const mcpBlockRes = await fetch(`${baseUrl}/registry/mcp/github-mcp/approval`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: ownerCookie },
      body: JSON.stringify({ approvalStatus: 'disabled' }),
    });
    assert.equal(mcpBlockRes.status, 200);

    const pepBlockedByMcp = await fetch(`${baseUrl}/enterprise/pep/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: ownerCookie },
      body: JSON.stringify({
        agentId: 'agent_code_review',
        model: 'azure-openai',
        tool: 'read_repos',
        mcpServer: 'github-mcp',
        promptText: 'Summarize PR #402 diff',
      }),
    });
    assert.equal(pepBlockedByMcp.status, 200);
    const pepBlockedBody = (await pepBlockedByMcp.json()) as {
      pdpDecision: string;
      event: { policy_rule: string };
    };
    assert.equal(pepBlockedBody.pdpDecision, 'block');
    assert.equal(pepBlockedBody.event.policy_rule, 'approved_ai_registry_guard');

    // Grant time-bound exception -> overrides PDP to allow
    const excRes = await fetch(`${baseUrl}/policy/exceptions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: ownerCookie },
      body: JSON.stringify({
        policyId: 'approved_ai_registry_guard',
        agentId: 'agent_code_review',
        justification: 'Emergency hotfix PR audit window for github-mcp upgrade',
        expiresInDays: 3,
      }),
    });
    assert.equal(excRes.status, 201);
    const excBody = (await excRes.json()) as { exception: { id: string } };

    const pepAllowedByExc = await fetch(`${baseUrl}/enterprise/pep/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: ownerCookie },
      body: JSON.stringify({
        agentId: 'agent_code_review',
        model: 'azure-openai',
        tool: 'read_repos',
        mcpServer: 'github-mcp',
        promptText: 'Summarize PR #402 diff',
      }),
    });
    const pepAllowedBody = (await pepAllowedByExc.json()) as {
      pdpDecision: string;
      event: { policy_rule: string };
    };
    assert.equal(pepAllowedBody.pdpDecision, 'allow');
    assert.equal(pepAllowedBody.event.policy_rule, 'approved_policy_exception');

    // Revoke exception -> block restored
    const revokeExcRes = await fetch(`${baseUrl}/policy/exceptions/${excBody.exception.id}/revoke`, {
      method: 'POST',
      headers: { Cookie: ownerCookie },
    });
    assert.equal(revokeExcRes.status, 200);

    const pepBlockedAgain = await fetch(`${baseUrl}/enterprise/pep/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: ownerCookie },
      body: JSON.stringify({
        agentId: 'agent_code_review',
        model: 'azure-openai',
        tool: 'read_repos',
        mcpServer: 'github-mcp',
        promptText: 'Summarize PR #402 diff',
      }),
    });
    const pepBlockedAgainBody = (await pepBlockedAgain.json()) as { pdpDecision: string };
    assert.equal(pepBlockedAgainBody.pdpDecision, 'block');

    // Re-approve github-mcp and check response inspection + fail_open vs fail_closed
    await fetch(`${baseUrl}/registry/mcp/github-mcp/approval`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: ownerCookie },
      body: JSON.stringify({ approvalStatus: 'approved' }),
    });

    // 6. Gateway failover & response inspection without raw prompt/response retention
    const pepFailClosed = await fetch(`${baseUrl}/enterprise/pep/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: ownerCookie },
      body: JSON.stringify({
        agentId: 'agent_code_review',
        tool: 'read_repos',
        mcpServer: 'github-mcp',
        simulatePdpUnavailable: true,
      }),
    });
    const failClosedBody = (await pepFailClosed.json()) as {
      pdpDecision: string;
      event: { policy_rule: string; content_retained: boolean };
    };
    assert.equal(failClosedBody.pdpDecision, 'block');
    assert.equal(failClosedBody.event.policy_rule, 'gateway_failover_mode');
    assert.equal(failClosedBody.event.content_retained, false);

    await fetch(`${baseUrl}/enterprise/gateway-config`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: ownerCookie },
      body: JSON.stringify({ failoverMode: 'fail_open', responseInspectionEnabled: true }),
    });

    const pepFailOpen = await fetch(`${baseUrl}/enterprise/pep/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: ownerCookie },
      body: JSON.stringify({
        agentId: 'agent_support',
        tool: 'read_contacts',
        mcpServer: 'crm-mcp',
        simulatePdpUnavailable: true,
      }),
    });
    const failOpenBody = (await pepFailOpen.json()) as { pdpDecision: string };
    assert.equal(failOpenBody.pdpDecision, 'allow');

    const pepRespInspect = await fetch(`${baseUrl}/enterprise/pep/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: ownerCookie },
      body: JSON.stringify({
        agentId: 'agent_support',
        tool: 'read_contacts',
        mcpServer: 'crm-mcp',
        promptText: 'Summarize quarterly account health',
        responseText: 'Contact SSN 123-45-6789 for CFO payout.',
      }),
    });
    const respInspectBody = (await pepRespInspect.json()) as {
      pdpDecision: string;
      event: { tokenized_preview?: string; content_retained: boolean };
    };
    assert.equal(respInspectBody.pdpDecision, 'redact');
    assert.ok(respInspectBody.event.tokenized_preview?.includes('tok_ssn_9f4a21'));
    assert.equal(respInspectBody.event.content_retained, false);

    // 7. 8-Action Incident Containment: 409 without approval -> Dry-run -> Approved Execution
    const contain409 = await fetch(`${baseUrl}/incidents/inc_nw_001/contain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: ownerCookie },
      body: JSON.stringify({ action: 'quarantine_agent', approve: false, dryRun: false }),
    });
    assert.equal(contain409.status, 409);

    const containDryRun = await fetch(`${baseUrl}/incidents/inc_nw_001/contain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: ownerCookie },
      body: JSON.stringify({ action: 'quarantine_agent', approve: false, dryRun: true }),
    });
    assert.equal(containDryRun.status, 200);
    const dryBody = (await containDryRun.json()) as { dryRunDiff?: string; agent?: { status: string } };
    assert.ok(dryBody.dryRunDiff?.includes('Dry-run impact'));
    assert.equal(dryBody.agent?.status, 'active');

    const containExec = await fetch(`${baseUrl}/incidents/inc_nw_001/contain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: ownerCookie },
      body: JSON.stringify({ action: 'quarantine_agent', approve: true, dryRun: false }),
    });
    assert.equal(containExec.status, 200);
    const execBody = (await containExec.json()) as {
      incident: { status: string; executedActions: Array<{ evidenceId: string }> };
      agent?: { status: string };
    };
    assert.equal(execBody.incident.status, 'resolved');
    assert.equal(execBody.agent?.status, 'quarantined');
    assert.ok(execBody.incident.executedActions[0].evidenceId.startsWith('evidence_'));

    // 8. Compliance Exceptions & CSV Export
    const cExcRes = await fetch(`${baseUrl}/compliance/exceptions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: ownerCookie },
      body: JSON.stringify({
        controlId: 'ctrl_soc2_cc62',
        reason: 'Scoped 14-day vendor token deprecation schedule',
        compensatingControl: 'Daily IAM permission diff & SOC webhook alert',
        expiresInDays: 14,
      }),
    });
    assert.equal(cExcRes.status, 201);
    const cExcBody = (await cExcRes.json()) as { exception: { id: string; status: string } };
    assert.equal(cExcBody.exception.status, 'active');

    const cRevRes = await fetch(`${baseUrl}/compliance/exceptions/${cExcBody.exception.id}/revoke`, {
      method: 'POST',
      headers: { Cookie: ownerCookie },
    });
    assert.equal(cRevRes.status, 200);
    const cRevBody = (await cRevRes.json()) as { exception: { status: string } };
    assert.equal(cRevBody.exception.status, 'revoked');

    const csvRes = await fetch(`${baseUrl}/compliance/export-csv`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: ownerCookie },
      body: JSON.stringify({ framework: 'SOC 2' }),
    });
    assert.equal(csvRes.status, 200);
    const csvBody = (await csvRes.json()) as {
      filename: string;
      csvContent: string;
      rowCount: number;
      auditEventId: string;
    };
    assert.ok(csvBody.filename.endsWith('.csv'));
    assert.ok(csvBody.csvContent.startsWith('Framework,Control Code,Title,Status'));
    assert.ok(csvBody.rowCount >= 1);
    assert.ok(csvBody.auditEventId);
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
