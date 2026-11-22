import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'node:net';
import { createApiRouter } from './api.ts';
import {
  decryptTenantSecret,
  encryptTenantSecret,
  redactSensitiveFields,
} from './cryptoVault.ts';
import { findSensitiveExposurePaths } from './graphEngine.ts';
import { TenantDataStore, TenantIsolationError } from './store.ts';

test('Tenant isolation: Tenant A cannot read Tenant B agents, findings, or graph nodes', () => {
  const ds = new TenantDataStore();
  const nwAgents = ds.getAgents('tenant_northwind');
  const euAgents = ds.getAgents('tenant_northwind_eu');

  assert.ok(nwAgents.some((a) => a.id === 'agent_finance_copilot'));
  assert.ok(!nwAgents.some((a) => a.id === 'agent_eu_treasury'));
  assert.ok(euAgents.some((a) => a.id === 'agent_eu_treasury'));
  assert.ok(!euAgents.some((a) => a.id === 'agent_finance_copilot'));

  assert.throws(
    () => ds.withTenantContext('tenant_nonexistent', () => true),
    TenantIsolationError
  );

  const euGraph = ds.getExposurePaths('tenant_northwind_eu');
  assert.ok(euGraph.nodes.every((n) => n.tenantId === 'tenant_northwind_eu'));
  assert.ok(euGraph.edges.every((e) => e.tenantId === 'tenant_northwind_eu'));
});

test('Credential security: AES-256-GCM encryption isolates tenants and redacts secrets', () => {
  const plaintext = 'oauth_rt_super_secret_token_9912';
  const encrypted = encryptTenantSecret('tenant_northwind', 'conn_aws', plaintext);

  assert.notEqual(encrypted.ciphertextHex, plaintext);
  assert.equal(decryptTenantSecret('tenant_northwind', encrypted), plaintext);

  assert.throws(() => decryptTenantSecret('tenant_northwind_eu', encrypted), /Cross-tenant/);

  const safeObj = redactSensitiveFields({
    id: 'conn_aws',
    refreshToken: plaintext,
    nested: { authorization: 'Bearer abc', rawPrompt: 'SSN 123-45-6789' },
  });
  assert.equal(safeObj.refreshToken, '[REDACTED]');
  assert.equal(safeObj.nested.authorization, '[REDACTED]');
  assert.equal(safeObj.nested.rawPrompt, '[REDACTED]');
});

test('Graph correctness: Finance Copilot multi-hop path reaches employee_pii via Payroll Exporter', () => {
  const ds = new TenantDataStore();
  const { nodes, edges } = ds.getExposurePaths('tenant_northwind', 'agent_finance_copilot');
  const paths = findSensitiveExposurePaths(nodes, edges, 'tenant_northwind', 'agent_finance_copilot');

  const piiPath = paths.find((p) => p.targetDataLabel === 'employee_pii');
  assert.ok(piiPath);
  assert.equal(piiPath.hopCount, 5);
  assert.deepEqual(
    piiPath.steps.map((s) => s.label),
    [
      'Finance Copilot',
      'svc-finance-copilot',
      'Payroll Exporter',
      's3:GetObject',
      's3://payroll-prod',
      'employee_pii',
    ]
  );
  assert.deepEqual(
    piiPath.steps.slice(1).map((s) => s.edgeFromPrev),
    ['OPERATED_BY', 'ASSIGNED_ROLE', 'GRANTS_PERMISSION', 'CAN_ACCESS', 'CONTAINS']
  );
});

test('Connector failure safety: failed sync does not corrupt existing graph nodes or edges', async () => {
  const ds = new TenantDataStore();
  const beforeGraph = ds.getExposurePaths('tenant_northwind');
  const beforeCount = beforeGraph.nodes.length;

  await assert.rejects(
    () =>
      ds.syncConnector(
        'tenant_northwind',
        'conn_slack',
        { id: 'usr_admin_nw', email: 'sec-admin@northwind.com', role: 'admin' },
        { simulateFailure: true }
      ),
    /429/
  );

  const afterGraph = ds.getExposurePaths('tenant_northwind');
  assert.equal(afterGraph.nodes.length, beforeCount);
});

test('HTTP E2E: Auth, RBAC, PKCE OAuth, token rotation/revocation, cross-tenant rejection, and audit log', async () => {
  const app = express();
  app.use('/api', createApiRouter());

  const server = app.listen(0);
  const { port } = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // 1. Service account interactive login blocked
    const svcRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'ci-scanner@northwind.com' }),
    });
    assert.equal(svcRes.status, 403);

    // 2. Auditor logs in with MFA
    const audLogin = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'external-audit@kpmg-sandbox.example',
        totpCode: '123456',
      }),
    });
    assert.equal(audLogin.status, 200);
    const audCookie = audLogin.headers.get('set-cookie')!.split(';')[0];

    // 3. Auditor cannot trigger connector sync or create Jira ticket (RBAC 403)
    const audSyncRes = await fetch(`${baseUrl}/api/connectors/conn_slack/sync`, {
      method: 'POST',
      headers: { Cookie: audCookie, 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert.equal(audSyncRes.status, 403);

    const audJiraRes = await fetch(`${baseUrl}/api/findings/finding_001/jira`, {
      method: 'POST',
      headers: { Cookie: audCookie, 'Content-Type': 'application/json' },
      body: JSON.stringify({ assignee: 'Cloud Security' }),
    });
    assert.equal(audJiraRes.status, 403);

    // 4. Cross-tenant header override rejected (403) and logged
    const crossRes = await fetch(`${baseUrl}/api/workspace`, {
      headers: { Cookie: audCookie, 'X-Tenant-Id': 'tenant_northwind_eu' },
    });
    assert.equal(crossRes.status, 403);

    // 5. Admin logs in (requires TOTP MFA)
    const noMfaAdmin = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'sec-admin@northwind.com' }),
    });
    assert.equal(noMfaAdmin.status, 401);

    const adminLogin = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'sec-admin@northwind.com', totpCode: '654321' }),
    });
    assert.equal(adminLogin.status, 200);
    const adminCookie = adminLogin.headers.get('set-cookie')!.split(';')[0];

    // 6. PKCE OAuth start -> callback -> token rotate -> sync -> disconnect/revoke
    const pkceStart = await fetch(`${baseUrl}/api/connectors/conn_slack/oauth/start`, {
      method: 'POST',
      headers: { Cookie: adminCookie },
    });
    assert.equal(pkceStart.status, 200);
    const { authSessionId, codeVerifier } = (await pkceStart.json()) as {
      authSessionId: string;
      codeVerifier: string;
    };

    const pkceCallback = await fetch(`${baseUrl}/api/connectors/conn_slack/oauth/callback`, {
      method: 'POST',
      headers: { Cookie: adminCookie, 'Content-Type': 'application/json' },
      body: JSON.stringify({ authSessionId, codeVerifier }),
    });
    assert.equal(pkceCallback.status, 200);

    const rotRes = await fetch(`${baseUrl}/api/connectors/conn_slack/rotate-token`, {
      method: 'POST',
      headers: { Cookie: adminCookie },
    });
    assert.equal(rotRes.status, 200);
    const rotData = (await rotRes.json()) as { tokenVersion: number };
    assert.equal(rotData.tokenVersion, 2);

    const syncRes = await fetch(`${baseUrl}/api/connectors/conn_slack/sync`, {
      method: 'POST',
      headers: { Cookie: adminCookie, 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert.equal(syncRes.status, 200);
    const syncData = (await syncRes.json()) as { nodesAdded: number };
    assert.equal(syncData.nodesAdded, 1);

    const revRes = await fetch(`${baseUrl}/api/connectors/conn_slack/disconnect`, {
      method: 'POST',
      headers: { Cookie: adminCookie },
    });
    assert.equal(revRes.status, 200);

    // Syncing revoked connector fails cleanly
    const postRevSync = await fetch(`${baseUrl}/api/connectors/conn_slack/sync`, {
      method: 'POST',
      headers: { Cookie: adminCookie, 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert.equal(postRevSync.status, 502);

    // 7. Audit log captured both allowed and denied security events
    const auditRes = await fetch(`${baseUrl}/api/audit-events`, {
      headers: { Cookie: adminCookie },
    });
    assert.equal(auditRes.status, 200);
    const { events } = (await auditRes.json()) as { events: Array<{ action: string }> };
    assert.ok(events.some((e) => e.action === 'security.cross_tenant_attempt_blocked'));
    assert.ok(events.some((e) => e.action === 'rbac.permission_denied'));
    assert.ok(events.some((e) => e.action === 'connector.pkce_authorized'));
    assert.ok(events.some((e) => e.action === 'connector.token_rotated'));
    assert.ok(events.some((e) => e.action === 'connector.disconnected_revoked'));

    // 8. Multi-tenant E2E: EU admin sees only Northwind Europe GmbH
    const euLogin = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'dpo-admin@northwind.eu', totpCode: '111222' }),
    });
    assert.equal(euLogin.status, 200);
    const euCookie = euLogin.headers.get('set-cookie')!.split(';')[0];

    const euWs = await fetch(`${baseUrl}/api/workspace`, {
      headers: { Cookie: euCookie },
    });
    assert.equal(euWs.status, 200);
    const euData = (await euWs.json()) as { tenant: { id: string }; agents: Array<{ id: string }> };
    assert.equal(euData.tenant.id, 'tenant_northwind_eu');
    assert.ok(!euData.agents.some((a) => a.id === 'agent_finance_copilot'));
  } finally {
    server.close();
  }
});
