import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'node:net';
import { createApiRouter } from './api.ts';
import { validateAwsConnectionInput } from './connectorRegistry.ts';
import {
  buildDryRunDiff,
  formatTicketDescription,
  INITIAL_DETECTION_RULES,
} from './findingsEngine.ts';
import { TenantDataStore } from './store.ts';

test('Detection rules catalog & formatted Jira/ServiceNow ticket templates', () => {
  assert.equal(INITIAL_DETECTION_RULES.length, 10);
  const ds = new TenantDataStore();
  const finding = ds.getFindings('tenant_northwind')[0];
  assert.ok(finding.evidence && finding.evidence.length >= 2);
  assert.ok(finding.evidence.every((e) => e.hash.startsWith('sha256:')));

  const ticket = ds.createRemediationTicket(
    'tenant_northwind',
    finding.id,
    { provider: 'servicenow', assignee: 'IAM Governance', notifyChannels: ['Slack', 'Microsoft Teams'] },
    { id: 'usr_admin_nw', email: 'sec-admin@northwind.com', role: 'admin' }
  );
  assert.ok(ticket.jiraTicketKey?.startsWith('INC-'));
  const formatted = formatTicketDescription(ticket, 'servicenow');
  assert.ok(formatted.includes('Exposure path:'));
  assert.ok(formatted.includes('Business impact:'));
  assert.ok(formatted.includes('Recommended remediation:'));
  assert.ok(formatted.includes('SLA:'));

  const diff = buildDryRunDiff(finding);
  assert.ok(diff.dryRunDiff.includes('s3:GetObject'));
  assert.ok(diff.rollbackSnapshot.includes('PayrollExporter'));
});

test('Read-only AWS validation blocks access keys & syncs Entra/AWS/Azure idempotently', async () => {
  assert.throws(
    () =>
      validateAwsConnectionInput({
        accountId: '449102881234',
        roleArn: 'arn:aws:iam::449102881234:role/EyesOfAgentReadOnlyRole',
        externalId: 'eoa-nw-8f3a91c2',
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      }),
    /prohibited/i
  );

  const ds = new TenantDataStore();
  const actor = { id: 'usr_admin_nw', email: 'sec-admin@northwind.com', role: 'admin' as const };

  const entra1 = await ds.connectCloudProvider(
    'tenant_northwind',
    'entra_id',
    { tenantDomain: 'northwind.com', adminConsent: 'granted' },
    actor
  );
  const aws1 = await ds.connectCloudProvider(
    'tenant_northwind',
    'aws',
    {
      accountId: '449102881234',
      roleArn: 'arn:aws:iam::449102881234:role/EyesOfAgentReadOnlyRole',
      externalId: 'eoa-nw-8f3a91c2',
    },
    actor
  );
  const azure1 = await ds.connectCloudProvider(
    'tenant_northwind',
    'azure',
    { subscriptionId: 'sub-nw-prod-01', clientId: 'wif-eoa-northwind-reader' },
    actor
  );

  assert.equal(entra1.connector.readOnly, true);
  assert.equal(aws1.connector.readOnly, true);
  assert.equal(azure1.connector.readOnly, true);

  const countBeforeRepeat = ds.getExposurePaths('tenant_northwind').nodes.length;
  const findingsBeforeRepeat = ds.getFindings('tenant_northwind').length;

  // Repeat sync must be 100% idempotent (0 duplicate nodes/edges/findings)
  const repeat = await ds.syncConnector('tenant_northwind', aws1.connector.id, actor);
  assert.equal(repeat.nodesAdded, 0);
  assert.equal(repeat.edgesAdded, 0);
  assert.equal(repeat.findingsAdded, 0);
  assert.equal(ds.getExposurePaths('tenant_northwind').nodes.length, countBeforeRepeat);
  assert.equal(ds.getFindings('tenant_northwind').length, findingsBeforeRepeat);
});

test('HTTP E2E: Approval-gated remediation, blocked unverified closure (409), verified closure, and rollback', async () => {
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

    // 1. Applying remediation before explicit approval is rejected (409)
    const unapprovedApply = await fetch(
      `${baseUrl}/api/findings/finding_001/apply-remediation`,
      { method: 'POST', headers: { Cookie: cookie } }
    );
    assert.equal(unapprovedApply.status, 409);

    // 2. Trying to close finding before exposure path is removed is rejected (409)
    const prematureClose = await fetch(
      `${baseUrl}/api/findings/finding_001/verify-closure`,
      { method: 'POST', headers: { Cookie: cookie } }
    );
    assert.equal(prematureClose.status, 409);
    const prematureBody = (await prematureClose.json()) as { closed: boolean; finding: { status: string; verification: { status: string } } };
    assert.equal(prematureBody.closed, false);
    assert.equal(prematureBody.finding.verification.status, 'path_still_present');
    assert.notEqual(prematureBody.finding.status, 'remediated');

    // 3. Ticket -> Dry-Run -> Approve -> Apply -> Re-sync & Verify Closure
    const ticketRes = await fetch(`${baseUrl}/api/findings/finding_001/ticket`, {
      method: 'POST',
      headers: { Cookie: cookie, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        provider: 'jira',
        assignee: 'Cloud Security',
        notifyChannels: ['Slack', 'Email'],
      }),
    });
    assert.equal(ticketRes.status, 200);

    const dryRunRes = await fetch(`${baseUrl}/api/findings/finding_001/dry-run`, {
      method: 'POST',
      headers: { Cookie: cookie },
    });
    assert.equal(dryRunRes.status, 200);

    const approveRes = await fetch(`${baseUrl}/api/findings/finding_001/approve`, {
      method: 'POST',
      headers: { Cookie: cookie, 'Content-Type': 'application/json' },
      body: JSON.stringify({ breakGlassDualApproval: false }),
    });
    assert.equal(approveRes.status, 200);

    const applyRes = await fetch(
      `${baseUrl}/api/findings/finding_001/apply-remediation`,
      { method: 'POST', headers: { Cookie: cookie } }
    );
    assert.equal(applyRes.status, 200);

    const verifiedClose = await fetch(
      `${baseUrl}/api/findings/finding_001/verify-closure`,
      { method: 'POST', headers: { Cookie: cookie } }
    );
    assert.equal(verifiedClose.status, 200);
    const closedData = (await verifiedClose.json()) as {
      closed: boolean;
      finding: { status: string; verification: { status: string; proofHash?: string; remainingPathCount?: number } };
    };
    assert.equal(closedData.closed, true);
    assert.equal(closedData.finding.status, 'remediated');
    assert.equal(closedData.finding.verification.status, 'verified_closed');
    assert.equal(closedData.finding.verification.remainingPathCount, 0);
    assert.ok(closedData.finding.verification.proofHash?.startsWith('sha256:'));

    // 4. Rollback restores previous state and re-opens finding
    const rollbackRes = await fetch(`${baseUrl}/api/findings/finding_001/rollback`, {
      method: 'POST',
      headers: { Cookie: cookie },
    });
    assert.equal(rollbackRes.status, 200);
    const rbBody = (await rollbackRes.json()) as { finding: { status: string; remediation: { approvalStatus: string } } };
    assert.equal(rbBody.finding.status, 'in_progress');
    assert.equal(rbBody.finding.remediation.approvalStatus, 'rolled_back');

    // Re-verifying after rollback detects the restored path again (409)
    const postRollbackVerify = await fetch(
      `${baseUrl}/api/findings/finding_001/verify-closure`,
      { method: 'POST', headers: { Cookie: cookie } }
    );
    assert.equal(postRollbackVerify.status, 409);
  } finally {
    server.close();
  }
});
