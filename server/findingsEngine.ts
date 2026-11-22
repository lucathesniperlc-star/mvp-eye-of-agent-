import crypto from 'node:crypto';
import type {
  Agent,
  Finding,
  FindingEvidenceArtifact,
  RiskLevel,
} from '../src/types/security.ts';
import { findSensitiveExposurePaths } from './graphEngine.ts';
import type {
  DetectionRuleDefinition,
  GraphEdge,
  GraphNode,
} from './types.ts';

export const INITIAL_DETECTION_RULES: DetectionRuleDefinition[] = [
  {
    id: 'RULE_UNOWNED_AGENT',
    name: 'Unowned AI agent',
    trigger: 'Agent has no accountable owner',
    severity: 'high',
    category: 'ownership_gap',
  },
  {
    id: 'RULE_PRIVILEGED_IDENTITY',
    name: 'Agent uses privileged identity',
    trigger: 'Agent identity has admin or broad cloud permission',
    severity: 'critical',
    category: 'excessive_identity_privilege',
  },
  {
    id: 'RULE_SENSITIVE_DATA_REACH',
    name: 'Agent reaches sensitive data',
    trigger: 'Agent can read PII, PHI, PCI, source code, or financial data',
    severity: 'critical',
    category: 'excessive_agent_permission',
  },
  {
    id: 'RULE_OVERPERMISSIVE_ROLE',
    name: 'Over-permissive cloud role',
    trigger: 'Role includes * actions or broad resource scope',
    severity: 'high',
    category: 'overpermissive_iam_role',
  },
  {
    id: 'RULE_UNUSED_PERMISSION',
    name: 'Unused privileged permission',
    trigger: 'Permission granted but unused for 90+ days',
    severity: 'medium',
    category: 'unused_entitlement',
  },
  {
    id: 'RULE_PUBLIC_DATA_EXPOSURE',
    name: 'Public data exposure',
    trigger: 'S3 bucket, storage account, or SharePoint accessible externally',
    severity: 'critical',
    category: 'public_storage_exposure',
  },
  {
    id: 'RULE_EXFILTRATION_PATH',
    name: 'Agent can exfiltrate data',
    trigger: 'Agent can send data to external endpoint or public model',
    severity: 'critical',
    category: 'data_exfiltration_path',
  },
  {
    id: 'RULE_NO_AUDIT_EVIDENCE',
    name: 'No audit evidence',
    trigger: 'Agent action lacks traceable audit record',
    severity: 'high',
    category: 'missing_audit_evidence',
  },
  {
    id: 'RULE_STALE_CREDENTIAL',
    name: 'Stale credential',
    trigger: 'Credential older than policy threshold',
    severity: 'high',
    category: 'stale_credential',
  },
  {
    id: 'RULE_SHADOW_AI',
    name: 'Shadow AI detected',
    trigger: 'AI app or MCP server discovered without approved inventory record',
    severity: 'high',
    category: 'shadow_ai_discovery',
  },
];

export function computeEvidenceHash(payload: unknown): string {
  const canonical = JSON.stringify(payload);
  const digest = crypto.createHash('sha256').update(canonical).digest('hex');
  return `sha256:${digest}`;
}

export function buildIdempotentKey(
  tenantId: string,
  provider: string,
  externalResourceId: string
): string {
  return `${tenantId}::${provider}::${externalResourceId}`;
}

export function buildDryRunDiff(finding: Finding): {
  dryRunDiff: string;
  rollbackSnapshot: string;
} {
  const target = finding.remediation?.target || finding.resourceId || 'excessive-permission';
  const action = finding.remediation?.action || 'remove_permission';

  if (target.includes('s3:') || finding.id === 'finding_001') {
    return {
      dryRunDiff: [
        `--- a/aws/iam/roles/PayrollExporter/policy.json`,
        `+++ b/aws/iam/roles/PayrollExporter/policy.json`,
        `@@ -3,8 +3,7 @@`,
        `   "Statement": [{`,
        `     "Effect": "Allow",`,
        `-    "Action": ["s3:GetObject", "s3:ListBucket", "snowflake:read"],`,
        `-    "Resource": "*"`,
        `+    "Action": ["s3:ListBucket"],`,
        `+    "Resource": "arn:aws:s3:::payroll-summary-view/*"`,
        `   }]`,
      ].join('\n'),
      rollbackSnapshot: JSON.stringify({
        provider: 'aws',
        role: 'PayrollExporter',
        previousActions: ['s3:GetObject', 's3:ListBucket', 'snowflake:read'],
        previousResource: '*',
      }),
    };
  }

  return {
    dryRunDiff: [
      `--- a/iam/${finding.identityId || 'agent-identity'}/grants.json`,
      `+++ b/iam/${finding.identityId || 'agent-identity'}/grants.json`,
      `@@ -1,5 +1,4 @@`,
      `   "action": "${action}",`,
      `-  "granted": "${target}",`,
      `+  "granted": "least-privilege-scoped-read",`,
      `   "approval_required": true`,
    ].join('\n'),
    rollbackSnapshot: JSON.stringify({
      findingId: finding.id,
      previousTarget: target,
      restorableEdgeId: finding.remediation?.targetEdgeId ?? null,
    }),
  };
}

export function formatTicketDescription(
  finding: Finding,
  provider: 'jira' | 'servicenow'
): string {
  const pathLines =
    finding.exposurePath && finding.exposurePath.length > 0
      ? finding.exposurePath.map((hop, idx) => (idx === 0 ? hop : `→ ${hop}`)).join('\n')
      : `${finding.agentName}\n→ ${finding.identityId || 'service-principal'}\n→ ${finding.resourceId || 'sensitive-store'}`;

  const steps = finding.remediationSteps
    .map((s, idx) => `${idx + 1}. ${s}`)
    .join('\n');

  const evidenceLines = (finding.evidence ?? [])
    .map((ev) => `- ${ev.source} (${ev.type}) · ${ev.hash.slice(0, 18)}...`)
    .join('\n');

  const slaHours = finding.slaRemainingDays * 24;

  return [
    `Title:`,
    `[${finding.severity.toUpperCase()}] ${finding.title}`,
    ``,
    `Provider: ${provider === 'jira' ? 'Atlassian Jira (SEC)' : 'ServiceNow ITSM (INC)'}`,
    `Rule ID: ${finding.ruleId ?? 'RULE_SENSITIVE_DATA_REACH'}`,
    ``,
    `Description:`,
    finding.description,
    ``,
    `Exposure path:`,
    pathLines,
    ``,
    `Business impact:`,
    finding.businessImpact,
    ``,
    `Recommended remediation:`,
    steps,
    ``,
    `Evidence:`,
    evidenceLines || '- Graph exposure path snapshot\n- Detection rule ID',
    ``,
    `SLA:`,
    `Due in ${slaHours} hours (${finding.slaDueAt ?? `${finding.slaDays}d SLA`}).`,
  ].join('\n');
}

/**
 * Verifies against the live tenant-isolated security graph whether the exposure path
 * backing a finding has genuinely been eliminated after connector re-sync.
 */
export function verifyFindingExposureRemoved(
  finding: Finding,
  tenantNodes: GraphNode[],
  tenantEdges: GraphEdge[],
  tenantId: string
): {
  verifiedClosed: boolean;
  remainingPathCount: number;
  proofHash?: string;
  message: string;
} {
  const paths = findSensitiveExposurePaths(
    tenantNodes,
    tenantEdges,
    tenantId,
    finding.agentId
  );

  // If finding specifies a concrete target resource (e.g., s3://payroll-prod or employee_pii),
  // check whether any path from the agent still reaches that target OR sensitive data via the risky edge.
  const targetResource = (finding.resourceId || '').toLowerCase();
  const matchingPaths = paths.filter((p) => {
    if (!targetResource) return true;
    return p.steps.some(
      (s) =>
        s.label.toLowerCase().includes(targetResource) ||
        s.nodeId.toLowerCase().includes(targetResource)
    );
  });

  if (matchingPaths.length > 0) {
    return {
      verifiedClosed: false,
      remainingPathCount: matchingPaths.length,
      message: `Cannot close finding: ${matchingPaths.length} active exposure path(s) still reach ${finding.resourceId || 'sensitive data'} in the security graph.`,
    };
  }

  const proofHash = computeEvidenceHash({
    findingId: finding.id,
    tenantId,
    agentId: finding.agentId,
    resourceId: finding.resourceId ?? null,
    checkedAt: new Date().toISOString(),
    remainingPathCount: 0,
  });

  return {
    verifiedClosed: true,
    remainingPathCount: 0,
    proofHash,
    message: `Re-sync confirmed 0 exposure paths remain from ${finding.agentName} to ${finding.resourceId || 'sensitive data'}.`,
  };
}

/**
 * Evaluates normalized discovery graph entities to surface evidence-backed findings
 * idempotently without creating duplicate findings on repeated syncs.
 */
export function evaluateFindingsFromDiscovery(params: {
  tenantId: string;
  provider: string;
  agents: Agent[];
  nodes: GraphNode[];
  edges: GraphEdge[];
  existingFindings: Finding[];
  evidenceArtifacts: FindingEvidenceArtifact[];
}): Finding[] {
  const { tenantId, provider, nodes, edges, existingFindings, evidenceArtifacts } = params;
  const newlyDetected: Finding[] = [];
  const paths = findSensitiveExposurePaths(nodes, edges, tenantId);

  for (const path of paths) {
    const ruleId = 'RULE_SENSITIVE_DATA_REACH';
    const resourceId = path.targetDataLabel;
    const alreadyExists =
      existingFindings.some(
        (f) =>
          f.tenantId === tenantId &&
          f.agentId === path.agentId &&
          (f.resourceId === resourceId ||
            (f.exposurePath ?? []).includes(resourceId))
      ) ||
      newlyDetected.some(
        (f) => f.agentId === path.agentId && f.resourceId === resourceId
      );

    if (alreadyExists) continue;

    const severity: RiskLevel =
      path.riskLevel === 'critical' || path.targetSensitivity === 'pii'
        ? 'critical'
        : 'high';
    const dueIso = new Date(Date.now() + 1000 * 60 * 60 * 48).toISOString();

    newlyDetected.push({
      id: `finding_${provider}_${crypto.randomUUID().slice(0, 8)}`,
      tenantId,
      ruleId,
      category: 'excessive_agent_permission',
      riskScore: severity === 'critical' ? 91 : 79,
      agentId: path.agentId,
      agentName: path.agentLabel,
      identityId: path.steps[1]?.label ?? 'discovered-identity',
      resourceId,
      dataClassification: path.targetSensitivity,
      title: `${path.agentLabel} can reach ${resourceId}`,
      description: `Discovery sync from ${provider} detected a ${path.hopCount}-hop access path from ${path.agentLabel} to sensitive target ${resourceId}.`,
      businessImpact: `Potential unauthorized access to ${path.targetSensitivity.toUpperCase()} data asset (${resourceId}).`,
      remediationSteps: [
        `Inspect discovered identity ${path.steps[1]?.label ?? 'principal'} and attached role grants.`,
        `Remove excessive read/export permission along path to ${resourceId}.`,
        `Re-run ${provider} discovery sync to verify path removal before closing.`,
      ],
      severity,
      owner: 'Cloud Security',
      ownerEmail: 'cloudsec@northwind.com',
      slaDays: 2,
      slaRemainingDays: 2,
      slaDueAt: dueIso,
      status: 'open',
      createdAt: new Date().toISOString().slice(0, 10),
      frameworks: ['SOC 2 CC6.1', 'ISO 27001 A.5.15'],
      exposurePath: path.steps.map((s) => s.label),
      evidence: evidenceArtifacts.slice(0, 3),
      remediation: {
        action: 'remove_permission',
        target: path.steps[2]?.label ?? resourceId,
        targetEdgeId: edges.find(
          (e) =>
            e.tenantId === tenantId &&
            e.sourceId === path.steps[0]?.nodeId &&
            e.targetId === path.steps[1]?.nodeId
        )?.id,
        dryRunAvailable: true,
        rollbackAvailable: true,
        approvalRequired: true,
        dryRunExecuted: false,
        approvalStatus: 'pending_approval',
      },
      verification: {
        status: 'unverified',
      },
    });
  }

  return newlyDetected;
}
