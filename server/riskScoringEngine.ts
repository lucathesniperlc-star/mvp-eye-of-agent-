import type {
  Agent,
  ExposurePathRiskSummary,
  Finding,
  NistAiRmfStatus,
  RiskFactorAssessment,
  RiskFactorContribution,
  RiskFactorInputs,
  RiskLevel,
} from '../src/types/security.ts';
import type { ExposureTraversalResult } from './types.ts';

export const RISK_FACTOR_WEIGHTS: Record<keyof RiskFactorInputs, number> = {
  dataSensitivity: 0.3,
  identityPrivilege: 0.25,
  exposureBreadth: 0.15,
  agentAutonomy: 0.15,
  governanceGap: 0.1,
  activity: 0.05,
};

export function clampFactorScore(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(100, Math.round(value * 10) / 10));
}

export function mapScoreToRiskLevel(score: number): {
  level: RiskLevel;
  actionRequired: string;
  recommendedSlaDays: number;
} {
  if (score >= 90) {
    return {
      level: 'critical',
      actionRequired: 'Immediate remediation',
      recommendedSlaDays: 3,
    };
  }
  if (score >= 70) {
    return {
      level: 'high',
      actionRequired: 'Remediate within 7 days',
      recommendedSlaDays: 7,
    };
  }
  if (score >= 40) {
    return {
      level: 'medium',
      actionRequired: 'Remediate within 30 days',
      recommendedSlaDays: 30,
    };
  }
  if (score >= 1) {
    return {
      level: 'low',
      actionRequired: 'Monitor',
      recommendedSlaDays: 90,
    };
  }
  return {
    level: 'informational',
    actionRequired: 'No action',
    recommendedSlaDays: 0,
  };
}

export function computeWeightedRiskScore(
  rawInputs: RiskFactorInputs,
  signalSummaries?: Partial<Record<keyof RiskFactorInputs, string>>,
  exposureSummary?: ExposurePathRiskSummary,
  nistOverride?: Partial<NistAiRmfStatus>
): RiskFactorAssessment {
  const inputs: RiskFactorInputs = {
    dataSensitivity: clampFactorScore(rawInputs.dataSensitivity),
    identityPrivilege: clampFactorScore(rawInputs.identityPrivilege),
    exposureBreadth: clampFactorScore(rawInputs.exposureBreadth),
    agentAutonomy: clampFactorScore(rawInputs.agentAutonomy),
    governanceGap: clampFactorScore(rawInputs.governanceGap),
    activity: clampFactorScore(rawInputs.activity),
  };

  const labels: Record<keyof RiskFactorInputs, string> = {
    dataSensitivity: 'Data sensitivity',
    identityPrivilege: 'Identity privilege',
    exposureBreadth: 'Exposure breadth',
    agentAutonomy: 'Agent autonomy',
    governanceGap: 'Governance gap',
    activity: 'Activity',
  };

  const defaultSummaries: Record<keyof RiskFactorInputs, string> = {
    dataSensitivity: 'PII / financial / restricted data reachability',
    identityPrivilege: 'IAM role and non-human service account scope',
    exposureBreadth: 'Cross-account, internet-facing, or external tool reach',
    agentAutonomy: 'Tool execution, write actions, or export autonomy',
    governanceGap: 'Ownership assignment, policy coverage, and audit trail',
    activity: 'Recent invocation volume and anomalous behavioral signals',
  };

  const keys: Array<keyof RiskFactorInputs> = [
    'dataSensitivity',
    'identityPrivilege',
    'exposureBreadth',
    'agentAutonomy',
    'governanceGap',
    'activity',
  ];

  const factors: RiskFactorContribution[] = keys.map((key) => {
    const normalizedScore = inputs[key];
    const weight = RISK_FACTOR_WEIGHTS[key];
    const weightedPoints = Math.round(normalizedScore * weight * 100) / 100;
    return {
      key,
      label: labels[key],
      signalSummary: signalSummaries?.[key] ?? defaultSummaries[key],
      normalizedScore,
      weight,
      weightedPoints,
    };
  });

  const rawTotal = factors.reduce((sum, f) => sum + f.weightedPoints, 0);
  const totalScore = Math.round(rawTotal * 10) / 10;
  const mapping = mapScoreToRiskLevel(totalScore);

  const nistAiRmf: NistAiRmfStatus = {
    govern:
      nistOverride?.govern ??
      (inputs.governanceGap >= 70
        ? 'Ownership or policy gap flagged for governance review'
        : 'Accountable owner & policy baseline verified'),
    map:
      nistOverride?.map ??
      (exposureSummary
        ? `Mapped ${exposureSummary.agent} -> ${exposureSummary.identity} -> ${exposureSummary.sensitiveResource}`
        : 'AI system, identity, MCP server, and data dependencies mapped'),
    measure:
      nistOverride?.measure ??
      `Weighted score ${totalScore} (${mapping.level.toUpperCase()}) across 6 NIST risk factors`,
    manage: nistOverride?.manage ?? mapping.actionRequired,
  };

  return {
    inputs,
    factors,
    totalScore,
    level: mapping.level,
    actionRequired: mapping.actionRequired,
    recommendedSlaDays: mapping.recommendedSlaDays,
    nistAiRmf,
    exposureSummary,
    calculatedAt: new Date().toISOString(),
  };
}

export function deriveAgentRiskAssessment(params: {
  agent: Agent;
  paths: ExposureTraversalResult[];
  openFindings: Finding[];
  overrides?: Partial<RiskFactorInputs>;
}): RiskFactorAssessment {
  const { agent, paths, openFindings, overrides } = params;

  // 1. Data sensitivity (0-100)
  const hasPiiOrPayroll =
    paths.some((p) => ['pii', 'phi', 'pci'].includes(p.targetSensitivity)) ||
    agent.dataSources.some((ds) => ds.includes('payroll') || ds.includes('snowflake') || ds.includes('sharepoint'));
  const hasConfidential =
    paths.some((p) => p.targetSensitivity === 'confidential' || p.targetSensitivity === 'restricted') ||
    agent.dataSources.some((ds) => ds.includes('crm') || ds.includes('github'));
  const derivedDataSensitivity =
    paths.length === 0 && agent.dataSources.length === 0
      ? 10
      : hasPiiOrPayroll
        ? 100
        : hasConfidential
          ? 70
          : 35;

  // 2. Identity privilege (0-100)
  const permsText = agent.permissions.join(' ').toLowerCase();
  const hasCriticalPriv =
    permsText.includes('readwrite.all') ||
    permsText.includes('payrollexport') ||
    permsText.includes('getobject') ||
    permsText.includes('admin') ||
    permsText.includes('*');
  const hasModeratePriv =
    permsText.includes('write') ||
    permsText.includes('analytics.read') ||
    permsText.includes('secrets:metadata') ||
    permsText.includes('eu_ledger.read');
  const derivedIdentityPrivilege =
    agent.permissions.length === 0
      ? 10
      : hasCriticalPriv
        ? 92
        : hasModeratePriv
          ? 75
          : 35;

  // 3. Exposure breadth (0-100)
  const isExternalOrUnrestricted =
    agent.type === 'Customer-facing' ||
    permsText.includes('outbound_unrestricted') ||
    agent.tools.includes('url_fetch');
  const isShadow = agent.type === 'Shadow AI';
  const derivedExposureBreadth = isExternalOrUnrestricted
    ? 85
    : isShadow
      ? 75
      : paths.length > 0
        ? 45
        : 20;

  // 4. Agent autonomy (0-100)
  const highAutonomyTools = ['export_payroll', 'send_email', 'file_upload', 'url_fetch', 'extract_contracts'];
  const hasHighAutonomy = agent.tools.some((t) => highAutonomyTools.includes(t));
  const derivedAgentAutonomy =
    agent.tools.length === 0 ? 10 : hasHighAutonomy ? 95 : agent.tools.length >= 2 ? 65 : 40;

  // 5. Governance gap (0-100)
  const isUnowned = !agent.owner || agent.owner === 'unassigned' || agent.type === 'Unowned';
  const derivedGovernanceGap = isUnowned
    ? 100
    : agent.type === 'Shadow AI'
      ? 85
      : openFindings.length > 0
        ? 40
        : 10;

  // 6. Activity (0-100)
  const derivedActivity =
    agent.dailyCalls >= 10000
      ? 95
      : agent.dailyCalls >= 4000
        ? 80
        : agent.dailyCalls >= 1500
          ? 65
          : agent.dailyCalls >= 500
            ? 40
            : agent.dailyCalls > 0
              ? 20
              : 0;

  const inputs: RiskFactorInputs = {
    dataSensitivity: overrides?.dataSensitivity ?? derivedDataSensitivity,
    identityPrivilege: overrides?.identityPrivilege ?? derivedIdentityPrivilege,
    exposureBreadth: overrides?.exposureBreadth ?? derivedExposureBreadth,
    agentAutonomy: overrides?.agentAutonomy ?? derivedAgentAutonomy,
    governanceGap: overrides?.governanceGap ?? derivedGovernanceGap,
    activity: overrides?.activity ?? derivedActivity,
  };

  const topPath = paths[0];
  const primaryFinding = openFindings[0];

  const exposureSummary: ExposurePathRiskSummary = {
    agent: agent.name,
    identity: topPath?.steps[1]?.label ?? agent.identity,
    enablingPermission:
      topPath?.steps.find((s) => s.nodeType === 'Permission')?.label ??
      agent.permissions[0] ??
      'Least-privilege scoped read',
    sensitiveResource:
      topPath?.targetDataLabel ?? agent.dataSources[0] ?? 'No sensitive data reachable',
    blastRadius: topPath
      ? `${paths.length} active graph path(s) across ${agent.businessService} reaching ${topPath.targetSensitivity.toUpperCase()} asset (${topPath.targetDataLabel})`
      : `Contained within ${agent.businessService} (0 active sensitive graph paths)`,
    shortestRemediation:
      primaryFinding?.remediationSteps[0] ??
      (isUnowned
        ? `Assign accountable owner to ${agent.name} and rotate ${agent.identity}`
        : `Scope ${agent.permissions[0] ?? 'service role'} to least-privilege read-only prefix`),
  };

  return computeWeightedRiskScore(
    inputs,
    {
      dataSensitivity: topPath
        ? `${topPath.targetSensitivity.toUpperCase()} target: ${topPath.targetDataLabel}`
        : `Data stores: ${agent.dataSources.join(', ') || 'None'}`,
      identityPrivilege: `${agent.identity} (${agent.permissions.slice(0, 2).join(', ') || 'scoped'})`,
      exposureBreadth: `${agent.type} · ${agent.mcpServers.join(', ') || 'direct runtime'}`,
      agentAutonomy: `Tools: ${agent.tools.join(', ') || 'none'}`,
      governanceGap: isUnowned
        ? 'No registered owner or policy attestation'
        : `Owner: ${agent.owner} · ${openFindings.length} open finding(s)`,
      activity: `${agent.dailyCalls.toLocaleString()} calls/day (last seen ${agent.lastSeen})`,
    },
    exposureSummary
  );
}
