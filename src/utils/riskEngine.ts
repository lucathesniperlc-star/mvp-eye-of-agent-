import type {
  Agent,
  AgentType,
  ControlItem,
  DataSource,
  Finding,
  McpServer,
  PolicyAction,
  PolicyMode,
  PolicyRule,
  PolicySimulationEvent,
  RiskLevel,
  Tenant,
} from '../types/security';

export interface AgentFilterCriteria {
  query: string;
  risk: RiskLevel | 'all';
  type: AgentType | 'all';
  onlyUnowned?: boolean;
}

export interface ExposurePathNode {
  id: string;
  stage: 'agent' | 'identity' | 'mcp' | 'data' | 'egress';
  label: string;
  sublabel: string;
  risk: RiskLevel;
}

export interface ExposurePathChain {
  agentId: string;
  agentName: string;
  riskScore: number;
  riskLevel: RiskLevel;
  nodes: ExposurePathNode[];
  externalDestination?: ExposurePathNode;
  permissions: string[];
  tools: string[];
}

export interface DashboardMetrics {
  overallRiskScore: number;
  riskTrendDelta: number;
  criticalFindingsCount: number;
  openFindingsCount: number;
  totalAgents: number;
  activeAgents: number;
  unownedAgents: number;
  shadowAgents: number;
  reachableSensitiveSources: number;
  overPrivilegedIdentities: number;
  unusedCredentials: number;
  riskyServiceAccounts: number;
  complianceCoveragePct: number;
  dailyRequests: number;
  dailyToolCalls: number;
  blockedOrRedactedEvents: number;
}

export function filterAgents(agents: Agent[], tenantId: string, criteria: AgentFilterCriteria): Agent[] {
  const q = criteria.query.trim().toLowerCase();
  return agents.filter((agent) => {
    if (agent.tenantId !== tenantId) return false;
    if (criteria.risk !== 'all' && agent.riskLevel !== criteria.risk) return false;
    if (criteria.type !== 'all' && agent.type !== criteria.type) return false;
    if (criteria.onlyUnowned && agent.owner !== 'unassigned' && agent.type !== 'Unowned') return false;
    if (!q) return true;
    const searchable = [
      agent.name,
      agent.owner,
      agent.ownerTeam,
      agent.identity,
      agent.businessService,
      ...agent.tools,
      ...agent.models,
      ...agent.dataSources,
    ]
      .join(' ')
      .toLowerCase();
    return searchable.includes(q);
  });
}

export function computeComplianceCoverage(controls: ControlItem[]): {
  coveredCount: number;
  partialCount: number;
  gapCount: number;
  coveragePct: number;
} {
  if (controls.length === 0) {
    return { coveredCount: 0, partialCount: 0, gapCount: 0, coveragePct: 0 };
  }
  const coveredCount = controls.filter((c) => c.status === 'covered').length;
  const partialCount = controls.filter((c) => c.status === 'partial').length;
  const gapCount = controls.filter((c) => c.status === 'gap').length;
  const weighted = coveredCount + partialCount * 0.5;
  const coveragePct = Math.round((weighted / controls.length) * 100);
  return { coveredCount, partialCount, gapCount, coveragePct };
}

export function computeDashboardMetrics(
  tenant: Tenant,
  agents: Agent[],
  findings: Finding[],
  dataSources: DataSource[],
  controls: ControlItem[]
): DashboardMetrics {
  const tenantAgents = agents.filter((a) => a.tenantId === tenant.id);
  const tenantFindings = findings.filter((f) => f.tenantId === tenant.id);
  const openFindings = tenantFindings.filter((f) => f.status !== 'remediated');
  const criticalOpen = openFindings.filter((f) => f.severity === 'critical').length;

  const reachableDataIds = new Set<string>();
  for (const agent of tenantAgents) {
    for (const ds of agent.dataSources) {
      reachableDataIds.add(ds);
    }
  }
  const reachableSensitiveSources = dataSources.filter(
    (ds) => reachableDataIds.has(ds.id) && (ds.classification === 'Restricted' || ds.classification === 'Confidential')
  ).length;

  const { coveragePct } = computeComplianceCoverage(controls);

  return {
    overallRiskScore: tenant.overallRiskScore,
    riskTrendDelta: tenant.riskTrendDelta,
    criticalFindingsCount: criticalOpen,
    openFindingsCount: openFindings.length,
    totalAgents: tenant.totalDiscoveredAgents,
    activeAgents: tenant.activeAgents,
    unownedAgents: tenant.unownedAgents,
    shadowAgents: tenant.shadowAgents,
    reachableSensitiveSources,
    overPrivilegedIdentities: tenant.overPrivilegedIdentities,
    unusedCredentials: tenant.unusedCredentials,
    riskyServiceAccounts: tenant.riskyServiceAccounts,
    complianceCoveragePct: coveragePct,
    dailyRequests: tenant.dailyRequests,
    dailyToolCalls: tenant.dailyToolCalls,
    blockedOrRedactedEvents: tenant.blockedOrRedactedEvents,
  };
}

export function buildExposurePathForAgent(
  agent: Agent,
  mcpServers: McpServer[],
  dataSources: DataSource[]
): ExposurePathChain {
  const primaryMcp = mcpServers.find((m) => agent.mcpServers.includes(m.id));
  const primaryData =
    dataSources.find((d) => agent.dataSources.includes(d.id) && d.risk === 'critical') ||
    dataSources.find((d) => agent.dataSources.includes(d.id));

  const nodes: ExposurePathNode[] = [
    {
      id: `node-agent-${agent.id}`,
      stage: 'agent',
      label: agent.name,
      sublabel: `${agent.type} · ${agent.ownerTeam}`,
      risk: agent.riskLevel,
    },
    {
      id: `node-identity-${agent.identity}`,
      stage: 'identity',
      label: agent.identity,
      sublabel: agent.identityType,
      risk: agent.riskScore >= 85 ? 'critical' : agent.riskLevel,
    },
    {
      id: `node-mcp-${primaryMcp?.id ?? 'direct'}`,
      stage: 'mcp',
      label: primaryMcp ? primaryMcp.name : 'Direct Tool Runtime',
      sublabel: `${agent.tools.slice(0, 2).join(', ')}`,
      risk: primaryMcp?.risk ?? agent.riskLevel,
    },
    {
      id: `node-data-${primaryData?.id ?? 'unknown'}`,
      stage: 'data',
      label: primaryData ? primaryData.name : 'Internal Store',
      sublabel: primaryData ? `${primaryData.provider} · ${primaryData.sensitivity}` : 'Restricted',
      risk: primaryData?.risk ?? agent.riskLevel,
    },
  ];

  return {
    agentId: agent.id,
    agentName: agent.name,
    riskScore: agent.riskScore,
    riskLevel: agent.riskLevel,
    nodes,
    permissions: agent.permissions,
    tools: agent.tools,
  };
}

export function createJiraTicketForFinding(
  findings: Finding[],
  findingId: string,
  ticketKey: string,
  assigneeOwner: string = 'Cloud Security'
): Finding[] {
  return findings.map((f) =>
    f.id === findingId
      ? {
          ...f,
          status: f.status === 'open' ? 'in_progress' : f.status,
          owner: assigneeOwner,
          jiraTicketKey: ticketKey,
        }
      : f
  );
}

export function summarizePolicySimulation(
  mode: PolicyMode,
  rules: PolicyRule[],
  events: PolicySimulationEvent[]
): {
  modeLabel: string;
  wouldBlockCount: number;
  wouldRedactCount: number;
  allowedCount: number;
  activeRuleCount: number;
} {
  const activeRuleCount = rules.filter((r) => r.enabled).length;
  const counts: Record<PolicyAction, number> = { block: 0, redact: 0, allow: 0 };
  for (const ev of events) {
    counts[ev.wouldAction] += 1;
  }
  return {
    modeLabel: mode === 'observe' ? 'Observe-Only (Audit)' : 'Enforce (Active Guardrail)',
    wouldBlockCount: counts.block,
    wouldRedactCount: counts.redact,
    allowedCount: counts.allow,
    activeRuleCount,
  };
}
