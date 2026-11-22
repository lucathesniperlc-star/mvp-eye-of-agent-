import { useCallback, useEffect, useState } from 'react';
import { AgentDetail } from './components/AgentDetail';
import { AgentInventory } from './components/AgentInventory';
import { AllInOneView } from './components/AllInOneView';
import { AuditLogView } from './components/AuditLogView';
import { AuthGateModal } from './components/AuthGateModal';
import { ComplianceView } from './components/ComplianceView';
import { ConnectorsView, type CloudOnboardProvider } from './components/ConnectorsView';
import { DashboardShell } from './components/DashboardShell';
import { EnterpriseView } from './components/EnterpriseView';
import { ExposurePaths } from './components/ExposurePaths';
import { FindingsView } from './components/FindingsView';
import { DEMO_TOUR_STEPS, GuidedTourOverlay } from './components/GuidedTourOverlay';
import { LandingPage } from './components/LandingPage';
import { PolicyView } from './components/PolicyView';
import { RiskCommandCenter } from './components/RiskCommandCenter';
import {
  CONTROLS,
  DATA_SOURCES,
  EVIDENCE_ITEMS,
  INITIAL_ACTIVITY,
  INITIAL_AGENTS,
  INITIAL_CONNECTORS,
  INITIAL_FINDINGS,
  INITIAL_POLICY_RULES,
  MCP_SERVERS,
  MODELS,
  POLICY_SIMULATION_EVENTS,
  RISK_TREND_SERIES,
  TENANTS,
} from './data/mockData';
import type {
  ActivityEvent,
  Agent,
  AgentStatus,
  AgentType,
  AiProviderAdapterMeta,
  AllInOneRunResult,
  AuditChainIntegrity,
  AuditEventRecord,
  AuthSessionState,
  ComplianceException,
  ComplianceFramework,
  Connector,
  ContainmentActionCatalogItem,
  ContainmentActionId,
  ControlItem,
  DataSource,
  DemoRequestRecord,
  EnforcementAction,
  EnterpriseSsoConfig,
  EvidenceItem,
  EvidenceRecord,
  Finding,
  GatewayEvent,
  GatewayPolicyDefinition,
  GatewayRuntimeConfig,
  GraphTraversalPath,
  KillSwitchState,
  McpApprovalStatus,
  McpServer,
  ModelApprovalStatus,
  ModelAsset,
  PlatformHardeningItem,
  PlaybookDefinition,
  PlaybookExecutionRecord,
  PlaybookId,
  PolicyAction,
  PolicyException,
  PolicyMode,
  PolicyRule,
  PolicySimulationEvent,
  RbacRole,
  ReleaseGateCheck,
  RetentionPolicyConfig,
  RiskFactorInputs,
  RiskTrendPoint,
  RolloutStage,
  ScimDirectoryUser,
  ScreenId,
  SecurityIncident,
  Tenant,
  VerticalPackId,
  VerticalPolicyPack,
} from './types/security';
import { computeDashboardMetrics } from './utils/riskEngine';

export interface ComplianceExportResponse {
  exported: boolean;
  packageId: string;
  exportedAt: string;
  exportDurationMs: number;
  auditorScoped: boolean;
  tenantId: string;
  tenantName: string;
  frameworkScope: ComplianceFramework | 'all';
  timeWindow: { from: string; to: string };
  hashChainIntegrity: { valid: boolean; verifiedCount: number; headHash: string };
  coverageSummary: {
    coveredCount: number;
    partialCount: number;
    gapCount: number;
    coveragePct: number;
  };
  controls: ControlItem[];
  evidenceRecords: EvidenceRecord[];
  auditEventId?: string;
}

export interface GatewayInspectResponse {
  event: GatewayEvent;
  evidenceRecord: EvidenceRecord;
  createdFinding?: Finding;
}

export interface PepEvaluateResponse {
  event: GatewayEvent;
  evidenceRecord: EvidenceRecord;
  pdpDecision: EnforcementAction;
  pdpReason: string;
  enforced: boolean;
  playbookExecution?: PlaybookExecutionRecord;
}

export interface EnterpriseStatePayload {
  rolloutStage: RolloutStage;
  killSwitch: KillSwitchState;
  playbooks: PlaybookDefinition[];
  playbookExecutions: PlaybookExecutionRecord[];
  ssoConfig: EnterpriseSsoConfig;
  scimDirectory: ScimDirectoryUser[];
  idpGroupRoleMap: Record<string, RbacRole>;
  hardeningMatrix: PlatformHardeningItem[];
  releaseGates: ReleaseGateCheck[];
  auditIntegrity: AuditChainIntegrity;
  auditRetentionDays: number;
  lastAllInOneRun?: AllInOneRunResult;
  gatewayRuntimeConfig?: GatewayRuntimeConfig;
  incidents?: SecurityIncident[];
  containmentCatalog?: ContainmentActionCatalogItem[];
  activeVerticalPacks?: VerticalPackId[];
  verticalPacksCatalog?: VerticalPolicyPack[];
  providerAdapters?: AiProviderAdapterMeta[];
}

const DEFAULT_RETENTION_STATE: RetentionPolicyConfig = {
  requestMetadataDays: 90,
  policyDecisionDays: 365,
  classificationResultDays: 365,
  rawPromptRetained: false,
  rawResponseRetained: false,
  redactedExcerptOptIn: false,
  redactedExcerptDays: 7,
  evidenceHashRetention: 'Retained per compliance policy (2 years minimum)',
};

interface WorkspacePayload {
  tenant: Tenant;
  tenants?: Tenant[];
  agents: Agent[];
  mcpServers: McpServer[];
  models: ModelAsset[];
  dataSources: DataSource[];
  findings: Finding[];
  incidents?: SecurityIncident[];
  controls: ControlItem[];
  evidence: EvidenceItem[];
  evidenceRecords?: EvidenceRecord[];
  complianceExceptions?: ComplianceException[];
  activity: ActivityEvent[];
  trendSeries: RiskTrendPoint[];
  connectors: Connector[];
  graph: { paths: GraphTraversalPath[] };
  policy: {
    mode: PolicyMode;
    rules: PolicyRule[];
    simulationEvents: PolicySimulationEvent[];
    gatewayPolicies?: GatewayPolicyDefinition[];
    gatewayEvents?: GatewayEvent[];
    retentionConfig?: RetentionPolicyConfig;
    activeVerticalPacks?: VerticalPackId[];
    verticalPacksCatalog?: VerticalPolicyPack[];
    providerAdapters?: AiProviderAdapterMeta[];
    policyExceptions?: PolicyException[];
    gatewayRuntimeConfig?: GatewayRuntimeConfig;
  };
  activeVerticalPacks?: VerticalPackId[];
  verticalPacksCatalog?: VerticalPolicyPack[];
  providerAdapters?: AiProviderAdapterMeta[];
  containmentCatalog?: ContainmentActionCatalogItem[];
  auditEvents: AuditEventRecord[];
  enterprise?: EnterpriseStatePayload;
  demoRequests?: DemoRequestRecord[];
}

export default function App() {
  const [viewMode, setViewMode] = useState<'landing' | 'dashboard'>(() => {
    if (typeof window !== 'undefined') {
      const params = new URLSearchParams(window.location.search);
      if (params.get('autostart') === '1') return 'dashboard';
    }
    return 'landing';
  });

  const [authSession, setAuthSession] = useState<AuthSessionState | null>(null);
  const [authModalOpen, setAuthModalOpen] = useState(false);

  const [selectedTenantId, setSelectedTenantId] = useState<string>(TENANTS[0].id);
  const [activeScreen, setActiveScreen] = useState<ScreenId>('overview');
  const [selectedAgentId, setSelectedAgentId] = useState<string>('agent_finance_copilot');

  const [tenants, setTenants] = useState<Tenant[]>(TENANTS);
  const [tenantRecord, setTenantRecord] = useState<Tenant>(TENANTS[0]);
  const [agents, setAgents] = useState<Agent[]>(INITIAL_AGENTS);
  const [mcpServers, setMcpServers] = useState<McpServer[]>(MCP_SERVERS);
  const [models, setModels] = useState<ModelAsset[]>(MODELS);
  const [dataSources, setDataSources] = useState<DataSource[]>(DATA_SOURCES);
  const [findings, setFindings] = useState<Finding[]>(INITIAL_FINDINGS);
  const [controls, setControls] = useState<ControlItem[]>(CONTROLS);
  const [evidenceItems, setEvidenceItems] = useState<EvidenceItem[]>(EVIDENCE_ITEMS);
  const [evidenceRecords, setEvidenceRecords] = useState<EvidenceRecord[]>([]);
  const [policyMode, setPolicyMode] = useState<PolicyMode>('observe');
  const [policyRules, setPolicyRules] = useState<PolicyRule[]>(INITIAL_POLICY_RULES);
  const [simulationEvents, setSimulationEvents] = useState<PolicySimulationEvent[]>(
    POLICY_SIMULATION_EVENTS
  );
  const [gatewayPolicies, setGatewayPolicies] = useState<GatewayPolicyDefinition[]>([]);
  const [gatewayEvents, setGatewayEvents] = useState<GatewayEvent[]>([]);
  const [retentionConfig, setRetentionConfig] = useState<RetentionPolicyConfig>(
    DEFAULT_RETENTION_STATE
  );
  const [connectors, setConnectors] = useState<Connector[]>(INITIAL_CONNECTORS);
  const [activity, setActivity] = useState<ActivityEvent[]>(INITIAL_ACTIVITY);
  const [trendSeries, setTrendSeries] = useState<RiskTrendPoint[]>(
    RISK_TREND_SERIES.tenant_northwind
  );
  const [graphPaths, setGraphPaths] = useState<GraphTraversalPath[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEventRecord[]>([]);
  const [enterpriseState, setEnterpriseState] = useState<EnterpriseStatePayload | null>(null);
  const [demoRequests, setDemoRequests] = useState<DemoRequestRecord[]>([]);
  const [incidents, setIncidents] = useState<SecurityIncident[]>([]);
  const [complianceExceptions, setComplianceExceptions] = useState<ComplianceException[]>([]);
  const [activeVerticalPacks, setActiveVerticalPacks] = useState<VerticalPackId[]>([]);
  const [verticalPacksCatalog, setVerticalPacksCatalog] = useState<VerticalPolicyPack[]>([]);
  const [providerAdapters, setProviderAdapters] = useState<AiProviderAdapterMeta[]>([]);
  const [containmentCatalog, setContainmentCatalog] = useState<ContainmentActionCatalogItem[]>([]);
  const [policyExceptions, setPolicyExceptions] = useState<PolicyException[]>([]);
  const [gatewayRuntimeConfig, setGatewayRuntimeConfig] = useState<
    GatewayRuntimeConfig | undefined
  >(undefined);
  const [rbacNotice, setRbacNotice] = useState<string>('');

  const [tourActive, setTourActive] = useState<boolean>(false);
  const [tourStepIndex, setTourStepIndex] = useState<number>(0);

  const loadWorkspace = useCallback(async () => {
    const res = await fetch('/api/workspace');
    if (!res.ok) return false;
    const data = (await res.json()) as WorkspacePayload;
    setTenantRecord(data.tenant);
    if (data.tenants?.length) setTenants(data.tenants);
    setSelectedTenantId(data.tenant.id);
    setAgents(data.agents);
    if (data.mcpServers?.length) setMcpServers(data.mcpServers);
    if (data.models?.length) setModels(data.models);
    if (data.dataSources?.length) setDataSources(data.dataSources);
    setFindings(data.findings);
    setIncidents(data.incidents ?? data.enterprise?.incidents ?? []);
    if (data.controls?.length) setControls(data.controls);
    if (data.evidence?.length) setEvidenceItems(data.evidence);
    setEvidenceRecords(data.evidenceRecords ?? []);
    setComplianceExceptions(data.complianceExceptions ?? []);
    setConnectors(data.connectors);
    setActivity(data.activity);
    setTrendSeries(data.trendSeries);
    setGraphPaths(data.graph?.paths ?? []);
    setPolicyMode(data.policy.mode);
    setPolicyRules(data.policy.rules);
    setSimulationEvents(data.policy.simulationEvents);
    setGatewayPolicies(data.policy.gatewayPolicies ?? []);
    setGatewayEvents(data.policy.gatewayEvents ?? []);
    if (data.policy.retentionConfig) {
      setRetentionConfig(data.policy.retentionConfig);
    }
    setActiveVerticalPacks(
      data.activeVerticalPacks ??
        data.policy.activeVerticalPacks ??
        data.enterprise?.activeVerticalPacks ??
        []
    );
    setVerticalPacksCatalog(
      data.verticalPacksCatalog ??
        data.policy.verticalPacksCatalog ??
        data.enterprise?.verticalPacksCatalog ??
        []
    );
    setProviderAdapters(
      data.providerAdapters ??
        data.policy.providerAdapters ??
        data.enterprise?.providerAdapters ??
        []
    );
    setContainmentCatalog(data.containmentCatalog ?? data.enterprise?.containmentCatalog ?? []);
    setPolicyExceptions(data.policy.policyExceptions ?? []);
    setGatewayRuntimeConfig(
      data.policy.gatewayRuntimeConfig ?? data.enterprise?.gatewayRuntimeConfig
    );
    setAuditEvents(data.auditEvents ?? []);
    if (data.enterprise) {
      setEnterpriseState(data.enterprise);
    }
    setDemoRequests(data.demoRequests ?? []);
    if (data.agents.length > 0 && !data.agents.some((a) => a.id === selectedAgentId)) {
      setSelectedAgentId(data.agents[0].id);
    }
    return true;
  }, [selectedAgentId]);

  const ensureAuthenticatedSession = useCallback(async () => {
    const meRes = await fetch('/api/auth/session');
    if (meRes.ok) {
      const me = (await meRes.json()) as { authenticated: boolean } & Partial<AuthSessionState>;
      if (me.authenticated && me.user) {
        setAuthSession(me as AuthSessionState);
        await loadWorkspace();
        return;
      }
    }
    // Establish initial sandbox Owner session via SSO/MFA endpoint for interactive demo
    const loginRes = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'ciso@northwind.com', totpCode: '123456' }),
    });
    if (loginRes.ok) {
      const sess = (await loginRes.json()) as AuthSessionState;
      setAuthSession(sess);
      await loadWorkspace();
    }
  }, [loadWorkspace]);

  useEffect(() => {
    if (viewMode === 'dashboard') {
      ensureAuthenticatedSession();
    }
  }, [viewMode, ensureAuthenticatedSession]);

  const selectedAgent =
    agents.find((a) => a.id === selectedAgentId) ?? agents[0] ?? INITIAL_AGENTS[0];

  const metrics = computeDashboardMetrics(
    tenantRecord,
    agents,
    findings,
    dataSources,
    controls
  );

  const openFindingsCount = findings.filter(
    (f) => f.tenantId === tenantRecord.id && f.status !== 'remediated'
  ).length;

  const applyTourStep = (index: number) => {
    const clamped = Math.max(0, Math.min(DEMO_TOUR_STEPS.length - 1, index));
    const step = DEMO_TOUR_STEPS[clamped];
    setTourStepIndex(clamped);
    setActiveScreen(step.screen);
    if (step.agentId) {
      setSelectedAgentId(step.agentId);
    }
  };

  const handleLaunchDemo = (startTour = false) => {
    setViewMode('dashboard');
    if (startTour) {
      setTourActive(true);
      applyTourStep(0);
    } else {
      setActiveScreen('overview');
    }
    window.scrollTo({ top: 0, behavior: 'auto' });
  };

  const handleSelectTenant = async (tenantId: string) => {
    setRbacNotice('');
    const res = await fetch('/api/auth/switch-tenant', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tenantId }),
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Tenant switch denied');
      return;
    }
    const updated = await res.json();
    setAuthSession((prev) =>
      prev
        ? {
            ...prev,
            activeTenantId: updated.activeTenantId,
            role: updated.role,
            permissions: updated.permissions,
          }
        : prev
    );
    await loadWorkspace();
    setActiveScreen('overview');
  };

  const handleAuthenticated = async (session: AuthSessionState) => {
    setRbacNotice('');
    setAuthSession(session);
    await loadWorkspace();
    setActiveScreen('overview');
  };

  const handleCreateRemediationTicket = async (
    findingId: string,
    payload: { provider: 'jira' | 'servicenow'; assignee: string; notifyChannels: string[] }
  ) => {
    setRbacNotice('');
    const res = await fetch(`/api/findings/${findingId}/ticket`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Permission denied');
      return;
    }
    await loadWorkspace();
  };

  const handleRunDryRun = async (findingId: string) => {
    setRbacNotice('');
    const res = await fetch(`/api/findings/${findingId}/dry-run`, { method: 'POST' });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Permission denied');
      return;
    }
    await loadWorkspace();
  };

  const handleApproveRemediation = async (
    findingId: string,
    breakGlassDualApproval: boolean
  ) => {
    setRbacNotice('');
    const res = await fetch(`/api/findings/${findingId}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ breakGlassDualApproval }),
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Permission denied');
      return;
    }
    await loadWorkspace();
  };

  const handleApplyRemediation = async (findingId: string) => {
    setRbacNotice('');
    const res = await fetch(`/api/findings/${findingId}/apply-remediation`, {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Unable to apply remediation');
      return;
    }
    await loadWorkspace();
  };

  const handleRollbackRemediation = async (findingId: string) => {
    setRbacNotice('');
    const res = await fetch(`/api/findings/${findingId}/rollback`, { method: 'POST' });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Rollback failed');
      return;
    }
    await loadWorkspace();
  };

  const handleVerifyAndCloseFinding = async (
    findingId: string
  ): Promise<{ closed: boolean; message?: string }> => {
    setRbacNotice('');
    const res = await fetch(`/api/findings/${findingId}/verify-closure`, {
      method: 'POST',
    });
    const data = await res.json();
    if (res.status === 403) {
      setRbacNotice(data.error || 'Permission denied');
      return { closed: false, message: data.error };
    }
    await loadWorkspace();
    if (!res.ok) {
      return { closed: false, message: data.error };
    }
    return { closed: Boolean(data.closed), message: data.finding?.verification?.message };
  };

  const handleChangePolicyMode = async (mode: PolicyMode) => {
    setRbacNotice('');
    const res = await fetch('/api/policy/mode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode }),
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Permission denied');
      return;
    }
    await loadWorkspace();
  };

  const handleToggleRule = async (ruleId: string) => {
    setRbacNotice('');
    const res = await fetch(`/api/policy/rules/${ruleId}/toggle`, {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Permission denied');
      return;
    }
    await loadWorkspace();
  };

  const handleRunConnectorSync = async (connectorId: string) => {
    setRbacNotice('');
    const res = await fetch(`/api/connectors/${connectorId}/sync`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Connector sync failed');
    }
    await loadWorkspace();
  };

  const handleRunAllSyncs = async () => {
    for (const c of connectors) {
      if (c.lastSync !== 'Disconnected') {
        await fetch(`/api/connectors/${c.id}/sync`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({}),
        });
      }
    }
    await loadWorkspace();
  };

  const handlePkceAuthorize = async (connectorId: string) => {
    const startRes = await fetch(`/api/connectors/${connectorId}/oauth/start`, {
      method: 'POST',
    });
    if (!startRes.ok) {
      const err = await startRes.json();
      throw new Error(err.error || 'PKCE start failed');
    }
    const { authSessionId, codeVerifier } = await startRes.json();
    const cbRes = await fetch(`/api/connectors/${connectorId}/oauth/callback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ authSessionId, codeVerifier }),
    });
    if (!cbRes.ok) {
      const err = await cbRes.json();
      throw new Error(err.error || 'PKCE callback failed');
    }
    await loadWorkspace();
    return `OAuth 2.0 PKCE verified & AES-256-GCM credential stored for ${connectorId}.`;
  };

  const handleRotateToken = async (connectorId: string) => {
    const res = await fetch(`/api/connectors/${connectorId}/rotate-token`, {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Token rotation failed');
    }
    const data = await res.json();
    await loadWorkspace();
    return `Rotated credential to version ${data.tokenVersion} (${data.keyId}).`;
  };

  const handleDisconnectConnector = async (connectorId: string) => {
    const res = await fetch(`/api/connectors/${connectorId}/disconnect`, {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Disconnect failed');
    }
    await loadWorkspace();
  };

  const handleOnboardCloud = async (
    provider: CloudOnboardProvider,
    config: Record<string, string>
  ) => {
    const res = await fetch('/api/connectors/onboard', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider, config }),
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || 'Cloud connector onboarding failed');
    }
    await loadWorkspace();
    return `${data.connector.displayName} onboarded read-only (${data.nodesAdded} new nodes, ${data.edgesAdded} new edges synced).`;
  };

  const handleRefreshAudit = async () => {
    const res = await fetch('/api/audit-events');
    if (res.ok) {
      const data = await res.json();
      setAuditEvents(data.events ?? []);
    }
  };

  const handleFilterAuditEvents = async (filters: {
    search?: string;
    outcome?: 'all' | 'allowed' | 'denied';
  }) => {
    setRbacNotice('');
    const params = new URLSearchParams();
    if (filters.search?.trim()) params.set('search', filters.search.trim());
    if (filters.outcome && filters.outcome !== 'all') params.set('outcome', filters.outcome);
    const qs = params.toString();
    const res = await fetch(`/api/audit-events${qs ? `?${qs}` : ''}`);
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Audit query denied');
      return;
    }
    const data = await res.json();
    setAuditEvents(data.events ?? []);
  };

  const handleCreateAgent = async (payload: {
    name: string;
    owner?: string;
    ownerTeam?: string;
    type?: AgentType;
    identity?: string;
    businessService?: string;
    tools?: string[];
    permissions?: string[];
    dataSources?: string[];
  }): Promise<Agent | null> => {
    setRbacNotice('');
    const res = await fetch('/api/agents', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) {
      const msg = data.error || 'Unable to register agent';
      setRbacNotice(msg);
      throw new Error(msg);
    }
    await loadWorkspace();
    return (data.agent as Agent) ?? null;
  };

  const handleUpdateAgentGovernance = async (
    agentId: string,
    updates: {
      owner?: string;
      ownerTeam?: string;
      status?: AgentStatus;
      businessService?: string;
      permissions?: string[];
    }
  ): Promise<Agent | null> => {
    setRbacNotice('');
    const res = await fetch(`/api/agents/${agentId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    });
    const data = await res.json();
    if (!res.ok) {
      const msg = data.error || 'Unable to update agent governance';
      setRbacNotice(msg);
      throw new Error(msg);
    }
    await loadWorkspace();
    return (data.agent as Agent) ?? null;
  };

  const handleCreatePolicyRule = async (payload: {
    name: string;
    scope: string;
    action: PolicyAction;
    condition: string;
  }) => {
    setRbacNotice('');
    const res = await fetch('/api/policy/rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) {
      const msg = data.error || 'Unable to create policy rule';
      setRbacNotice(msg);
      throw new Error(msg);
    }
    await loadWorkspace();
  };

  const handleCreateGatewayPolicy = async (payload: {
    name: string;
    agents: string[];
    tools: string[];
    dataClassification: string[];
    decision: EnforcementAction;
  }) => {
    setRbacNotice('');
    const res = await fetch('/api/enterprise/policies', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) {
      const msg = data.error || 'Unable to create YAML gateway policy';
      setRbacNotice(msg);
      throw new Error(msg);
    }
    await loadWorkspace();
  };

  const handleAttestControl = async (
    controlId: string,
    payload: { title?: string; summary: string; source?: string }
  ): Promise<{ control: ControlItem; evidenceRecord: EvidenceRecord } | null> => {
    setRbacNotice('');
    const res = await fetch(`/api/compliance/controls/${encodeURIComponent(controlId)}/attest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) {
      const msg = data.error || 'Control attestation denied';
      setRbacNotice(msg);
      throw new Error(msg);
    }
    await loadWorkspace();
    return data as { control: ControlItem; evidenceRecord: EvidenceRecord };
  };

  const handleResetDemoState = async () => {
    setRbacNotice('');
    const res = await fetch('/api/system/reset-demo', { method: 'POST' });
    const data = await res.json();
    if (!res.ok) {
      const msg = data.error || 'Sandbox reset denied';
      setRbacNotice(msg);
      throw new Error(msg);
    }
    await loadWorkspace();
  };

  const handleRecalculateAgentRisk = async (
    agentId: string,
    payload: {
      owner?: string;
      permissions?: string[];
      dailyCalls?: number;
      overrides?: Partial<RiskFactorInputs>;
    }
  ) => {
    setRbacNotice('');
    const res = await fetch(`/api/agents/${agentId}/risk-signals`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Permission denied');
      return;
    }
    await loadWorkspace();
  };

  const handleExportAuditPack = async (opts: {
    framework: ComplianceFramework | 'all';
    fromDate?: string;
    toDate?: string;
  }): Promise<ComplianceExportResponse | null> => {
    setRbacNotice('');
    const res = await fetch('/api/compliance/export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(opts),
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Compliance export denied');
      return null;
    }
    const pkg = (await res.json()) as ComplianceExportResponse;
    await loadWorkspace();
    return pkg;
  };

  const handleInspectGateway = async (payload: {
    agentId: string;
    provider?: string;
    model?: string;
    tool: string;
    mcpServer?: string;
    promptText?: string;
    responseText?: string;
    targetResource?: string;
  }): Promise<GatewayInspectResponse | null> => {
    setRbacNotice('');
    const res = await fetch('/api/gateway/inspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Gateway inspection failed');
      return null;
    }
    const data = (await res.json()) as GatewayInspectResponse;
    await loadWorkspace();
    return data;
  };

  const handleToggleRetentionOptIn = async (redactedExcerptOptIn: boolean) => {
    setRbacNotice('');
    const res = await fetch('/api/gateway/retention', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ redactedExcerptOptIn }),
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Permission denied');
      return;
    }
    await loadWorkspace();
  };

  const handleEvaluatePep = async (payload: {
    agentId: string;
    provider?: string;
    model?: string;
    tool: string;
    mcpServer?: string;
    promptText?: string;
    responseText?: string;
    targetResource?: string;
    requestedActionOverride?: EnforcementAction;
    simulatePdpUnavailable?: boolean;
  }): Promise<PepEvaluateResponse | null> => {
    setRbacNotice('');
    const res = await fetch('/api/enterprise/pep/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'PEP/PDP evaluation failed');
      return null;
    }
    const data = (await res.json()) as PepEvaluateResponse;
    await loadWorkspace();
    return data;
  };

  const handleChangeRolloutStage = async (stage: RolloutStage) => {
    setRbacNotice('');
    const res = await fetch('/api/enterprise/rollout-stage', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ stage }),
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Permission denied');
      return;
    }
    await loadWorkspace();
  };

  const handleToggleKillSwitch = async (paused: boolean, reason?: string) => {
    setRbacNotice('');
    const res = await fetch('/api/enterprise/kill-switch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ paused, reason }),
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Permission denied');
      return;
    }
    await loadWorkspace();
  };

  const handleDryRunPlaybook = async (playbookId: PlaybookId, agentId: string) => {
    setRbacNotice('');
    const res = await fetch(`/api/enterprise/playbooks/${playbookId}/dry-run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agentId }),
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Dry-run failed');
      return;
    }
    await loadWorkspace();
  };

  const handleExecutePlaybook = async (playbookId: PlaybookId, agentId: string) => {
    setRbacNotice('');
    const res = await fetch(`/api/enterprise/playbooks/${playbookId}/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agentId }),
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Playbook execution failed');
      throw new Error(err.error || 'Playbook execution failed');
    }
    await loadWorkspace();
  };

  const handleApprovePlaybookExecution = async (executionId: string) => {
    setRbacNotice('');
    const res = await fetch(`/api/enterprise/responses/${executionId}/approve`, {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Approval failed');
      return;
    }
    await loadWorkspace();
  };

  const handleRollbackPlaybookExecution = async (executionId: string) => {
    setRbacNotice('');
    const res = await fetch(`/api/enterprise/responses/${executionId}/rollback`, {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Rollback failed');
      return;
    }
    await loadWorkspace();
  };

  const handleUpdateSsoConfig = async (updates: {
    protocol?: 'saml_2_0' | 'oidc';
    ssoEnforced?: boolean;
    localPasswordFallbackDisabled?: boolean;
    mfaRequiredForAdmins?: boolean;
    scimEnabled?: boolean;
    rotateCertificate?: boolean;
  }) => {
    setRbacNotice('');
    const res = await fetch('/api/enterprise/sso/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Permission denied');
      return;
    }
    await loadWorkspace();
  };

  const handleProvisionScimUser = async (payload: {
    email: string;
    displayName: string;
    idpGroups: string[];
  }) => {
    setRbacNotice('');
    const res = await fetch('/api/enterprise/scim/provision', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'SCIM provisioning denied');
      return;
    }
    await loadWorkspace();
  };

  const handleDeprovisionScimUser = async (email: string) => {
    setRbacNotice('');
    const res = await fetch('/api/enterprise/scim/deprovision', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'SCIM deprovisioning denied');
      return null;
    }
    const data = (await res.json()) as { revokedSessionCount: number };
    await loadWorkspace();
    return data;
  };

  const handleVerifyReleaseGates = async () => {
    setRbacNotice('');
    const res = await fetch('/api/enterprise/release-gates/verify', { method: 'POST' });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Release gate check failed');
      return;
    }
    await loadWorkspace();
  };

  const handleUpdateAuditRetention = async (retentionDays: number) => {
    setRbacNotice('');
    const res = await fetch('/api/enterprise/audit/retention', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ retentionDays }),
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Retention update denied');
      return;
    }
    await loadWorkspace();
  };

  const handleExportAuditLedger = async () => {
    setRbacNotice('');
    const res = await fetch('/api/audit-events/export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Audit export denied');
      return null;
    }
    const pkg = await res.json();
    await loadWorkspace();
    return pkg;
  };

  const handleRunAllInOne = async (options?: {
    ticketProvider?: 'jira' | 'servicenow';
    assignee?: string;
  }) => {
    setRbacNotice('');
    const res = await fetch('/api/enterprise/all-in-one/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(options ?? {}),
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'All-in-One orchestration failed');
      return null;
    }
    const result = (await res.json()) as AllInOneRunResult;
    await loadWorkspace();
    return result;
  };

  const handleOnboardAllClouds = async () => {
    setRbacNotice('');
    const res = await fetch('/api/connectors/onboard-all', { method: 'POST' });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Batch cloud onboarding failed');
      return null;
    }
    const result = (await res.json()) as {
      connectorsSynced: number;
      nodesAdded: number;
      edgesAdded: number;
    };
    await loadWorkspace();
    return result;
  };

  const handleTicketAllOpenFindings = async (provider: 'jira' | 'servicenow') => {
    setRbacNotice('');
    const res = await fetch('/api/findings/ticket-all', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider }),
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Batch ticketing failed');
      return null;
    }
    const result = (await res.json()) as { createdCount: number };
    await loadWorkspace();
    return result;
  };

  const handleReviewAgentLifecycle = async (
    agentId: string,
    payload: {
      action: 'verify' | 'sanction' | 'unsanction' | 'retire';
      owner?: string;
      ownerTeam?: string;
      reason?: string;
    }
  ): Promise<Agent | null> => {
    setRbacNotice('');
    const res = await fetch(`/api/agents/${agentId}/lifecycle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) {
      const msg = data.error || 'Agent lifecycle update denied';
      setRbacNotice(msg);
      throw new Error(msg);
    }
    await loadWorkspace();
    return (data.agent as Agent) ?? null;
  };

  const handleActivateVerticalPack = async (packId: VerticalPackId, install: boolean) => {
    setRbacNotice('');
    const res = await fetch(`/api/vertical-packs/${packId}/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ install }),
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Vertical policy pack update denied');
      return;
    }
    await loadWorkspace();
  };

  const handleUpdateModelApproval = async (
    modelId: string,
    approvalStatus: ModelApprovalStatus
  ) => {
    setRbacNotice('');
    const res = await fetch(`/api/registry/models/${modelId}/approval`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ approvalStatus }),
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Model registry update denied');
      return;
    }
    await loadWorkspace();
  };

  const handleUpdateMcpApproval = async (mcpId: string, approvalStatus: McpApprovalStatus) => {
    setRbacNotice('');
    const res = await fetch(`/api/registry/mcp/${mcpId}/approval`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ approvalStatus }),
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'MCP registry update denied');
      return;
    }
    await loadWorkspace();
  };

  const handleCreatePolicyException = async (payload: {
    policyId: string;
    agentId: string;
    justification: string;
    expiresInDays?: number;
  }) => {
    setRbacNotice('');
    const res = await fetch('/api/policy/exceptions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) {
      const msg = data.error || 'Unable to grant policy exception';
      setRbacNotice(msg);
      throw new Error(msg);
    }
    await loadWorkspace();
  };

  const handleRevokePolicyException = async (exceptionId: string) => {
    setRbacNotice('');
    const res = await fetch(`/api/policy/exceptions/${exceptionId}/revoke`, {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Unable to revoke policy exception');
      return;
    }
    await loadWorkspace();
  };

  const handleUpdateGatewayConfig = async (updates: {
    failoverMode?: 'fail_open' | 'fail_closed';
    responseInspectionEnabled?: boolean;
    promptInjectionGuardEnabled?: boolean;
  }) => {
    setRbacNotice('');
    const res = await fetch('/api/enterprise/gateway-config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Gateway configuration update denied');
      return;
    }
    await loadWorkspace();
  };

  const handleContainIncident = async (
    incidentId: string,
    payload: { action: ContainmentActionId; approve: boolean; dryRun: boolean }
  ): Promise<{ incident: SecurityIncident; dryRunDiff?: string } | null> => {
    setRbacNotice('');
    const res = await fetch(`/api/incidents/${incidentId}/contain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) {
      const msg = data.error || 'Incident containment failed';
      setRbacNotice(msg);
      throw new Error(msg);
    }
    await loadWorkspace();
    return data as { incident: SecurityIncident; dryRunDiff?: string };
  };

  const handleCreateComplianceException = async (payload: {
    controlId: string;
    reason: string;
    compensatingControl: string;
    expiresInDays?: number;
  }): Promise<ComplianceException | null> => {
    setRbacNotice('');
    const res = await fetch('/api/compliance/exceptions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) {
      const msg = data.error || 'Compliance exception denied';
      setRbacNotice(msg);
      throw new Error(msg);
    }
    await loadWorkspace();
    return (data.exception as ComplianceException) ?? null;
  };

  const handleRevokeComplianceException = async (exceptionId: string) => {
    setRbacNotice('');
    const res = await fetch(`/api/compliance/exceptions/${exceptionId}/revoke`, {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Unable to revoke compliance exception');
      return;
    }
    await loadWorkspace();
  };

  const handleExportComplianceCsv = async (
    framework: ComplianceFramework | 'all'
  ): Promise<{ filename: string; csvContent: string; rowCount: number } | null> => {
    setRbacNotice('');
    const res = await fetch('/api/compliance/export-csv', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ framework }),
    });
    if (!res.ok) {
      const err = await res.json();
      setRbacNotice(err.error || 'Compliance CSV export denied');
      return null;
    }
    const data = (await res.json()) as {
      filename: string;
      csvContent: string;
      rowCount: number;
    };
    await loadWorkspace();
    return data;
  };

  if (viewMode === 'landing') {
    return <LandingPage onLaunchDemo={handleLaunchDemo} />;
  }

  const breadcrumbDetail =
    activeScreen === 'agent-detail' || activeScreen === 'exposure'
      ? selectedAgent?.name
      : undefined;

  const canManageConnectors = Boolean(
    !authSession || authSession.permissions.includes('connectors:manage')
  );
  const canManageAgents = Boolean(
    !authSession || authSession.permissions.includes('findings:manage')
  );
  const canAdminTenant = Boolean(
    !authSession || authSession.permissions.includes('tenant:admin')
  );
  const canRunAllInOne = Boolean(
    !authSession || authSession.permissions.includes('policies:manage')
  );

  return (
    <DashboardShell
      tenants={tenants}
      selectedTenantId={selectedTenantId}
      onSelectTenant={handleSelectTenant}
      activeScreen={activeScreen}
      onNavigate={(screen) => {
        setRbacNotice('');
        setActiveScreen(screen);
      }}
      onExitToLanding={() => {
        setTourActive(false);
        setViewMode('landing');
      }}
      onStartTour={() => {
        setTourActive(true);
        applyTourStep(0);
      }}
      onOpenAuthModal={() => setAuthModalOpen(true)}
      authSession={authSession}
      tourActive={tourActive}
      breadcrumbDetail={breadcrumbDetail}
      openFindingsCount={openFindingsCount}
    >
      {rbacNotice && (
        <div
          role="alert"
          className="mx-auto mb-5 max-w-7xl rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-2.5 text-xs text-rose-300"
        >
          {rbacNotice}
        </div>
      )}

      {activeScreen === 'overview' && (
        <RiskCommandCenter
          tenant={tenantRecord}
          metrics={metrics}
          agents={agents}
          findings={findings}
          controls={controls}
          dataSources={dataSources}
          activity={activity}
          trendSeries={trendSeries}
          activeVerticalPacks={activeVerticalPacks}
          verticalPacksCatalog={verticalPacksCatalog}
          onSelectAgent={(id) => {
            setSelectedAgentId(id);
            setActiveScreen('agent-detail');
          }}
          onNavigate={(screen) => setActiveScreen(screen)}
        />
      )}

      {activeScreen === 'all-in-one' && (
        <AllInOneView
          tenant={tenantRecord}
          agents={agents}
          connectors={connectors}
          graphPaths={graphPaths}
          findings={findings}
          controls={controls}
          enterpriseState={enterpriseState}
          lastRun={enterpriseState?.lastAllInOneRun}
          canRunAllInOne={canRunAllInOne}
          onRunAllInOne={handleRunAllInOne}
          onOnboardAllClouds={handleOnboardAllClouds}
          onTicketAllOpenFindings={handleTicketAllOpenFindings}
          onChangeRolloutStage={handleChangeRolloutStage}
          onToggleKillSwitch={handleToggleKillSwitch}
          onExportCompliance={async () => {
            const pkg = await handleExportAuditPack({ framework: 'all' });
            return pkg?.packageId ?? null;
          }}
          onVerifyReleaseGates={handleVerifyReleaseGates}
          onNavigate={(screen) => setActiveScreen(screen)}
        />
      )}

      {activeScreen === 'inventory' && (
        <AgentInventory
          tenantId={tenantRecord.id}
          totalTenantDiscoveredCount={tenantRecord.totalDiscoveredAgents}
          agents={agents}
          dataSources={dataSources}
          canManageAgents={canManageAgents}
          onCreateAgent={handleCreateAgent}
          onReviewAgentLifecycle={handleReviewAgentLifecycle}
          onSelectAgent={(id) => {
            setSelectedAgentId(id);
            setActiveScreen('agent-detail');
          }}
        />
      )}

      {activeScreen === 'agent-detail' && selectedAgent && (
        <AgentDetail
          agent={selectedAgent}
          mcpServers={mcpServers}
          models={models}
          dataSources={dataSources}
          findings={findings}
          canManageAgents={canManageAgents}
          onUpdateAgentGovernance={handleUpdateAgentGovernance}
          onReviewAgentLifecycle={handleReviewAgentLifecycle}
          onBack={() => setActiveScreen('inventory')}
          onViewExposurePath={(id) => {
            setSelectedAgentId(id);
            setActiveScreen('exposure');
          }}
          onOpenFindings={() => setActiveScreen('findings')}
        />
      )}

      {activeScreen === 'exposure' && (
        <ExposurePaths
          tenantId={tenantRecord.id}
          agents={agents}
          mcpServers={mcpServers}
          dataSources={dataSources}
          graphPaths={graphPaths}
          selectedAgentId={selectedAgent?.id ?? 'agent_finance_copilot'}
          onSelectAgentId={(id) => setSelectedAgentId(id)}
          onOpenFindingsForAgent={() => setActiveScreen('findings')}
        />
      )}

      {activeScreen === 'findings' && (
        <FindingsView
          tenantId={tenantRecord.id}
          findings={findings}
          agents={agents}
          incidents={incidents}
          containmentCatalog={containmentCatalog}
          onCreateRemediationTicket={handleCreateRemediationTicket}
          onTicketAllOpenFindings={handleTicketAllOpenFindings}
          onRunDryRun={handleRunDryRun}
          onApproveRemediation={handleApproveRemediation}
          onApplyRemediation={handleApplyRemediation}
          onRollbackRemediation={handleRollbackRemediation}
          onVerifyAndClose={handleVerifyAndCloseFinding}
          onRecalculateAgentRisk={handleRecalculateAgentRisk}
          onContainIncident={handleContainIncident}
        />
      )}

      {activeScreen === 'compliance' && (
        <ComplianceView
          tenantName={tenantRecord.name}
          controls={controls}
          evidence={evidenceItems}
          evidenceRecords={evidenceRecords}
          complianceExceptions={complianceExceptions}
          onExportAuditPack={handleExportAuditPack}
          onExportComplianceCsv={handleExportComplianceCsv}
          onAttestControl={handleAttestControl}
          onCreateComplianceException={handleCreateComplianceException}
          onRevokeComplianceException={handleRevokeComplianceException}
        />
      )}

      {activeScreen === 'policy' && (
        <PolicyView
          policyMode={policyMode}
          onChangeMode={handleChangePolicyMode}
          rules={policyRules}
          onToggleRule={handleToggleRule}
          onCreatePolicyRule={handleCreatePolicyRule}
          onCreateGatewayPolicy={handleCreateGatewayPolicy}
          simulationEvents={simulationEvents}
          agents={agents}
          models={models}
          mcpServers={mcpServers}
          gatewayPolicies={gatewayPolicies}
          gatewayEvents={gatewayEvents}
          retentionConfig={retentionConfig}
          rolloutStage={enterpriseState?.rolloutStage}
          killSwitch={enterpriseState?.killSwitch}
          playbooks={enterpriseState?.playbooks}
          playbookExecutions={enterpriseState?.playbookExecutions}
          activeVerticalPacks={activeVerticalPacks}
          verticalPacksCatalog={verticalPacksCatalog}
          providerAdapters={providerAdapters}
          policyExceptions={policyExceptions}
          gatewayRuntimeConfig={gatewayRuntimeConfig}
          onInspectGateway={handleInspectGateway}
          onEvaluatePep={handleEvaluatePep}
          onChangeRolloutStage={handleChangeRolloutStage}
          onToggleKillSwitch={handleToggleKillSwitch}
          onDryRunPlaybook={handleDryRunPlaybook}
          onExecutePlaybook={handleExecutePlaybook}
          onApprovePlaybookExecution={handleApprovePlaybookExecution}
          onRollbackPlaybookExecution={handleRollbackPlaybookExecution}
          onToggleRetentionOptIn={handleToggleRetentionOptIn}
          onActivateVerticalPack={handleActivateVerticalPack}
          onUpdateModelApproval={handleUpdateModelApproval}
          onUpdateMcpApproval={handleUpdateMcpApproval}
          onCreatePolicyException={handleCreatePolicyException}
          onRevokePolicyException={handleRevokePolicyException}
          onUpdateGatewayConfig={handleUpdateGatewayConfig}
        />
      )}

      {activeScreen === 'connectors' && (
        <ConnectorsView
          tenantId={tenantRecord.id}
          connectors={connectors}
          canManageConnectors={canManageConnectors}
          onRunSync={handleRunConnectorSync}
          onRunAllSyncs={handleRunAllSyncs}
          onOnboardAllClouds={handleOnboardAllClouds}
          onPkceAuthorize={handlePkceAuthorize}
          onRotateToken={handleRotateToken}
          onDisconnect={handleDisconnectConnector}
          onOnboardCloud={handleOnboardCloud}
        />
      )}

      {activeScreen === 'enterprise' && enterpriseState && (
        <EnterpriseView
          tenantName={tenantRecord.name}
          canAdminTenant={canAdminTenant}
          ssoConfig={enterpriseState.ssoConfig}
          scimDirectory={enterpriseState.scimDirectory}
          idpGroupRoleMap={enterpriseState.idpGroupRoleMap}
          hardeningMatrix={enterpriseState.hardeningMatrix}
          releaseGates={enterpriseState.releaseGates}
          demoRequests={demoRequests}
          onUpdateSsoConfig={handleUpdateSsoConfig}
          onProvisionScimUser={handleProvisionScimUser}
          onDeprovisionScimUser={handleDeprovisionScimUser}
          onVerifyReleaseGates={handleVerifyReleaseGates}
          onResetDemoState={handleResetDemoState}
        />
      )}

      {activeScreen === 'audit' && (
        <AuditLogView
          tenantId={tenantRecord.id}
          tenantName={tenantRecord.name}
          events={auditEvents}
          integrity={enterpriseState?.auditIntegrity}
          retentionDays={enterpriseState?.auditRetentionDays}
          canAdminTenant={canAdminTenant}
          onRefreshAudit={handleRefreshAudit}
          onFilterAuditEvents={handleFilterAuditEvents}
          onUpdateRetentionDays={handleUpdateAuditRetention}
          onExportAuditLedger={handleExportAuditLedger}
        />
      )}

      {tourActive && (
        <GuidedTourOverlay
          currentStepIndex={tourStepIndex}
          onSelectStep={applyTourStep}
          onClose={() => setTourActive(false)}
        />
      )}

      <AuthGateModal
        isOpen={authModalOpen}
        onClose={() => setAuthModalOpen(false)}
        onAuthenticated={handleAuthenticated}
      />
    </DashboardShell>
  );
}
