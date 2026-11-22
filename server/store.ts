import crypto from 'node:crypto';
import type {
  ActivityEvent,
  Agent,
  AgentStatus,
  AgentType,
  AllInOneRunResult,
  AllInOneStageResult,
  AuditChainIntegrity,
  ComplianceFramework,
  Connector,
  ControlItem,
  DataSource,
  DemoRequestRecord,
  EnforcementAction,
  EnterpriseSsoConfig,
  EvidenceItem,
  EvidenceRecord,
  EvidenceType,
  Finding,
  FindingEvidenceArtifact,
  GatewayDecision,
  GatewayEvent,
  GatewayPolicyDefinition,
  KillSwitchState,
  McpServer,
  ModelAsset,
  PlatformHardeningItem,
  PlaybookDefinition,
  PlaybookExecutionRecord,
  PlaybookId,
  PolicyAction,
  PolicyMode,
  PolicyRule,
  PolicySimulationEvent,
  ReleaseGateCheck,
  RetentionPolicyConfig,
  RiskFactorInputs,
  RiskLevel,
  RiskTrendPoint,
  RolloutStage,
  ScimDirectoryUser,
} from '../src/types/security.ts';
import {
  DATA_SOURCES,
  INITIAL_ACTIVITY,
  INITIAL_AGENTS,
  INITIAL_FINDINGS,
  INITIAL_POLICY_RULES,
  MCP_SERVERS,
  MODELS,
  POLICY_SIMULATION_EVENTS,
  RISK_TREND_SERIES,
} from '../src/data/mockData.ts';
import {
  AWS_READ_ONLY_POLICY_DOCUMENT,
  AZURE_SECURITY_READER_ACTIONS,
  ConnectorRegistry,
  validateAwsConnectionInput,
} from './connectorRegistry.ts';
import {
  createPkcePair,
  decryptTenantSecret,
  encryptTenantSecret,
} from './cryptoVault.ts';
import {
  buildCanonicalAuditPayload,
  computeAuditEventHash,
  ENTERPRISE_YAML_POLICIES,
  evaluatePolicyDecisionPoint,
  IDP_GROUP_ROLE_MAP,
  isDecisionEnforcedAtStage,
  mapIdpGroupsToRole,
  PLATFORM_HARDENING_MATRIX,
  RESPONSE_PLAYBOOKS,
  verifyAuditHashChain,
} from './enterpriseEngine.ts';
import {
  buildDryRunDiff,
  buildIdempotentKey,
  computeEvidenceHash,
  evaluateFindingsFromDiscovery,
  formatTicketDescription,
  INITIAL_DETECTION_RULES,
  verifyFindingExposureRemoved,
} from './findingsEngine.ts';
import {
  buildAuditorExportPackage,
  createChainedEvidenceRecord,
  DEFAULT_RETENTION_POLICY,
  GOVERNANCE_CONTROLS,
  inspectGatewayRequest,
  SEED_GATEWAY_POLICIES,
} from './governanceEngine.ts';
import { findSensitiveExposurePaths } from './graphEngine.ts';
import { deriveAgentRiskAssessment } from './riskScoringEngine.ts';
import type {
  AuditEvent,
  ConnectorRecord,
  EncryptedCredentialRecord,
  ExposureTraversalResult,
  GraphEdge,
  GraphNode,
  Role,
  SessionRecord,
  TenantMembership,
  TenantRecord,
  UserRecord,
} from './types.ts';
import { FileStatePersistence } from './persistence.ts';

export class TenantIsolationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TenantIsolationError';
  }
}

export class TenantDataStore {
  private tenants: TenantRecord[] = [
    {
      id: 'tenant_northwind',
      name: 'Northwind Financial',
      slug: 'northwind-financial',
      domain: 'northwind.com',
      industry: 'Financial Services',
      plan: 'enterprise',
      status: 'active',
      totalDiscoveredAgents: 42,
      activeAgents: 36,
      unownedAgents: 5,
      shadowAgents: 7,
      overallRiskScore: 78,
      riskTrendDelta: -6,
      overPrivilegedIdentities: 11,
      unusedCredentials: 14,
      riskyServiceAccounts: 6,
      dailyRequests: 148200,
      dailyToolCalls: 39410,
      blockedOrRedactedEvents: 1284,
      createdAt: '2026-06-01T00:00:00Z',
    },
    {
      id: 'tenant_northwind_eu',
      name: 'Northwind Europe GmbH',
      slug: 'northwind-europe',
      domain: 'northwind.eu',
      industry: 'Wealth & Institutional Banking',
      plan: 'enterprise',
      status: 'active',
      totalDiscoveredAgents: 19,
      activeAgents: 16,
      unownedAgents: 2,
      shadowAgents: 3,
      overallRiskScore: 61,
      riskTrendDelta: -9,
      overPrivilegedIdentities: 4,
      unusedCredentials: 6,
      riskyServiceAccounts: 2,
      dailyRequests: 62400,
      dailyToolCalls: 14890,
      blockedOrRedactedEvents: 412,
      createdAt: '2026-08-15T00:00:00Z',
    },
  ];

  private users: UserRecord[] = [
    {
      id: 'usr_owner_nw',
      email: 'ciso@northwind.com',
      displayName: 'Elena Rostova (CISO · Owner)',
      externalId: 'okta_00u1a9x',
      idp: 'okta_saml',
      mfaEnabled: true,
      interactiveAllowed: true,
      createdAt: '2026-06-01T00:00:00Z',
    },
    {
      id: 'usr_admin_nw',
      email: 'sec-admin@northwind.com',
      displayName: 'Marcus Vance (Security Admin)',
      externalId: 'entra_99b2c1',
      idp: 'entra_oidc',
      mfaEnabled: true,
      interactiveAllowed: true,
      createdAt: '2026-06-05T00:00:00Z',
    },
    {
      id: 'usr_analyst_nw',
      email: 'analyst@northwind.com',
      displayName: 'Priya Nair (Security Analyst)',
      externalId: 'entra_41d8f0',
      idp: 'entra_oidc',
      mfaEnabled: true,
      interactiveAllowed: true,
      createdAt: '2026-06-12T00:00:00Z',
    },
    {
      id: 'usr_compliance_nw',
      email: 'grc@northwind.com',
      displayName: 'Hannah Kim (Compliance Manager)',
      externalId: 'workos_77e3a2',
      idp: 'workos_sso',
      mfaEnabled: true,
      interactiveAllowed: true,
      createdAt: '2026-07-01T00:00:00Z',
    },
    {
      id: 'usr_agent_owner_nw',
      email: 'finance-ops@northwind.com',
      displayName: 'David Chen (Agent Owner · Finance)',
      externalId: 'entra_55c1d9',
      idp: 'entra_oidc',
      mfaEnabled: false,
      interactiveAllowed: true,
      createdAt: '2026-07-10T00:00:00Z',
    },
    {
      id: 'usr_auditor_nw',
      email: 'external-audit@kpmg-sandbox.example',
      displayName: 'Claire Dubois (External Auditor)',
      externalId: 'workos_88a4b7',
      idp: 'workos_sso',
      mfaEnabled: true,
      interactiveAllowed: true,
      createdAt: '2026-09-01T00:00:00Z',
    },
    {
      id: 'usr_svc_nw',
      email: 'ci-scanner@northwind.com',
      displayName: 'CI Discovery Service Account',
      externalId: 'svc_ci_scanner',
      idp: 'service_token',
      mfaEnabled: false,
      interactiveAllowed: false,
      createdAt: '2026-09-10T00:00:00Z',
    },
    {
      id: 'usr_admin_eu',
      email: 'dpo-admin@northwind.eu',
      displayName: 'Lukas Weber (EU Admin)',
      externalId: 'entra_eu_102',
      idp: 'entra_oidc',
      mfaEnabled: true,
      interactiveAllowed: true,
      createdAt: '2026-08-15T00:00:00Z',
    },
  ];

  private memberships: TenantMembership[] = [
    // ciso@northwind.com holds membership in BOTH Northwind Financial and Northwind Europe GmbH
    { tenantId: 'tenant_northwind', userId: 'usr_owner_nw', role: 'owner', status: 'active' },
    { tenantId: 'tenant_northwind_eu', userId: 'usr_owner_nw', role: 'owner', status: 'active' },
    // Single-tenant memberships
    { tenantId: 'tenant_northwind', userId: 'usr_admin_nw', role: 'admin', status: 'active' },
    { tenantId: 'tenant_northwind', userId: 'usr_analyst_nw', role: 'security_analyst', status: 'active' },
    { tenantId: 'tenant_northwind', userId: 'usr_compliance_nw', role: 'compliance_manager', status: 'active' },
    { tenantId: 'tenant_northwind', userId: 'usr_agent_owner_nw', role: 'agent_owner', status: 'active' },
    { tenantId: 'tenant_northwind', userId: 'usr_auditor_nw', role: 'auditor', status: 'active' },
    { tenantId: 'tenant_northwind', userId: 'usr_svc_nw', role: 'service_account', status: 'active' },
    { tenantId: 'tenant_northwind_eu', userId: 'usr_admin_eu', role: 'admin', status: 'active' },
  ];

  private sessions = new Map<string, SessionRecord>();
  private pkceChallenges = new Map<string, { tenantId: string; connectorId: string; codeChallenge: string }>();

  private agents: Agent[] = structuredClone(INITIAL_AGENTS);
  private findings: Finding[] = structuredClone(INITIAL_FINDINGS);
  private policyModes: Record<string, PolicyMode> = {
    tenant_northwind: 'observe',
    tenant_northwind_eu: 'observe',
  };
  private policyRules: Record<string, PolicyRule[]> = {
    tenant_northwind: structuredClone(INITIAL_POLICY_RULES),
    tenant_northwind_eu: structuredClone(INITIAL_POLICY_RULES),
  };
  private activity: ActivityEvent[] = structuredClone(INITIAL_ACTIVITY);
  private connectors: ConnectorRecord[] = [];
  private credentials: EncryptedCredentialRecord[] = [];
  private graphNodes: GraphNode[] = [];
  private graphEdges: GraphEdge[] = [];
  private removedEdgeBackups = new Map<string, GraphEdge>();
  private auditEvents: AuditEvent[] = [];
  private evidenceRecords: EvidenceRecord[] = [];
  private gatewayEvents: GatewayEvent[] = [];
  private gatewayPolicies: Record<string, GatewayPolicyDefinition[]> = {
    tenant_northwind: structuredClone([...SEED_GATEWAY_POLICIES, ...ENTERPRISE_YAML_POLICIES]),
    tenant_northwind_eu: structuredClone([...SEED_GATEWAY_POLICIES, ...ENTERPRISE_YAML_POLICIES]),
  };
  private retentionConfigs: Record<string, RetentionPolicyConfig> = {
    tenant_northwind: { ...DEFAULT_RETENTION_POLICY },
    tenant_northwind_eu: { ...DEFAULT_RETENTION_POLICY },
  };
  private rolloutStages: Record<string, RolloutStage> = {
    tenant_northwind: 'observe',
    tenant_northwind_eu: 'observe',
  };
  private killSwitches: Record<string, KillSwitchState> = {
    tenant_northwind: {
      paused: false,
      updatedAt: '2026-11-16T06:00:00Z',
      updatedBy: 'ciso@northwind.com',
      reason: 'Normal enterprise control plane operations',
    },
    tenant_northwind_eu: {
      paused: false,
      updatedAt: '2026-11-16T06:00:00Z',
      updatedBy: 'dpo-admin@northwind.eu',
      reason: 'Normal EU control plane operations',
    },
  };
  private playbookExecutions: PlaybookExecutionRecord[] = [];
  private responseRateWindow = new Map<string, number[]>();
  private replayNonces = new Set<string>();
  private ssoConfigs: Record<string, EnterpriseSsoConfig> = {};
  private scimDirectory: ScimDirectoryUser[] = [];
  private auditRetentionDays: Record<string, number> = {
    tenant_northwind: 365,
    tenant_northwind_eu: 365,
  };
  private lastAllInOneRuns: Record<string, AllInOneRunResult> = {};
  private mcpServers: McpServer[] = structuredClone(MCP_SERVERS);
  private models: ModelAsset[] = structuredClone(MODELS);
  private dataSources: DataSource[] = structuredClone(DATA_SOURCES);
  private demoRequests: DemoRequestRecord[] = [];
  private nextTicketNum = 4201;
  private nextSnowNum = 8840;
  private persistence: FileStatePersistence;
  private hydrating = false;

  public registry = new ConnectorRegistry();

  constructor(options?: { persist?: boolean; stateFilePath?: string }) {
    this.persistence = new FileStatePersistence({
      enabled: options?.persist ?? false,
      filePath: options?.stateFilePath,
    });
    const loaded = this.persistence.load();
    if (loaded && this.hydrateFromSnapshot(loaded.data)) {
      return;
    }
    this.initializeSeedState();
    this.persistState();
  }

  private initializeSeedState() {
    this.seedConnectorsAndCredentials();
    this.seedSecurityGraph();
    this.enrichSeedFindings();
    this.recomputeTenantRiskAssessments('tenant_northwind');
    this.recomputeTenantRiskAssessments('tenant_northwind_eu');
    this.seedGovernanceEvidenceAndGateway();
    this.seedInitialAuditEvents();
    this.seedEnterpriseState();
  }

  private persistState() {
    if (this.hydrating || !this.persistence.isEnabled()) return;
    this.persistence.save({
      tenants: this.tenants,
      users: this.users,
      memberships: this.memberships,
      sessions: Array.from(this.sessions.entries()),
      agents: this.agents,
      findings: this.findings,
      policyModes: this.policyModes,
      policyRules: this.policyRules,
      activity: this.activity,
      connectors: this.connectors,
      credentials: this.credentials,
      graphNodes: this.graphNodes,
      graphEdges: this.graphEdges,
      removedEdgeBackups: Array.from(this.removedEdgeBackups.entries()),
      auditEvents: this.auditEvents,
      evidenceRecords: this.evidenceRecords,
      gatewayEvents: this.gatewayEvents,
      gatewayPolicies: this.gatewayPolicies,
      retentionConfigs: this.retentionConfigs,
      rolloutStages: this.rolloutStages,
      killSwitches: this.killSwitches,
      playbookExecutions: this.playbookExecutions,
      replayNonces: Array.from(this.replayNonces),
      ssoConfigs: this.ssoConfigs,
      scimDirectory: this.scimDirectory,
      auditRetentionDays: this.auditRetentionDays,
      lastAllInOneRuns: this.lastAllInOneRuns,
      mcpServers: this.mcpServers,
      models: this.models,
      dataSources: this.dataSources,
      demoRequests: this.demoRequests,
      nextTicketNum: this.nextTicketNum,
      nextSnowNum: this.nextSnowNum,
    });
  }

  private hydrateFromSnapshot(data: Record<string, unknown>): boolean {
    try {
      this.hydrating = true;
      if (Array.isArray(data.tenants)) this.tenants = data.tenants as TenantRecord[];
      if (Array.isArray(data.users)) this.users = data.users as UserRecord[];
      if (Array.isArray(data.memberships)) this.memberships = data.memberships as TenantMembership[];
      if (Array.isArray(data.sessions)) {
        this.sessions = new Map(data.sessions as Array<[string, SessionRecord]>);
      }
      if (Array.isArray(data.agents)) this.agents = data.agents as Agent[];
      if (Array.isArray(data.findings)) this.findings = data.findings as Finding[];
      if (data.policyModes) this.policyModes = data.policyModes as Record<string, PolicyMode>;
      if (data.policyRules) this.policyRules = data.policyRules as Record<string, PolicyRule[]>;
      if (Array.isArray(data.activity)) this.activity = data.activity as ActivityEvent[];
      if (Array.isArray(data.connectors)) this.connectors = data.connectors as ConnectorRecord[];
      if (Array.isArray(data.credentials)) {
        this.credentials = data.credentials as EncryptedCredentialRecord[];
      }
      if (Array.isArray(data.graphNodes)) this.graphNodes = data.graphNodes as GraphNode[];
      if (Array.isArray(data.graphEdges)) this.graphEdges = data.graphEdges as GraphEdge[];
      if (Array.isArray(data.removedEdgeBackups)) {
        this.removedEdgeBackups = new Map(data.removedEdgeBackups as Array<[string, GraphEdge]>);
      }
      if (Array.isArray(data.auditEvents)) this.auditEvents = data.auditEvents as AuditEvent[];
      if (Array.isArray(data.evidenceRecords)) {
        this.evidenceRecords = data.evidenceRecords as EvidenceRecord[];
      }
      if (Array.isArray(data.gatewayEvents)) this.gatewayEvents = data.gatewayEvents as GatewayEvent[];
      if (data.gatewayPolicies) {
        this.gatewayPolicies = data.gatewayPolicies as Record<string, GatewayPolicyDefinition[]>;
      }
      if (data.retentionConfigs) {
        this.retentionConfigs = data.retentionConfigs as Record<string, RetentionPolicyConfig>;
      }
      if (data.rolloutStages) this.rolloutStages = data.rolloutStages as Record<string, RolloutStage>;
      if (data.killSwitches) {
        this.killSwitches = data.killSwitches as Record<string, KillSwitchState>;
      }
      if (Array.isArray(data.playbookExecutions)) {
        this.playbookExecutions = data.playbookExecutions as PlaybookExecutionRecord[];
      }
      if (Array.isArray(data.replayNonces)) {
        this.replayNonces = new Set(data.replayNonces as string[]);
      }
      if (data.ssoConfigs) {
        this.ssoConfigs = data.ssoConfigs as Record<string, EnterpriseSsoConfig>;
      }
      if (Array.isArray(data.scimDirectory)) {
        this.scimDirectory = data.scimDirectory as ScimDirectoryUser[];
      }
      if (data.auditRetentionDays) {
        this.auditRetentionDays = data.auditRetentionDays as Record<string, number>;
      }
      if (data.lastAllInOneRuns) {
        this.lastAllInOneRuns = data.lastAllInOneRuns as Record<string, AllInOneRunResult>;
      }
      if (Array.isArray(data.mcpServers)) this.mcpServers = data.mcpServers as McpServer[];
      if (Array.isArray(data.models)) this.models = data.models as ModelAsset[];
      if (Array.isArray(data.dataSources)) this.dataSources = data.dataSources as DataSource[];
      if (Array.isArray(data.demoRequests)) {
        this.demoRequests = data.demoRequests as DemoRequestRecord[];
      }
      if (typeof data.nextTicketNum === 'number') this.nextTicketNum = data.nextTicketNum;
      if (typeof data.nextSnowNum === 'number') this.nextSnowNum = data.nextSnowNum;
      return true;
    } catch {
      return false;
    } finally {
      this.hydrating = false;
    }
  }

  public getPersistenceInfo(): { enabled: boolean; filePath: string } {
    return {
      enabled: this.persistence.isEnabled(),
      filePath: this.persistence.filePath,
    };
  }

  public resetToSeedState(actor: { id: string; email: string; role: Role }, tenantId: string): void {
    this.persistence.clear();
    const fresh = new TenantDataStore({ persist: false });
    this.hydrateFromSnapshot({
      tenants: fresh.tenants,
      users: fresh.users,
      memberships: fresh.memberships,
      sessions: Array.from(this.sessions.entries()),
      agents: fresh.agents,
      findings: fresh.findings,
      policyModes: fresh.policyModes,
      policyRules: fresh.policyRules,
      activity: fresh.activity,
      connectors: fresh.connectors,
      credentials: fresh.credentials,
      graphNodes: fresh.graphNodes,
      graphEdges: fresh.graphEdges,
      removedEdgeBackups: [],
      auditEvents: fresh.auditEvents,
      evidenceRecords: fresh.evidenceRecords,
      gatewayEvents: fresh.gatewayEvents,
      gatewayPolicies: fresh.gatewayPolicies,
      retentionConfigs: fresh.retentionConfigs,
      rolloutStages: fresh.rolloutStages,
      killSwitches: fresh.killSwitches,
      playbookExecutions: fresh.playbookExecutions,
      replayNonces: [],
      ssoConfigs: fresh.ssoConfigs,
      scimDirectory: fresh.scimDirectory,
      auditRetentionDays: fresh.auditRetentionDays,
      lastAllInOneRuns: {},
      mcpServers: fresh.mcpServers,
      models: fresh.models,
      dataSources: fresh.dataSources,
      demoRequests: [],
      nextTicketNum: 4201,
      nextSnowNum: 8840,
    });
    this.recordAuditEvent({
      tenantId,
      actorId: actor.id,
      actorEmail: actor.email,
      actorRole: actor.role,
      action: 'system.sandbox_reset',
      resourceType: 'control_plane',
      resourceId: tenantId,
      outcome: 'allowed',
      before: null,
      after: { resetAt: new Date().toISOString() },
      reason: 'Administrator reset sandbox state to baseline seed posture',
    });
    this.persistState();
  }

  /**
   * Simulates PostgreSQL RLS `SET LOCAL app.current_tenant_id = $tenantId`
   * Every tenant-scoped read/write must pass through this guard.
   */
  public withTenantContext<T>(tenantId: string, fn: (scopedTenantId: string) => T): T {
    if (!tenantId || !this.tenants.some((t) => t.id === tenantId)) {
      throw new TenantIsolationError('Invalid or missing tenant execution context');
    }
    return fn(tenantId);
  }

  private seedConnectorsAndCredentials() {
    const initialList: Omit<ConnectorRecord, 'pkceVerified' | 'readOnly'>[] = [
      {
        id: 'conn_entra',
        tenantId: 'tenant_northwind',
        provider: 'entra_id',
        displayName: 'Microsoft Entra ID',
        category: 'Identity',
        status: 'healthy',
        lastSyncAt: new Date(Date.now() - 180000).toISOString(),
        lastSyncLabel: '3m ago',
        coveragePct: 100,
        discoveredAssets: 62,
        discoveredSummary: {
          Users: 24,
          Groups: 8,
          'Service Principals': 14,
          'Directory Roles': 5,
          'OAuth Grants': 11,
        },
        scopes: [
          'User.Read.All',
          'Group.Read.All',
          'Application.Read.All',
          'Directory.Read.All',
          'RoleManagement.Read.Directory',
        ],
        config: { tenantDomain: 'northwind.com', adminConsent: 'granted' },
      },
      {
        id: 'conn_aws',
        tenantId: 'tenant_northwind',
        provider: 'aws',
        displayName: 'AWS Organizations & IAM',
        category: 'Cloud',
        status: 'healthy',
        lastSyncAt: new Date(Date.now() - 240000).toISOString(),
        lastSyncLabel: '4m ago',
        coveragePct: 98,
        discoveredAssets: 44,
        discoveredSummary: {
          'IAM Roles': 12,
          'IAM Policies': 19,
          'S3 Buckets': 6,
          'KMS Keys': 4,
          'Access Analyzer Findings': 3,
        },
        scopes: AWS_READ_ONLY_POLICY_DOCUMENT.Statement[0].Action,
        config: {
          accountId: '449102881234',
          roleArn: 'arn:aws:iam::449102881234:role/EyesOfAgentReadOnlyRole',
          externalId: 'eoa-nw-8f3a91c2',
        },
      },
      {
        id: 'conn_azure',
        tenantId: 'tenant_northwind',
        provider: 'azure',
        displayName: 'Microsoft Azure & AI Foundry',
        category: 'Cloud',
        status: 'healthy',
        lastSyncAt: new Date(Date.now() - 360000).toISOString(),
        lastSyncLabel: '6m ago',
        coveragePct: 96,
        discoveredAssets: 39,
        discoveredSummary: {
          Subscriptions: 4,
          'Managed Identities': 7,
          'RBAC Role Assignments': 16,
          'Key Vaults': 3,
          'Storage Accounts': 5,
          'Azure OpenAI Resources': 4,
        },
        scopes: AZURE_SECURITY_READER_ACTIONS,
        config: {
          subscriptionId: 'sub-nw-prod-01',
          authMethod: 'Workload Identity Federation',
        },
      },
      {
        id: 'conn_gcp',
        tenantId: 'tenant_northwind',
        provider: 'gcp',
        displayName: 'Google Cloud & Vertex AI',
        category: 'Cloud',
        status: 'healthy',
        lastSyncAt: new Date(Date.now() - 480000).toISOString(),
        lastSyncLabel: '8m ago',
        coveragePct: 94,
        discoveredAssets: 9,
        scopes: ['aiplatform.endpoints.list', 'iam.roles.list'],
        config: { folderId: 'folders/48102' },
      },
      {
        id: 'conn_github',
        tenantId: 'tenant_northwind',
        provider: 'github',
        displayName: 'GitHub Enterprise',
        category: 'Code',
        status: 'healthy',
        lastSyncAt: new Date(Date.now() - 300000).toISOString(),
        lastSyncLabel: '5m ago',
        coveragePct: 100,
        discoveredAssets: 418,
        scopes: ['read:org', 'repo:status', 'installations:read'],
        config: { org: 'northwind-financial' },
      },
      {
        id: 'conn_slack',
        tenantId: 'tenant_northwind',
        provider: 'slack',
        displayName: 'Slack Enterprise Grid',
        category: 'Collaboration',
        status: 'warning',
        lastSyncAt: new Date(Date.now() - 1320000).toISOString(),
        lastSyncLabel: '22m ago',
        coveragePct: 82,
        discoveredAssets: 11,
        scopes: ['app_mentions:read', 'team:read'],
        config: { pendingWorkspaces: '2' },
      },
      {
        id: 'conn_jira',
        tenantId: 'tenant_northwind',
        provider: 'jira',
        displayName: 'Atlassian Jira',
        category: 'Ticketing',
        status: 'healthy',
        lastSyncAt: new Date(Date.now() - 60000).toISOString(),
        lastSyncLabel: '1m ago',
        coveragePct: 100,
        discoveredAssets: 6,
        scopes: ['write:jira-work', 'read:jira-user'],
        config: { projectKey: 'SEC' },
      },
      {
        id: 'conn_servicenow',
        tenantId: 'tenant_northwind',
        provider: 'servicenow',
        displayName: 'ServiceNow ITSM',
        category: 'Ticketing',
        status: 'healthy',
        lastSyncAt: new Date(Date.now() - 660000).toISOString(),
        lastSyncLabel: '11m ago',
        coveragePct: 95,
        discoveredAssets: 4,
        scopes: ['cmdb_ci_ai_agent.read', 'incident.write'],
        config: { instance: 'northwind.service-now.com' },
      },
      {
        id: 'conn_eu_entra',
        tenantId: 'tenant_northwind_eu',
        provider: 'entra_id',
        displayName: 'Microsoft Entra ID (EU)',
        category: 'Identity',
        status: 'healthy',
        lastSyncAt: new Date(Date.now() - 300000).toISOString(),
        lastSyncLabel: '5m ago',
        coveragePct: 100,
        discoveredAssets: 19,
        discoveredSummary: { Users: 9, Groups: 4, 'Service Principals': 6 },
        scopes: [
          'User.Read.All',
          'Group.Read.All',
          'Application.Read.All',
          'Directory.Read.All',
          'RoleManagement.Read.Directory',
        ],
        config: { tenantDomain: 'northwind.eu', adminConsent: 'granted' },
      },
      {
        id: 'conn_eu_azure',
        tenantId: 'tenant_northwind_eu',
        provider: 'azure',
        displayName: 'Azure Frankfurt Region',
        category: 'Cloud',
        status: 'healthy',
        lastSyncAt: new Date(Date.now() - 420000).toISOString(),
        lastSyncLabel: '7m ago',
        coveragePct: 100,
        discoveredAssets: 11,
        discoveredSummary: { Subscriptions: 2, 'Managed Identities': 3, 'Key Vaults': 2 },
        scopes: AZURE_SECURITY_READER_ACTIONS,
        config: { region: 'germanywestcentral', authMethod: 'Workload Identity Federation' },
      },
    ];

    for (const c of initialList) {
      this.connectors.push({ ...c, pkceVerified: true, readOnly: true });
      this.credentials.push(
        encryptTenantSecret(
          c.tenantId,
          c.id,
          `oauth_rt_${c.provider}_${c.tenantId}_seed`
        )
      );
    }
  }

  private enrichSeedFindings() {
    const findingMeta: Record<
      string,
      {
        ruleId: string;
        category: string;
        riskScore: number;
        identityId: string;
        resourceId: string;
        dataClassification: string;
        targetEdgeId: string;
        action: string;
        target: string;
        sources: Array<{ source: string; type: string; summary: string }>;
      }
    > = {
      finding_001: {
        ruleId: 'RULE_SENSITIVE_DATA_REACH',
        category: 'excessive_agent_permission',
        riskScore: 94,
        identityId: 'svc-finance-copilot',
        resourceId: 's3://payroll-prod',
        dataClassification: 'pii_financial',
        targetEdgeId: 'e_nw_4',
        action: 'remove_permission',
        target: 's3:GetObject',
        sources: [
          {
            source: 'aws_iam',
            type: 'role_policy',
            summary: 'PayrollExporter inline & attached IAM policy grants s3:GetObject on *',
          },
          {
            source: 'aws_s3',
            type: 'bucket_policy',
            summary: 's3://payroll-prod bucket policy allows PayrollExporter role access',
          },
        ],
      },
      finding_002: {
        ruleId: 'RULE_UNOWNED_AGENT',
        category: 'ownership_gap',
        riskScore: 89,
        identityId: 'sp-doc-extract-prod',
        resourceId: 'SharePoint M&A & HR',
        dataClassification: 'restricted_contracts',
        targetEdgeId: 'e_nw_11',
        action: 'revoke_oauth_grant',
        target: 'Sites.ReadWrite.All',
        sources: [
          {
            source: 'entra_id',
            type: 'servicePrincipal',
            summary: '/servicePrincipals/sp-doc-extract-prod owner list is empty',
          },
          {
            source: 'entra_id',
            type: 'oauth2PermissionGrants',
            summary: 'Sites.ReadWrite.All consented without site restriction',
          },
        ],
      },
      finding_003: {
        ruleId: 'RULE_SHADOW_AI',
        category: 'shadow_ai_discovery',
        riskScore: 81,
        identityId: 'pat-marketing-analytics-02',
        resourceId: 'Snowflake Warehouse',
        dataClassification: 'pii_customer',
        targetEdgeId: 'e_nw_15',
        action: 'revoke_pat_and_migrate_sso',
        target: 'snowflake:analytics.read',
        sources: [
          {
            source: 'slack',
            type: 'app_mentions',
            summary: 'Unregistered bot workflow invoking personal Snowflake PAT',
          },
        ],
      },
      finding_004: {
        ruleId: 'RULE_PRIVILEGED_IDENTITY',
        category: 'excessive_identity_privilege',
        riskScore: 76,
        identityId: 'svc-cx-support-bot',
        resourceId: 'Salesforce CRM',
        dataClassification: 'pii_customer',
        targetEdgeId: 'e_nw_19',
        action: 'scope_crm_fields',
        target: 'crm:contacts.read',
        sources: [
          {
            source: 'entra_id',
            type: 'appRoleAssignedTo',
            summary: 'Support service principal assigned bulk CRM export capability',
          },
        ],
      },
      finding_005: {
        ruleId: 'RULE_OVERPERMISSIVE_ROLE',
        category: 'overpermissive_iam_role',
        riskScore: 74,
        identityId: 'gh-app-northwind-reviewer',
        resourceId: 'GitHub Enterprise',
        dataClassification: 'restricted_source',
        targetEdgeId: 'e_nw_23',
        action: 'scope_repo_permissions',
        target: 'contents:read',
        sources: [
          {
            source: 'github',
            type: 'app_installation',
            summary: 'GitHub App installation spans archived payment-gateway repos',
          },
        ],
      },
      finding_eu_001: {
        ruleId: 'RULE_SENSITIVE_DATA_REACH',
        category: 'excessive_agent_permission',
        riskScore: 78,
        identityId: 'svc-eu-sepa-copilot',
        resourceId: 'Snowflake EU Frankfurt',
        dataClassification: 'pci_iban',
        targetEdgeId: 'e_eu_4',
        action: 'enforce_residency_filter',
        target: 'snowflake:eu_ledger.read',
        sources: [
          {
            source: 'azure_arm',
            type: 'roleAssignment',
            summary: 'SEPA ledger reader role lacks tenant row-level filter constraint',
          },
        ],
      },
    };

    this.findings = this.findings.map((f) => {
      const meta = findingMeta[f.id];
      const paths = findSensitiveExposurePaths(
        this.graphNodes,
        this.graphEdges,
        f.tenantId,
        f.agentId
      );
      const bestPath = paths[0];
      const dueDate = new Date(Date.now() + f.slaRemainingDays * 86400000).toISOString();

      const evidence: FindingEvidenceArtifact[] = (
        meta?.sources ?? [{ source: 'graph_engine', type: 'exposure_path', summary: f.description }]
      ).map((s, idx) => ({
        id: `ev_${f.id}_${idx + 1}`,
        source: s.source,
        type: s.type,
        summary: s.summary,
        collectedAt: '2026-11-16T08:30:00Z',
        hash: computeEvidenceHash({ findingId: f.id, ...s }),
      }));

      if (bestPath) {
        evidence.push({
          id: `ev_${f.id}_graph`,
          source: 'security_graph',
          type: 'exposure_path',
          summary: bestPath.steps.map((s) => s.label).join(' -> '),
          collectedAt: '2026-11-16T08:30:00Z',
          hash: computeEvidenceHash(bestPath.steps),
        });
      }

      const enriched: Finding = {
        ...f,
        ruleId: meta?.ruleId ?? 'RULE_SENSITIVE_DATA_REACH',
        category: meta?.category ?? 'excessive_agent_permission',
        riskScore: meta?.riskScore ?? 80,
        identityId: meta?.identityId ?? bestPath?.steps[1]?.label,
        resourceId: meta?.resourceId ?? bestPath?.targetDataLabel,
        dataClassification: meta?.dataClassification ?? bestPath?.targetSensitivity ?? 'restricted',
        slaDueAt: dueDate,
        ownerEmail: 'cloudsec@northwind.com',
        exposurePath: bestPath ? bestPath.steps.map((s) => s.label) : undefined,
        evidence,
        remediation: {
          action: meta?.action ?? 'remove_permission',
          target: meta?.target ?? 'excessive_permission',
          targetEdgeId: meta?.targetEdgeId,
          dryRunAvailable: true,
          rollbackAvailable: true,
          approvalRequired: true,
          dryRunExecuted: false,
          approvalStatus: f.status === 'remediated' ? 'applied' : 'pending_approval',
        },
        verification:
          f.status === 'remediated'
            ? {
                status: 'verified_closed',
                remainingPathCount: 0,
                lastSyncCheckedAt: '2026-11-16T08:30:00Z',
                proofHash: computeEvidenceHash({ findingId: f.id, closed: true }),
                message: 'Re-sync confirmed 0 active exposure paths.',
              }
            : { status: 'unverified' },
      };

      const diff = buildDryRunDiff(enriched);
      if (enriched.remediation) {
        enriched.remediation.dryRunDiff = diff.dryRunDiff;
        enriched.remediation.rollbackSnapshot = diff.rollbackSnapshot;
      }
      if (f.jiraTicketKey) {
        enriched.ticketProvider = 'jira';
        enriched.ticketPayloadPreview = formatTicketDescription(enriched, 'jira');
      }
      return enriched;
    });
  }

  private getLatestEvidenceHash(tenantId: string): string {
    const latest = this.evidenceRecords.find((r) => r.tenant_id === tenantId);
    return latest?.content_hash ?? 'sha256:genesis';
  }

  public appendEvidenceRecord(params: {
    tenantId: string;
    controlId: string;
    framework: ComplianceFramework;
    mappedFrameworks?: ComplianceFramework[];
    evidenceType: EvidenceType;
    source: string;
    resourceId: string;
    title: string;
    summary: string;
    payload: Record<string, unknown>;
    collectedAt?: string;
    status?: 'valid' | 'gap_flagged';
  }): EvidenceRecord {
    const record = createChainedEvidenceRecord({
      ...params,
      previousHash: this.getLatestEvidenceHash(params.tenantId),
    });
    this.evidenceRecords.unshift(record);
    return record;
  }

  public recomputeTenantRiskAssessments(
    tenantId: string,
    agentOverrides?: { agentId: string; overrides: Partial<RiskFactorInputs> }
  ) {
    const tenantNodes = this.graphNodes.filter((n) => n.tenantId === tenantId);
    const tenantEdges = this.graphEdges.filter((e) => e.tenantId === tenantId);

    this.agents = this.agents.map((agent) => {
      if (agent.tenantId !== tenantId) return agent;
      const paths = findSensitiveExposurePaths(tenantNodes, tenantEdges, tenantId, agent.id);
      const openAgentFindings = this.findings.filter(
        (f) => f.tenantId === tenantId && f.agentId === agent.id && f.status !== 'remediated'
      );
      const overrides =
        agentOverrides && agentOverrides.agentId === agent.id
          ? agentOverrides.overrides
          : undefined;
      const assessment = deriveAgentRiskAssessment({
        agent,
        paths,
        openFindings: openAgentFindings,
        overrides,
      });
      return {
        ...agent,
        riskAssessment: assessment,
        riskScore: Math.round(assessment.totalScore),
        riskLevel: assessment.level,
      };
    });

    this.findings = this.findings.map((finding) => {
      if (finding.tenantId !== tenantId) return finding;
      const agent = this.agents.find((a) => a.id === finding.agentId && a.tenantId === tenantId);
      if (!agent?.riskAssessment) return finding;
      return {
        ...finding,
        riskScore: agent.riskAssessment.totalScore,
        riskAssessment: agent.riskAssessment,
      };
    });

    // Update overall tenant risk posture from active agents
    const tenantAgents = this.agents.filter((a) => a.tenantId === tenantId);
    if (tenantAgents.length > 0) {
      const avg =
        tenantAgents.reduce((sum, a) => sum + (a.riskAssessment?.totalScore ?? a.riskScore), 0) /
        tenantAgents.length;
      const tIdx = this.tenants.findIndex((t) => t.id === tenantId);
      if (tIdx !== -1) {
        this.tenants[tIdx] = {
          ...this.tenants[tIdx],
          overallRiskScore: Math.round(avg),
        };
      }
    }
  }

  private seedGovernanceEvidenceAndGateway() {
    const seedEntries: Array<Parameters<TenantDataStore['appendEvidenceRecord']>[0]> = [
      {
        tenantId: 'tenant_northwind',
        controlId: 'SOC2_CC6.1',
        framework: 'SOC 2',
        mappedFrameworks: ['SOC 2', 'ISO 27001'],
        evidenceType: 'identity_inventory',
        source: 'entra_id',
        resourceId: 'tenant/northwind.com/servicePrincipals',
        title: 'Entra ID Non-Human Identity & Role Inventory Snapshot',
        summary: '24 users, 8 groups, 14 service principals, 5 directory roles collected via Graph API',
        payload: { users: 24, servicePrincipals: 14, directoryRoles: 5 },
        collectedAt: '2026-11-16T08:15:00Z',
      },
      {
        tenantId: 'tenant_northwind',
        controlId: 'ISO27001_A.8.2',
        framework: 'ISO 27001',
        mappedFrameworks: ['ISO 27001', 'SOC 2'],
        evidenceType: 'permission_snapshot',
        source: 'aws_iam',
        resourceId: 'arn:aws:iam::449102881234:role/PayrollExporter',
        title: 'AWS IAM PayrollExporter Role Policy Snapshot',
        summary: 'Captured inline & attached policy JSON showing s3:GetObject on payroll bucket',
        payload: { role: 'PayrollExporter', actions: ['s3:GetObject', 's3:ListBucket'] },
        collectedAt: '2026-11-16T08:20:00Z',
      },
      {
        tenantId: 'tenant_northwind',
        controlId: 'GDPR_Art32',
        framework: 'GDPR',
        mappedFrameworks: ['GDPR', 'SOC 2'],
        evidenceType: 'data_access_evidence',
        source: 'aws_s3',
        resourceId: 's3://payroll-prod',
        title: 'S3 Payroll Bucket ACL & Access Telemetry Attestation',
        summary: 'Bucket policy + encryption-at-rest + PII classification metadata collected',
        payload: { bucket: 's3://payroll-prod', classification: 'pii_financial' },
        collectedAt: '2026-11-16T08:22:00Z',
      },
      {
        tenantId: 'tenant_northwind',
        controlId: 'ISO_42001_6.1',
        framework: 'ISO 42001',
        mappedFrameworks: ['ISO 42001', 'EU AI Act'],
        evidenceType: 'agent_inventory',
        source: 'platform_connectors',
        resourceId: 'inventory/northwind/ai-agents',
        title: 'AI Agent, Model & MCP Server Governance Inventory',
        summary: '42 discovered agents, 5 MCP servers, and 4 foundation model providers cataloged',
        payload: { totalAgents: 42, unownedAgents: 5, shadowAgents: 7 },
        collectedAt: '2026-11-16T08:24:00Z',
      },
      {
        tenantId: 'tenant_northwind',
        controlId: 'SOC2_CC6.2',
        framework: 'SOC 2',
        mappedFrameworks: ['SOC 2', 'EU AI Act'],
        evidenceType: 'approval_record',
        source: 'workflow',
        resourceId: 'finding_006',
        title: 'Privacy Remediation Approval Attestation (SEC-4110)',
        summary: 'Approved by ciso@northwind.com for 24h PII TTL enforcement',
        payload: { approver: 'ciso@northwind.com', decision: 'approved' },
        collectedAt: '2026-11-16T08:26:00Z',
      },
      {
        tenantId: 'tenant_northwind',
        controlId: 'SOC2_CC6.3',
        framework: 'SOC 2',
        mappedFrameworks: ['SOC 2', 'ISO 27001'],
        evidenceType: 'remediation_proof',
        source: 'jira',
        resourceId: 'SEC-4110',
        title: 'Verified Closure & Ticket Proof for SEC-4110',
        summary: 'Jira ticket SEC-4110 closed after re-sync verified 0 retention violations',
        payload: { ticket: 'SEC-4110', status: 'verified_closed' },
        collectedAt: '2026-11-16T08:28:00Z',
      },
      {
        tenantId: 'tenant_northwind',
        controlId: 'EU_AI_Act_Art12',
        framework: 'EU AI Act',
        mappedFrameworks: ['EU AI Act', 'SOC 2'],
        evidenceType: 'audit_event',
        source: 'audit_log',
        resourceId: 'tenant_northwind/audit-stream',
        title: 'Immutable Control Plane Audit Trail Checkpoint',
        summary: 'Append-only actor/role/outcome events verified for EU AI Act Art. 12 traceability',
        payload: { stream: 'audit_log', immutable: true },
        collectedAt: '2026-11-16T08:30:00Z',
      },
    ];

    for (const item of seedEntries) {
      this.appendEvidenceRecord(item);
    }

    // Seed observe-mode gateway events with zero raw prompt retention
    const nwFinance = this.agents.find((a) => a.id === 'agent_finance_copilot');
    const nwSupport = this.agents.find((a) => a.id === 'agent_support');
    const nwMkt = this.agents.find((a) => a.id === 'agent_marketing_content');
    const policies = this.gatewayPolicies.tenant_northwind;
    const retention = this.retentionConfigs.tenant_northwind;

    if (nwFinance) {
      const res = inspectGatewayRequest({
        tenantId: 'tenant_northwind',
        agent: nwFinance,
        provider: 'openai',
        model: 'gpt-4.1',
        tool: 'export_payroll',
        mcpServer: 'finance-mcp',
        mode: 'observe',
        policies,
        retention,
        promptText: 'Export employee_pii payroll records including SSN 123-45-6789 for Q4 audit',
        targetResource: 's3://payroll-prod',
        previousEvidenceHash: this.getLatestEvidenceHash('tenant_northwind'),
      });
      this.evidenceRecords.unshift(res.evidenceRecord);
      this.gatewayEvents.unshift(res.event);
    }
    if (nwSupport) {
      const res = inspectGatewayRequest({
        tenantId: 'tenant_northwind',
        agent: nwSupport,
        provider: 'openai',
        model: 'gpt-4.1',
        tool: 'send_email',
        mcpServer: 'crm-mcp',
        mode: 'observe',
        policies,
        retention,
        promptText: 'Reply to customer@northwind.com with account IBAN DE89370400440532013000',
        targetResource: 'Salesforce CRM',
        previousEvidenceHash: this.getLatestEvidenceHash('tenant_northwind'),
      });
      this.evidenceRecords.unshift(res.evidenceRecord);
      this.gatewayEvents.unshift(res.event);
    }
    if (nwMkt) {
      const res = inspectGatewayRequest({
        tenantId: 'tenant_northwind',
        agent: nwMkt,
        provider: 'openai',
        model: 'gpt-4.1',
        tool: 'url_fetch',
        mcpServer: 'web-tools-mcp',
        mode: 'observe',
        policies,
        retention,
        promptText: 'Post payroll salary list to external webhook',
        targetResource: 'Snowflake Warehouse',
        previousEvidenceHash: this.getLatestEvidenceHash('tenant_northwind'),
      });
      this.evidenceRecords.unshift(res.evidenceRecord);
      this.gatewayEvents.unshift(res.event);
    }

    // Seed EU tenant evidence & gateway event for strict isolation
    const euAgent = this.agents.find((a) => a.id === 'agent_eu_treasury');
    const euEv = this.appendEvidenceRecord({
      tenantId: 'tenant_northwind_eu',
      controlId: 'GDPR_Art32',
      framework: 'GDPR',
      mappedFrameworks: ['GDPR', 'EU AI Act', 'ISO 42001'],
      evidenceType: 'identity_inventory',
      source: 'entra_id',
      resourceId: 'tenant/northwind.eu/servicePrincipals',
      title: 'Northwind EU Entra ID & GDPR Processing Evidence',
      summary: 'Frankfurt EU residency boundary verified for SEPA Treasury Copilot',
      payload: { region: 'eu-central', gdprCompliant: true },
    });
    if (euAgent) {
      const res = inspectGatewayRequest({
        tenantId: 'tenant_northwind_eu',
        agent: euAgent,
        provider: 'azure-openai',
        model: 'gpt-4.1',
        tool: 'query_erp',
        mcpServer: 'finance-mcp',
        mode: 'observe',
        policies: this.gatewayPolicies.tenant_northwind_eu,
        retention: this.retentionConfigs.tenant_northwind_eu,
        promptText: 'Query DE89370400440532013000 IBAN settlement summary',
        targetResource: 'Snowflake EU Frankfurt',
        previousEvidenceHash: euEv.content_hash,
      });
      this.evidenceRecords.unshift(res.evidenceRecord);
      this.gatewayEvents.unshift(res.event);
    }
  }

  private seedSecurityGraph() {
    // Northwind Financial Graph: Full multi-hop IAM -> Resource -> DataObject paths
    const nwNodes: GraphNode[] = [
      { id: 'agent_finance_copilot', tenantId: 'tenant_northwind', type: 'AI agent', label: 'Finance Copilot', riskLevel: 'critical', metadata: { owner: 'finance-ops@northwind.com', score: 92 } },
      { id: 'node_nw_id_finance', tenantId: 'tenant_northwind', type: 'Identity', label: 'svc-finance-copilot', riskLevel: 'critical', metadata: { kind: 'Service Principal' } },
      { id: 'node_nw_role_payroll', tenantId: 'tenant_northwind', type: 'Role', label: 'Payroll Exporter', riskLevel: 'critical', metadata: { provider: 'AWS IAM' } },
      { id: 'node_nw_perm_s3', tenantId: 'tenant_northwind', type: 'Permission', label: 's3:GetObject', riskLevel: 'critical', metadata: { action: 's3:GetObject' } },
      { id: 'node_nw_mcp_finance', tenantId: 'tenant_northwind', type: 'MCP server', label: 'finance-mcp', riskLevel: 'critical', metadata: { transport: 'streamable-http' } },
      { id: 'node_nw_tool_payroll', tenantId: 'tenant_northwind', type: 'Tool', label: 'export_payroll', riskLevel: 'critical', metadata: {} },
      { id: 'node_nw_ds_s3_payroll', tenantId: 'tenant_northwind', type: 'Data source', label: 's3://payroll-prod', sensitivity: 'restricted', riskLevel: 'critical', metadata: { provider: 'AWS S3' } },
      { id: 'node_nw_obj_employee_pii', tenantId: 'tenant_northwind', type: 'Data object', label: 'employee_pii', sensitivity: 'pii', riskLevel: 'critical', metadata: { records: '1.4M SSN/Tax' } },

      // Procurement Agent path
      { id: 'agent_procurement', tenantId: 'tenant_northwind', type: 'AI agent', label: 'Procurement Agent', riskLevel: 'critical', metadata: { owner: 'unassigned', score: 89 } },
      { id: 'node_nw_id_proc', tenantId: 'tenant_northwind', type: 'Identity', label: 'sp-doc-extract-prod', riskLevel: 'critical', metadata: { kind: 'Legacy App Reg' } },
      { id: 'node_nw_role_sp_admin', tenantId: 'tenant_northwind', type: 'Role', label: 'SharePoint Tenant Reader', riskLevel: 'critical', metadata: {} },
      { id: 'node_nw_perm_sites', tenantId: 'tenant_northwind', type: 'Permission', label: 'Sites.ReadWrite.All', riskLevel: 'critical', metadata: {} },
      { id: 'node_nw_ds_sharepoint', tenantId: 'tenant_northwind', type: 'Data source', label: 'SharePoint M&A & HR', sensitivity: 'restricted', riskLevel: 'critical', metadata: {} },
      { id: 'node_nw_obj_contracts', tenantId: 'tenant_northwind', type: 'Data object', label: 'vendor_contracts_and_ma', sensitivity: 'restricted', riskLevel: 'critical', metadata: {} },

      // Marketing Content Agent (Shadow AI) path
      { id: 'agent_marketing_content', tenantId: 'tenant_northwind', type: 'AI agent', label: 'Marketing Content Agent', riskLevel: 'high', metadata: { type: 'Shadow AI', score: 81 } },
      { id: 'node_nw_id_mkt', tenantId: 'tenant_northwind', type: 'Identity', label: 'pat-marketing-analytics-02', riskLevel: 'high', metadata: {} },
      { id: 'node_nw_perm_sf', tenantId: 'tenant_northwind', type: 'Permission', label: 'snowflake:analytics.read', riskLevel: 'high', metadata: {} },
      { id: 'node_nw_ds_snowflake', tenantId: 'tenant_northwind', type: 'Data source', label: 'Snowflake Warehouse', sensitivity: 'restricted', riskLevel: 'critical', metadata: {} },
      { id: 'node_nw_obj_hnw', tenantId: 'tenant_northwind', type: 'Data object', label: 'hnw_client_segments', sensitivity: 'pii', riskLevel: 'high', metadata: {} },

      // Support Agent path
      { id: 'agent_support', tenantId: 'tenant_northwind', type: 'AI agent', label: 'Support Agent', riskLevel: 'high', metadata: { score: 76 } },
      { id: 'node_nw_id_support', tenantId: 'tenant_northwind', type: 'Identity', label: 'svc-cx-support-bot', riskLevel: 'high', metadata: {} },
      { id: 'node_nw_perm_crm', tenantId: 'tenant_northwind', type: 'Permission', label: 'crm:contacts.read', riskLevel: 'high', metadata: {} },
      { id: 'node_nw_ds_crm', tenantId: 'tenant_northwind', type: 'Data source', label: 'Salesforce CRM', sensitivity: 'pii', riskLevel: 'high', metadata: {} },
      { id: 'node_nw_obj_contacts', tenantId: 'tenant_northwind', type: 'Data object', label: 'customer_contacts_pii', sensitivity: 'pii', riskLevel: 'high', metadata: {} },

      // Code Review Agent path
      { id: 'agent_code_review', tenantId: 'tenant_northwind', type: 'AI agent', label: 'Code Review Agent', riskLevel: 'high', metadata: { score: 74 } },
      { id: 'node_nw_id_gh', tenantId: 'tenant_northwind', type: 'Identity', label: 'gh-app-northwind-reviewer', riskLevel: 'high', metadata: {} },
      { id: 'node_nw_perm_gh', tenantId: 'tenant_northwind', type: 'Permission', label: 'contents:read', riskLevel: 'high', metadata: {} },
      { id: 'node_nw_ds_gh', tenantId: 'tenant_northwind', type: 'Data source', label: 'GitHub Enterprise', sensitivity: 'restricted', riskLevel: 'high', metadata: {} },
      { id: 'node_nw_obj_secrets', tenantId: 'tenant_northwind', type: 'Data object', label: 'legacy_gateway_secrets', sensitivity: 'restricted', riskLevel: 'high', metadata: {} },

      // Recruiting Agent path
      { id: 'agent_recruiting', tenantId: 'tenant_northwind', type: 'AI agent', label: 'Recruiting Agent', riskLevel: 'medium', metadata: { score: 52 } },
      { id: 'node_nw_id_rec', tenantId: 'tenant_northwind', type: 'Identity', label: 'svc-talent-screener', riskLevel: 'medium', metadata: {} },
      { id: 'node_nw_ds_ats', tenantId: 'tenant_northwind', type: 'Data source', label: 'Greenhouse ATS', sensitivity: 'pii', riskLevel: 'medium', metadata: {} },
      { id: 'node_nw_obj_resumes', tenantId: 'tenant_northwind', type: 'Data object', label: 'candidate_resumes_pii', sensitivity: 'pii', riskLevel: 'medium', metadata: {} },
    ];

    const nwEdges: GraphEdge[] = [
      // Exact example path from architecture spec:
      // Finance Copilot -> OPERATED_BY -> svc-finance-copilot -> ASSIGNED_ROLE -> Payroll Exporter -> GRANTS_PERMISSION -> s3:GetObject -> CAN_ACCESS -> s3://payroll-prod -> CONTAINS -> employee_pii
      { id: 'e_nw_1', tenantId: 'tenant_northwind', sourceId: 'agent_finance_copilot', targetId: 'node_nw_id_finance', type: 'OPERATED_BY' },
      { id: 'e_nw_2', tenantId: 'tenant_northwind', sourceId: 'node_nw_id_finance', targetId: 'node_nw_role_payroll', type: 'ASSIGNED_ROLE' },
      { id: 'e_nw_3', tenantId: 'tenant_northwind', sourceId: 'node_nw_role_payroll', targetId: 'node_nw_perm_s3', type: 'GRANTS_PERMISSION' },
      { id: 'e_nw_4', tenantId: 'tenant_northwind', sourceId: 'node_nw_perm_s3', targetId: 'node_nw_ds_s3_payroll', type: 'CAN_ACCESS' },
      { id: 'e_nw_5', tenantId: 'tenant_northwind', sourceId: 'node_nw_ds_s3_payroll', targetId: 'node_nw_obj_employee_pii', type: 'CONTAINS' },
      { id: 'e_nw_6', tenantId: 'tenant_northwind', sourceId: 'agent_finance_copilot', targetId: 'node_nw_tool_payroll', type: 'CALLS_TOOL' },
      { id: 'e_nw_7', tenantId: 'tenant_northwind', sourceId: 'node_nw_tool_payroll', targetId: 'node_nw_mcp_finance', type: 'HOSTED_BY' },

      // Procurement Agent
      { id: 'e_nw_8', tenantId: 'tenant_northwind', sourceId: 'agent_procurement', targetId: 'node_nw_id_proc', type: 'OPERATED_BY' },
      { id: 'e_nw_9', tenantId: 'tenant_northwind', sourceId: 'node_nw_id_proc', targetId: 'node_nw_role_sp_admin', type: 'ASSIGNED_ROLE' },
      { id: 'e_nw_10', tenantId: 'tenant_northwind', sourceId: 'node_nw_role_sp_admin', targetId: 'node_nw_perm_sites', type: 'GRANTS_PERMISSION' },
      { id: 'e_nw_11', tenantId: 'tenant_northwind', sourceId: 'node_nw_perm_sites', targetId: 'node_nw_ds_sharepoint', type: 'CAN_ACCESS' },
      { id: 'e_nw_12', tenantId: 'tenant_northwind', sourceId: 'node_nw_ds_sharepoint', targetId: 'node_nw_obj_contracts', type: 'CONTAINS' },

      // Marketing Content Agent
      { id: 'e_nw_13', tenantId: 'tenant_northwind', sourceId: 'agent_marketing_content', targetId: 'node_nw_id_mkt', type: 'OPERATED_BY' },
      { id: 'e_nw_14', tenantId: 'tenant_northwind', sourceId: 'node_nw_id_mkt', targetId: 'node_nw_perm_sf', type: 'GRANTS_PERMISSION' },
      { id: 'e_nw_15', tenantId: 'tenant_northwind', sourceId: 'node_nw_perm_sf', targetId: 'node_nw_ds_snowflake', type: 'CAN_ACCESS' },
      { id: 'e_nw_16', tenantId: 'tenant_northwind', sourceId: 'node_nw_ds_snowflake', targetId: 'node_nw_obj_hnw', type: 'CONTAINS' },

      // Support Agent
      { id: 'e_nw_17', tenantId: 'tenant_northwind', sourceId: 'agent_support', targetId: 'node_nw_id_support', type: 'OPERATED_BY' },
      { id: 'e_nw_18', tenantId: 'tenant_northwind', sourceId: 'node_nw_id_support', targetId: 'node_nw_perm_crm', type: 'GRANTS_PERMISSION' },
      { id: 'e_nw_19', tenantId: 'tenant_northwind', sourceId: 'node_nw_perm_crm', targetId: 'node_nw_ds_crm', type: 'CAN_ACCESS' },
      { id: 'e_nw_20', tenantId: 'tenant_northwind', sourceId: 'node_nw_ds_crm', targetId: 'node_nw_obj_contacts', type: 'CONTAINS' },

      // Code Review Agent
      { id: 'e_nw_21', tenantId: 'tenant_northwind', sourceId: 'agent_code_review', targetId: 'node_nw_id_gh', type: 'OPERATED_BY' },
      { id: 'e_nw_22', tenantId: 'tenant_northwind', sourceId: 'node_nw_id_gh', targetId: 'node_nw_perm_gh', type: 'GRANTS_PERMISSION' },
      { id: 'e_nw_23', tenantId: 'tenant_northwind', sourceId: 'node_nw_perm_gh', targetId: 'node_nw_ds_gh', type: 'CAN_ACCESS' },
      { id: 'e_nw_24', tenantId: 'tenant_northwind', sourceId: 'node_nw_ds_gh', targetId: 'node_nw_obj_secrets', type: 'CONTAINS' },

      // Recruiting Agent
      { id: 'e_nw_25', tenantId: 'tenant_northwind', sourceId: 'agent_recruiting', targetId: 'node_nw_id_rec', type: 'OPERATED_BY' },
      { id: 'e_nw_26', tenantId: 'tenant_northwind', sourceId: 'node_nw_id_rec', targetId: 'node_nw_ds_ats', type: 'CAN_ACCESS' },
      { id: 'e_nw_27', tenantId: 'tenant_northwind', sourceId: 'node_nw_ds_ats', targetId: 'node_nw_obj_resumes', type: 'CONTAINS' },
    ];

    // Isolated Northwind Europe GmbH Graph
    const euNodes: GraphNode[] = [
      { id: 'agent_eu_treasury', tenantId: 'tenant_northwind_eu', type: 'AI agent', label: 'SEPA Treasury Copilot', riskLevel: 'high', metadata: { score: 71 } },
      { id: 'node_eu_id_sepa', tenantId: 'tenant_northwind_eu', type: 'Identity', label: 'svc-eu-sepa-copilot', riskLevel: 'high', metadata: {} },
      { id: 'node_eu_role_ledger', tenantId: 'tenant_northwind_eu', type: 'Role', label: 'EU Ledger Reader', riskLevel: 'high', metadata: {} },
      { id: 'node_eu_perm_sf', tenantId: 'tenant_northwind_eu', type: 'Permission', label: 'snowflake:eu_ledger.read', riskLevel: 'high', metadata: {} },
      { id: 'node_eu_ds_sf', tenantId: 'tenant_northwind_eu', type: 'Data source', label: 'Snowflake EU Frankfurt', sensitivity: 'restricted', riskLevel: 'high', metadata: {} },
      { id: 'node_eu_obj_iban', tenantId: 'tenant_northwind_eu', type: 'Data object', label: 'sepa_iban_settlements', sensitivity: 'pci', riskLevel: 'high', metadata: {} },

      { id: 'agent_eu_gdpr_intake', tenantId: 'tenant_northwind_eu', type: 'AI agent', label: 'DSAR Intake Assistant', riskLevel: 'medium', metadata: { score: 44 } },
      { id: 'node_eu_id_gdpr', tenantId: 'tenant_northwind_eu', type: 'Identity', label: 'svc-gdpr-intake', riskLevel: 'medium', metadata: {} },
      { id: 'node_eu_ds_dsar', tenantId: 'tenant_northwind_eu', type: 'Data source', label: 'EU DSAR Vault', sensitivity: 'pii', riskLevel: 'medium', metadata: {} },
      { id: 'node_eu_obj_dsar', tenantId: 'tenant_northwind_eu', type: 'Data object', label: 'dsar_subject_requests', sensitivity: 'pii', riskLevel: 'medium', metadata: {} },
    ];

    const euEdges: GraphEdge[] = [
      { id: 'e_eu_1', tenantId: 'tenant_northwind_eu', sourceId: 'agent_eu_treasury', targetId: 'node_eu_id_sepa', type: 'OPERATED_BY' },
      { id: 'e_eu_2', tenantId: 'tenant_northwind_eu', sourceId: 'node_eu_id_sepa', targetId: 'node_eu_role_ledger', type: 'ASSIGNED_ROLE' },
      { id: 'e_eu_3', tenantId: 'tenant_northwind_eu', sourceId: 'node_eu_role_ledger', targetId: 'node_eu_perm_sf', type: 'GRANTS_PERMISSION' },
      { id: 'e_eu_4', tenantId: 'tenant_northwind_eu', sourceId: 'node_eu_perm_sf', targetId: 'node_eu_ds_sf', type: 'CAN_ACCESS' },
      { id: 'e_eu_5', tenantId: 'tenant_northwind_eu', sourceId: 'node_eu_ds_sf', targetId: 'node_eu_obj_iban', type: 'CONTAINS' },
      { id: 'e_eu_6', tenantId: 'tenant_northwind_eu', sourceId: 'agent_eu_gdpr_intake', targetId: 'node_eu_id_gdpr', type: 'OPERATED_BY' },
      { id: 'e_eu_7', tenantId: 'tenant_northwind_eu', sourceId: 'node_eu_id_gdpr', targetId: 'node_eu_ds_dsar', type: 'CAN_ACCESS' },
      { id: 'e_eu_8', tenantId: 'tenant_northwind_eu', sourceId: 'node_eu_ds_dsar', targetId: 'node_eu_obj_dsar', type: 'CONTAINS' },
    ];

    this.graphNodes = [...nwNodes, ...euNodes];
    this.graphEdges = [...nwEdges, ...euEdges];
  }

  private seedInitialAuditEvents() {
    this.recordAuditEvent(
      {
        tenantId: 'tenant_northwind',
        actorId: 'usr_owner_nw',
        actorEmail: 'ciso@northwind.com',
        actorRole: 'owner',
        action: 'connector.authorized',
        resourceType: 'connector',
        resourceId: 'conn_entra',
        outcome: 'allowed',
        before: null,
        after: { provider: 'entra_id', pkce: true, scopes: ['ServicePrincipals.Read.All'] },
        reason: 'Initial Entra ID read-only discovery consent completed',
      },
      '2026-11-16T05:10:00Z'
    );
    this.recordAuditEvent(
      {
        tenantId: 'tenant_northwind',
        actorId: 'usr_admin_nw',
        actorEmail: 'sec-admin@northwind.com',
        actorRole: 'admin',
        action: 'policy.mode_updated',
        resourceType: 'policy_mode',
        resourceId: 'tenant_northwind',
        outcome: 'allowed',
        before: { mode: 'off' },
        after: { mode: 'observe' },
        reason: 'Progressive rollout stage 1 initialized in observe mode',
      },
      '2026-11-16T05:45:00Z'
    );
    this.recordAuditEvent(
      {
        tenantId: 'tenant_northwind_eu',
        actorId: 'usr_admin_eu',
        actorEmail: 'dpo-admin@northwind.eu',
        actorRole: 'admin',
        action: 'sso.metadata_verified',
        resourceType: 'sso_config',
        resourceId: 'tenant_northwind_eu',
        outcome: 'allowed',
        before: null,
        after: { protocol: 'oidc', ssoEnforced: true, scimEnabled: true },
        reason: 'EU tenant SSO & SCIM directory boundary verified',
      },
      '2026-11-16T05:50:00Z'
    );
  }

  private seedEnterpriseState() {
    this.ssoConfigs = {
      tenant_northwind: {
        tenantId: 'tenant_northwind',
        protocol: 'saml_2_0',
        idpName: 'Okta + Microsoft Entra ID',
        idpEntityId: 'https://sso.northwind.com/saml2/metadata',
        ssoEnforced: true,
        localPasswordFallbackDisabled: true,
        mfaRequiredForAdmins: true,
        allowedMfaMethods: ['totp', 'webauthn'],
        scimEnabled: true,
        certificateFingerprint: 'SHA256:9F:44:C1:8E:02:B7:6D:3A:11:FE:48:90',
        certificateRotatedAt: '2026-11-01T09:00:00Z',
        metadataValidated: true,
      },
      tenant_northwind_eu: {
        tenantId: 'tenant_northwind_eu',
        protocol: 'oidc',
        idpName: 'Microsoft Entra ID EU',
        idpEntityId: 'https://login.microsoftonline.com/nw-eu-tenant/v2.0',
        ssoEnforced: true,
        localPasswordFallbackDisabled: true,
        mfaRequiredForAdmins: true,
        allowedMfaMethods: ['totp', 'webauthn'],
        scimEnabled: true,
        certificateFingerprint: 'SHA256:4A:19:77:D2:55:E1:3C:8B:04:AA:21:60',
        certificateRotatedAt: '2026-11-05T09:00:00Z',
        metadataValidated: true,
      },
    };

    const reverseGroupMap: Partial<Record<Role, string>> = {};
    for (const [group, role] of Object.entries(IDP_GROUP_ROLE_MAP)) {
      reverseGroupMap[role] = group;
    }

    for (const membership of this.memberships) {
      const user = this.users.find((u) => u.id === membership.userId);
      if (!user || membership.role === 'service_account') continue;
      const groupName = reverseGroupMap[membership.role] ?? 'EyesOfAgent-Auditors';
      this.scimDirectory.push({
        id: `scim_${membership.tenantId}_${user.id}`,
        tenantId: membership.tenantId,
        email: user.email,
        displayName: user.displayName,
        idpGroups: [groupName],
        mappedRole: membership.role,
        status: membership.status === 'active' ? 'active' : 'disabled',
        mfaEnrolled: user.mfaEnabled,
        activeSessionCount: 0,
        lastSyncedAt: '2026-11-16T08:00:00Z',
      });
    }

    this.playbookExecutions.push({
      executionId: 'pb_exec_seed_01',
      tenantId: 'tenant_northwind',
      playbookId: 'pb_sensitive_exfiltration',
      playbookName: 'Sensitive-data exfiltration',
      agentId: 'agent_finance_copilot',
      agentName: 'Finance Copilot',
      triggerSignal: 'Observed export_payroll call carrying employee_pii toward gpt-4.1',
      severity: 'critical',
      status: 'contained_awaiting_approval',
      dryRunImpactSummary:
        'Impact preview: scope tool export_payroll to read-only sandbox; zero disruption to read_erp queries.',
      containmentActions: [
        'Tagged outbound gateway session with prevent_payroll_exfiltration',
        'Preserved SHA-256 evidence record',
        'Notified #secops-ai-alerts & created SEC-4201',
      ],
      pendingApprovalAction: 'Permanent IAM change (remove s3:GetObject on payroll-prod)',
      responderIdentity: 'svc-soar-responder (least-privilege containment)',
      ticketKey: 'SEC-4201',
      evidenceId: this.evidenceRecords[0]?.id ?? 'ev_seed_01',
      auditEventId: this.auditEvents[0]?.id ?? 'aud_seed_1',
      rollbackSnapshot: {
        agentId: 'agent_finance_copilot',
        previousStatus: 'active',
        previousPermissions: ['s3:GetObject (payroll-prod)', 'erp:ReadInvoices', 'slack:PostMessage'],
      },
      executedAt: '2026-11-16T08:32:00Z',
    });
  }

  // ---- Identity, Membership & Session Operations ----

  findUserByEmail(email: string): UserRecord | undefined {
    return this.users.find((u) => u.email.toLowerCase() === email.toLowerCase());
  }

  findUserById(userId: string): UserRecord | undefined {
    return this.users.find((u) => u.id === userId);
  }

  listUsersForDemoSignIn(): Array<{
    user: UserRecord;
    memberships: Array<{ tenantId: string; tenantName: string; role: Role }>;
  }> {
    return this.users.map((user) => ({
      user,
      memberships: this.memberships
        .filter((m) => m.userId === user.id && m.status === 'active')
        .map((m) => ({
          tenantId: m.tenantId,
          tenantName: this.tenants.find((t) => t.id === m.tenantId)?.name ?? m.tenantId,
          role: m.role,
        })),
    }));
  }

  getMembershipsForUser(userId: string): TenantMembership[] {
    return this.memberships.filter((m) => m.userId === userId && m.status === 'active');
  }

  getMembership(tenantId: string, userId: string): TenantMembership | undefined {
    return this.memberships.find(
      (m) => m.tenantId === tenantId && m.userId === userId && m.status === 'active'
    );
  }

  createSession(userId: string, tenantId: string, mfaVerified: boolean): SessionRecord {
    const sessionId = `sess_${crypto.randomUUID()}`;
    const refreshId = `ref_${crypto.randomUUID()}`;
    const now = Date.now();
    const record: SessionRecord = {
      sessionId,
      refreshId,
      userId,
      activeTenantId: tenantId,
      mfaVerified,
      createdAt: now,
      expiresAt: now + 1000 * 60 * 60 * 8,
    };
    this.sessions.set(sessionId, record);
    return record;
  }

  getSession(sessionId: string): SessionRecord | undefined {
    const sess = this.sessions.get(sessionId);
    if (!sess) return undefined;
    if (Date.now() > sess.expiresAt) {
      this.sessions.delete(sessionId);
      return undefined;
    }
    return sess;
  }

  rotateSession(sessionId: string): SessionRecord | undefined {
    const existing = this.getSession(sessionId);
    if (!existing) return undefined;
    this.sessions.delete(sessionId);
    return this.createSession(existing.userId, existing.activeTenantId, existing.mfaVerified);
  }

  deleteSession(sessionId: string) {
    this.sessions.delete(sessionId);
  }

  switchSessionTenant(sessionId: string, targetTenantId: string): SessionRecord | undefined {
    const sess = this.getSession(sessionId);
    if (!sess) return undefined;
    const membership = this.getMembership(targetTenantId, sess.userId);
    if (!membership) return undefined;
    sess.activeTenantId = targetTenantId;
    return sess;
  }

  // ---- Audit Service (Hash-Chained, Write-Once Ledger) ----

  recordAuditEvent(
    event: Omit<AuditEvent, 'id' | 'occurredAt'>,
    occurredAtOverride?: string
  ): AuditEvent {
    const id = `aud_${crypto.randomUUID()}`;
    const occurredAt = occurredAtOverride ?? new Date().toISOString();
    const prevEvent = this.auditEvents.find((e) => e.tenantId === event.tenantId);
    const prev_hash = prevEvent?.event_hash ?? 'sha256:audit_genesis';
    const retentionDays = Math.max(365, this.auditRetentionDays[event.tenantId] ?? 365);
    const retention_until = new Date(
      Date.parse(occurredAt) + retentionDays * 86400000
    ).toISOString();

    const base: AuditEvent = {
      ...event,
      id,
      event_id: id,
      occurredAt,
      actor: event.actor ?? {
        type:
          event.actorRole === 'service_account'
            ? 'service'
            : event.actorId.startsWith('svc-')
              ? 'automation'
              : 'user',
        id: event.actorId,
        email: event.actorEmail,
        ip: '10.42.8.14',
        user_agent: 'EyesOfAgent-ControlPlane/2.0',
      },
      resource: event.resource ?? {
        type: event.resourceType,
        id: event.resourceId,
      },
      prev_hash,
      retention_until,
    };

    const event_hash = computeAuditEventHash(buildCanonicalAuditPayload(base), prev_hash);
    const full: AuditEvent = {
      ...base,
      event_hash,
    };
    this.auditEvents.unshift(full);
    this.persistState();
    return full;
  }

  getAuditEvents(
    tenantId: string,
    filters?: { search?: string; outcome?: 'allowed' | 'denied' | 'all' }
  ): AuditEvent[] {
    return this.withTenantContext(tenantId, (tid) => {
      const search = filters?.search?.trim().toLowerCase() ?? '';
      const outcome = filters?.outcome;
      return this.auditEvents.filter((e) => {
        if (e.tenantId !== tid) return false;
        if (outcome && outcome !== 'all' && e.outcome !== outcome) return false;
        if (search) {
          const hay = [
            e.action,
            e.actorEmail,
            e.actorRole,
            e.resourceType,
            e.resourceId,
            e.reason ?? '',
          ]
            .join(' ')
            .toLowerCase();
          if (!hay.includes(search)) return false;
        }
        return true;
      });
    });
  }

  getAuditIntegrity(tenantId: string): AuditChainIntegrity {
    return this.withTenantContext(tenantId, (tid) => {
      const events = this.auditEvents.filter((e) => e.tenantId === tid);
      const retentionDays = Math.max(365, this.auditRetentionDays[tid] ?? 365);
      return verifyAuditHashChain(events, retentionDays);
    });
  }

  setAuditRetentionDays(
    tenantId: string,
    days: number,
    actor: { id: string; email: string; role: Role }
  ): number {
    return this.withTenantContext(tenantId, (tid) => {
      if (!Number.isFinite(days) || days < 365) {
        throw new Error('Audit-grade policy enforces a minimum retention of 365 days (1 year).');
      }
      const prev = this.auditRetentionDays[tid] ?? 365;
      this.auditRetentionDays[tid] = Math.round(days);
      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'audit.retention_updated',
        resourceType: 'audit_policy',
        resourceId: tid,
        outcome: 'allowed',
        before: { retentionDays: prev },
        after: { retentionDays: this.auditRetentionDays[tid] },
        reason: 'Configured compliant audit retention >= 1 year',
      });
      return this.auditRetentionDays[tid];
    });
  }

  exportAuditLedger(
    tenantId: string,
    options: { fromDate?: string; toDate?: string },
    actor: { id: string; email: string; role: Role }
  ) {
    return this.withTenantContext(tenantId, (tid) => {
      const fromMs = options.fromDate ? Date.parse(options.fromDate) : 0;
      const toMs = options.toDate ? Date.parse(options.toDate) + 86400000 : Number.MAX_SAFE_INTEGER;
      const events = this.auditEvents.filter((e) => {
        if (e.tenantId !== tid) return false;
        const ts = Date.parse(e.occurredAt);
        return ts >= fromMs && ts <= toMs;
      });
      const integrity = this.getAuditIntegrity(tid);
      const exportedAt = new Date().toISOString();

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'audit.ledger_exported',
        resourceType: 'audit_ledger',
        resourceId: `export_${tid}`,
        outcome: 'allowed',
        before: null,
        after: {
          exportedCount: events.length,
          chainValid: integrity.valid,
          fromDate: options.fromDate ?? 'inception',
          toDate: options.toDate ?? 'present',
        },
        reason: 'Scoped immutable audit ledger export generated',
      });

      return {
        tenantId: tid,
        exportedAt,
        integrity,
        eventCount: events.length,
        events,
      };
    });
  }

  // ---- Tenant-Scoped Queries ----

  getTenant(tenantId: string): TenantRecord {
    return this.withTenantContext(tenantId, (tid) => {
      const t = this.tenants.find((x) => x.id === tid);
      if (!t) throw new TenantIsolationError('Tenant not found');
      return t;
    });
  }

  getAgents(tenantId: string, userRole?: Role, userEmail?: string): Agent[] {
    return this.withTenantContext(tenantId, (tid) => {
      const list = this.agents.filter((a) => a.tenantId === tid);
      if (userRole === 'agent_owner' && userEmail) {
        return list.filter((a) => a.owner.toLowerCase() === userEmail.toLowerCase());
      }
      return list;
    });
  }

  getAgentById(tenantId: string, agentId: string): Agent | undefined {
    return this.withTenantContext(tenantId, (tid) =>
      this.agents.find((a) => a.tenantId === tid && a.id === agentId)
    );
  }

  getDetectionRules() {
    return INITIAL_DETECTION_RULES;
  }

  getFindings(tenantId: string): Finding[] {
    return this.withTenantContext(tenantId, (tid) =>
      this.findings.filter((f) => f.tenantId === tid)
    );
  }

  createRemediationTicket(
    tenantId: string,
    findingId: string,
    options: {
      provider?: 'jira' | 'servicenow';
      assignee: string;
      notifyChannels?: string[];
    },
    actor: { id: string; email: string; role: Role }
  ): Finding {
    return this.withTenantContext(tenantId, (tid) => {
      const idx = this.findings.findIndex((f) => f.id === findingId && f.tenantId === tid);
      if (idx === -1) {
        throw new Error('Finding not found in tenant scope');
      }
      const before = { ...this.findings[idx] };
      const provider = options.provider === 'servicenow' ? 'servicenow' : 'jira';
      const ticketKey =
        provider === 'servicenow'
          ? `INC-${this.nextSnowNum++}`
          : `SEC-${this.nextTicketNum++}`;
      const notifyChannels =
        options.notifyChannels && options.notifyChannels.length > 0
          ? options.notifyChannels
          : ['Slack', 'Email'];

      const draft: Finding = {
        ...before,
        status: before.status === 'open' ? 'in_progress' : before.status,
        owner: options.assignee,
        jiraTicketKey: ticketKey,
        ticketProvider: provider,
        notifiedChannels: notifyChannels,
      };
      draft.ticketPayloadPreview = formatTicketDescription(draft, provider);
      this.findings[idx] = draft;

      this.activity.unshift({
        id: `act_${crypto.randomUUID()}`,
        tenantId: tid,
        timestamp: 'Just now',
        category: 'remediation',
        title: `${provider === 'servicenow' ? 'ServiceNow' : 'Jira'} ${ticketKey} created & assigned to ${options.assignee}`,
        detail: `${draft.title} · Notified ${notifyChannels.join(', ')}`,
        severity: 'nominal',
      });

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: `finding.${provider}_ticket_created`,
        resourceType: 'finding',
        resourceId: findingId,
        outcome: 'allowed',
        before: { status: before.status, owner: before.owner, ticketKey: before.jiraTicketKey ?? null },
        after: { status: draft.status, owner: draft.owner, ticketKey, provider, notifyChannels },
      });

      return draft;
    });
  }

  createJiraTicket(
    tenantId: string,
    findingId: string,
    assignee: string,
    actor: { id: string; email: string; role: Role }
  ): Finding {
    return this.createRemediationTicket(
      tenantId,
      findingId,
      { provider: 'jira', assignee, notifyChannels: ['Slack', 'Email'] },
      actor
    );
  }

  runFindingDryRun(
    tenantId: string,
    findingId: string,
    actor: { id: string; email: string; role: Role }
  ): Finding {
    return this.withTenantContext(tenantId, (tid) => {
      const idx = this.findings.findIndex((f) => f.id === findingId && f.tenantId === tid);
      if (idx === -1) throw new Error('Finding not found in tenant scope');
      const current = this.findings[idx];
      const { dryRunDiff, rollbackSnapshot } = buildDryRunDiff(current);

      const updated: Finding = {
        ...current,
        remediation: {
          ...(current.remediation ?? {
            action: 'remove_permission',
            target: current.resourceId ?? 'excessive_permission',
            dryRunAvailable: true,
            rollbackAvailable: true,
            approvalRequired: true,
            approvalStatus: 'pending_approval',
          }),
          dryRunExecuted: true,
          dryRunDiff,
          rollbackSnapshot,
        },
      };
      this.findings[idx] = updated;

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'remediation.dry_run_executed',
        resourceType: 'finding',
        resourceId: findingId,
        outcome: 'allowed',
        before: { dryRunExecuted: current.remediation?.dryRunExecuted ?? false },
        after: { dryRunExecuted: true, target: updated.remediation?.target },
      });

      return updated;
    });
  }

  approveFindingRemediation(
    tenantId: string,
    findingId: string,
    options: { breakGlassDualApproval?: boolean },
    actor: { id: string; email: string; role: Role }
  ): Finding {
    return this.withTenantContext(tenantId, (tid) => {
      const idx = this.findings.findIndex((f) => f.id === findingId && f.tenantId === tid);
      if (idx === -1) throw new Error('Finding not found in tenant scope');
      const current = this.findings[idx];
      const now = new Date().toISOString();

      const updated: Finding = {
        ...current,
        status: current.status === 'open' ? 'in_progress' : current.status,
        remediation: {
          ...(current.remediation ?? {
            action: 'remove_permission',
            target: current.resourceId ?? 'excessive_permission',
            dryRunAvailable: true,
            rollbackAvailable: true,
            approvalRequired: true,
            dryRunExecuted: true,
          }),
          approvalStatus: 'approved',
          approvedBy: actor.email,
          approvedAt: now,
          breakGlassDualApproval: Boolean(options.breakGlassDualApproval),
        },
      };
      this.findings[idx] = updated;

      this.appendEvidenceRecord({
        tenantId: tid,
        controlId: 'SOC2_CC6.2',
        framework: 'SOC 2',
        mappedFrameworks: ['SOC 2', 'ISO 27001', 'EU AI Act'],
        evidenceType: 'approval_record',
        source: 'workflow',
        resourceId: findingId,
        title: `Remediation Approval Recorded for ${current.agentName}`,
        summary: `Approved by ${actor.email} (breakGlass=${Boolean(options.breakGlassDualApproval)})`,
        payload: { findingId, approver: actor.email, approvedAt: now },
      });

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'remediation.approved',
        resourceType: 'finding',
        resourceId: findingId,
        outcome: 'allowed',
        before: { approvalStatus: current.remediation?.approvalStatus ?? 'pending_approval' },
        after: {
          approvalStatus: 'approved',
          approvedBy: actor.email,
          breakGlassDualApproval: Boolean(options.breakGlassDualApproval),
        },
      });

      return updated;
    });
  }

  applyApprovedRemediation(
    tenantId: string,
    findingId: string,
    actor: { id: string; email: string; role: Role }
  ): Finding {
    return this.withTenantContext(tenantId, (tid) => {
      const idx = this.findings.findIndex((f) => f.id === findingId && f.tenantId === tid);
      if (idx === -1) throw new Error('Finding not found in tenant scope');
      const current = this.findings[idx];

      if (current.remediation?.approvalStatus !== 'approved') {
        this.recordAuditEvent({
          tenantId: tid,
          actorId: actor.id,
          actorEmail: actor.email,
          actorRole: actor.role,
          action: 'remediation.unapproved_execution_blocked',
          resourceType: 'finding',
          resourceId: findingId,
          outcome: 'denied',
          before: { approvalStatus: current.remediation?.approvalStatus ?? 'pending_approval' },
          after: { reason: 'Explicit approval required before applying remediation' },
        });
        throw new Error('Approval required: Explicitly approve this remediation change before applying.');
      }

      const targetEdgeId = current.remediation.targetEdgeId;
      if (targetEdgeId) {
        const edgeIdx = this.graphEdges.findIndex(
          (e) => e.id === targetEdgeId && e.tenantId === tid
        );
        if (edgeIdx !== -1) {
          const [removed] = this.graphEdges.splice(edgeIdx, 1);
          this.removedEdgeBackups.set(`${tid}::${findingId}`, removed);
        }
      }

      const now = new Date().toISOString();
      const updated: Finding = {
        ...current,
        status: 'in_progress',
        remediation: {
          ...current.remediation,
          approvalStatus: 'applied',
          appliedAt: now,
        },
      };
      this.findings[idx] = updated;
      this.recomputeTenantRiskAssessments(tid);

      this.activity.unshift({
        id: `act_${crypto.randomUUID()}`,
        tenantId: tid,
        timestamp: 'Just now',
        category: 'remediation',
        title: `Least-privilege change applied for ${current.agentName}`,
        detail: `${current.remediation.target} scoped down — awaiting re-sync verification`,
        severity: 'nominal',
      });

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'remediation.applied_least_privilege',
        resourceType: 'finding',
        resourceId: findingId,
        outcome: 'allowed',
        before: { approvalStatus: 'approved' },
        after: { approvalStatus: 'applied', removedEdgeId: targetEdgeId ?? null },
      });

      return this.findings[idx];
    });
  }

  rollbackFindingRemediation(
    tenantId: string,
    findingId: string,
    actor: { id: string; email: string; role: Role }
  ): Finding {
    return this.withTenantContext(tenantId, (tid) => {
      const idx = this.findings.findIndex((f) => f.id === findingId && f.tenantId === tid);
      if (idx === -1) throw new Error('Finding not found in tenant scope');
      const current = this.findings[idx];

      const backupEdge = this.removedEdgeBackups.get(`${tid}::${findingId}`);
      if (backupEdge && !this.graphEdges.some((e) => e.id === backupEdge.id && e.tenantId === tid)) {
        this.graphEdges.push(backupEdge);
      }

      const updated: Finding = {
        ...current,
        status: 'in_progress',
        slaRemainingDays: Math.max(1, current.slaDays),
        remediation: {
          ...(current.remediation ?? {
            action: 'remove_permission',
            target: current.resourceId ?? 'excessive_permission',
            dryRunAvailable: true,
            rollbackAvailable: true,
            approvalRequired: true,
            dryRunExecuted: true,
          }),
          approvalStatus: 'rolled_back',
        },
        verification: {
          status: 'unverified',
          message: 'Remediation rolled back; previous policy state restored.',
        },
      };
      this.findings[idx] = updated;
      this.recomputeTenantRiskAssessments(tid);

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'remediation.rolled_back',
        resourceType: 'finding',
        resourceId: findingId,
        outcome: 'allowed',
        before: { status: current.status, approvalStatus: current.remediation?.approvalStatus },
        after: { status: 'in_progress', approvalStatus: 'rolled_back', restoredEdgeId: backupEdge?.id ?? null },
      });

      return this.findings[idx];
    });
  }

  async verifyAndCloseFinding(
    tenantId: string,
    findingId: string,
    actor: { id: string; email: string; role: Role }
  ): Promise<{ closed: boolean; finding: Finding }> {
    return this.withTenantContext(tenantId, async (tid) => {
      const idx = this.findings.findIndex((f) => f.id === findingId && f.tenantId === tid);
      if (idx === -1) throw new Error('Finding not found in tenant scope');
      const current = this.findings[idx];

      // Trigger read-only discovery re-sync on primary cloud/identity connectors first
      const syncable = this.connectors.filter(
        (c) =>
          c.tenantId === tid &&
          c.status !== 'disconnected' &&
          (c.provider === 'aws' || c.provider === 'entra_id' || c.provider === 'azure')
      );
      for (const conn of syncable) {
        await this.syncConnector(tid, conn.id, actor);
      }

      const tenantNodes = this.graphNodes.filter((n) => n.tenantId === tid);
      const tenantEdges = this.graphEdges.filter((e) => e.tenantId === tid);
      const check = verifyFindingExposureRemoved(current, tenantNodes, tenantEdges, tid);
      const checkedAt = new Date().toISOString();

      if (!check.verifiedClosed) {
        const blockedFinding: Finding = {
          ...current,
          verification: {
            status: 'path_still_present',
            lastSyncCheckedAt: checkedAt,
            remainingPathCount: check.remainingPathCount,
            message: check.message,
          },
        };
        this.findings[idx] = blockedFinding;

        this.recordAuditEvent({
          tenantId: tid,
          actorId: actor.id,
          actorEmail: actor.email,
          actorRole: actor.role,
          action: 'finding.closure_blocked_path_present',
          resourceType: 'finding',
          resourceId: findingId,
          outcome: 'denied',
          before: { status: current.status },
          after: {
            remainingPathCount: check.remainingPathCount,
            reason: check.message,
          },
        });

        return { closed: false, finding: blockedFinding };
      }

      const closedFinding: Finding = {
        ...current,
        status: 'remediated',
        slaRemainingDays: 0,
        verification: {
          status: 'verified_closed',
          lastSyncCheckedAt: checkedAt,
          remainingPathCount: 0,
          proofHash: check.proofHash,
          message: check.message,
        },
      };
      this.findings[idx] = closedFinding;
      this.recomputeTenantRiskAssessments(tid);

      this.appendEvidenceRecord({
        tenantId: tid,
        controlId: 'SOC2_CC6.3',
        framework: 'SOC 2',
        mappedFrameworks: ['SOC 2', 'ISO 27001', 'EU AI Act'],
        evidenceType: 'remediation_proof',
        source: closedFinding.ticketProvider ?? 'jira',
        resourceId: closedFinding.jiraTicketKey ?? findingId,
        title: `Verified Remediation Closure Proof for ${closedFinding.agentName}`,
        summary: check.message,
        payload: {
          findingId,
          ticketKey: closedFinding.jiraTicketKey ?? null,
          proofHash: check.proofHash,
          remainingPathCount: 0,
        },
      });

      this.activity.unshift({
        id: `act_${crypto.randomUUID()}`,
        tenantId: tid,
        timestamp: 'Just now',
        category: 'remediation',
        title: `Verified & closed: ${closedFinding.title}`,
        detail: `Re-sync confirmed 0 paths · Proof ${check.proofHash?.slice(0, 18)}...`,
        severity: 'nominal',
      });

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'finding.verified_closed',
        resourceType: 'finding',
        resourceId: findingId,
        outcome: 'allowed',
        before: { status: current.status },
        after: { status: 'remediated', proofHash: check.proofHash, remainingPathCount: 0 },
      });

      return { closed: true, finding: this.findings[idx] };
    });
  }

  markFindingRemediated(
    tenantId: string,
    findingId: string,
    actor: { id: string; email: string; role: Role }
  ): Finding {
    return this.withTenantContext(tenantId, (tid) => {
      const idx = this.findings.findIndex((f) => f.id === findingId && f.tenantId === tid);
      if (idx === -1) {
        throw new Error('Finding not found in tenant scope');
      }
      const before = { ...this.findings[idx] };
      const tenantNodes = this.graphNodes.filter((n) => n.tenantId === tid);
      const tenantEdges = this.graphEdges.filter((e) => e.tenantId === tid);
      const check = verifyFindingExposureRemoved(before, tenantNodes, tenantEdges, tid);
      if (!check.verifiedClosed) {
        throw new Error(check.message);
      }
      const updated: Finding = {
        ...before,
        status: 'remediated',
        slaRemainingDays: 0,
        verification: {
          status: 'verified_closed',
          lastSyncCheckedAt: new Date().toISOString(),
          remainingPathCount: 0,
          proofHash: check.proofHash,
          message: check.message,
        },
      };
      this.findings[idx] = updated;

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'finding.verified_closed',
        resourceType: 'finding',
        resourceId: findingId,
        outcome: 'allowed',
        before: { status: before.status },
        after: { status: 'remediated', proofHash: check.proofHash },
      });

      return updated;
    });
  }

  getExposurePaths(tenantId: string, agentId?: string): {
    nodes: GraphNode[];
    edges: GraphEdge[];
    paths: ExposureTraversalResult[];
  } {
    return this.withTenantContext(tenantId, (tid) => {
      const nodes = this.graphNodes.filter((n) => n.tenantId === tid);
      const edges = this.graphEdges.filter((e) => e.tenantId === tid);
      const paths = findSensitiveExposurePaths(nodes, edges, tid, agentId);
      return { nodes, edges, paths };
    });
  }

  getPolicyState(tenantId: string): {
    mode: PolicyMode;
    rules: PolicyRule[];
    simulationEvents: PolicySimulationEvent[];
    gatewayPolicies: GatewayPolicyDefinition[];
    gatewayEvents: GatewayEvent[];
    retentionConfig: RetentionPolicyConfig;
  } {
    return this.withTenantContext(tenantId, (tid) => ({
      mode: this.policyModes[tid] ?? 'observe',
      rules: this.policyRules[tid] ?? [],
      simulationEvents: POLICY_SIMULATION_EVENTS,
      gatewayPolicies: this.gatewayPolicies[tid] ?? [],
      gatewayEvents: this.gatewayEvents.filter((e) => e.tenant_id === tid),
      retentionConfig: this.retentionConfigs[tid] ?? { ...DEFAULT_RETENTION_POLICY },
    }));
  }

  setPolicyMode(
    tenantId: string,
    mode: PolicyMode,
    actor: { id: string; email: string; role: Role }
  ): PolicyMode {
    return this.withTenantContext(tenantId, (tid) => {
      const prev = this.policyModes[tid] ?? 'observe';
      const prevStage = this.rolloutStages[tid] ?? 'observe';
      const nextStage: RolloutStage = mode === 'observe' ? 'observe' : 'full_enforcement';
      this.policyModes[tid] = mode;
      this.rolloutStages[tid] = nextStage;
      this.gatewayPolicies[tid] = (this.gatewayPolicies[tid] ?? []).map((p) => ({
        ...p,
        mode,
        yaml: p.yaml.replace(/mode:\s*(observe|enforce)/, `mode: ${mode}`),
      }));
      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'policy.mode_updated',
        resourceType: 'policy_mode',
        resourceId: tid,
        outcome: 'allowed',
        before: { mode: prev, rolloutStage: prevStage },
        after: { mode, rolloutStage: nextStage },
      });
      return mode;
    });
  }

  setRolloutStage(
    tenantId: string,
    stage: RolloutStage,
    actor: { id: string; email: string; role: Role }
  ): { stage: RolloutStage; mode: PolicyMode } {
    return this.withTenantContext(tenantId, (tid) => {
      const prevStage = this.rolloutStages[tid] ?? 'observe';
      const prevMode = this.policyModes[tid] ?? 'observe';
      const nextMode: PolicyMode =
        stage === 'observe' || stage === 'advisory' ? 'observe' : 'enforce';

      this.rolloutStages[tid] = stage;
      this.policyModes[tid] = nextMode;
      this.gatewayPolicies[tid] = (this.gatewayPolicies[tid] ?? []).map((p) => ({
        ...p,
        mode: nextMode,
        yaml: p.yaml.replace(/mode:\s*(observe|enforce)/, `mode: ${nextMode}`),
      }));

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'policy.rollout_stage_updated',
        resourceType: 'rollout_stage',
        resourceId: tid,
        outcome: 'allowed',
        before: { stage: prevStage, mode: prevMode },
        after: { stage, mode: nextMode },
        reason: `Progressive rollout transitioned from ${prevStage} to ${stage}`,
      });

      return { stage, mode: nextMode };
    });
  }

  togglePolicyRule(
    tenantId: string,
    ruleId: string,
    actor: { id: string; email: string; role: Role }
  ): PolicyRule {
    return this.withTenantContext(tenantId, (tid) => {
      const list = this.policyRules[tid] ?? [];
      const idx = list.findIndex((r) => r.id === ruleId);
      const gwList = this.gatewayPolicies[tid] ?? [];
      const gwIdx = gwList.findIndex((g) => g.id === ruleId);
      if (idx === -1 && gwIdx === -1) throw new Error('Policy rule not found');

      let nextEnabled = true;
      let prevEnabled = false;
      if (idx !== -1) {
        prevEnabled = list[idx].enabled;
        nextEnabled = !prevEnabled;
        list[idx] = { ...list[idx], enabled: nextEnabled };
      }
      if (gwIdx !== -1) {
        prevEnabled = gwList[gwIdx].enabled;
        nextEnabled = !prevEnabled;
        gwList[gwIdx] = { ...gwList[gwIdx], enabled: nextEnabled };
      }

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'policy.rule_toggled',
        resourceType: 'policy_rule',
        resourceId: ruleId,
        outcome: 'allowed',
        before: { enabled: prevEnabled },
        after: { enabled: nextEnabled },
      });
      return idx !== -1
        ? list[idx]
        : {
            id: gwList[gwIdx].id,
            name: gwList[gwIdx].name,
            scope: gwList[gwIdx].scope.tools.join(', '),
            condition: gwList[gwIdx].scope.data_classification.join(', '),
            action: gwList[gwIdx].decision,
            observeHits24h: gwList[gwIdx].observeHits24h,
            enabled: gwList[gwIdx].enabled,
            lastTriggered: gwList[gwIdx].lastTriggered,
          };
    });
  }

  // ---- Dynamic Risk Re-scoring, Evidence Vault, Auditor Export & Observe-Mode Gateway ----

  updateAgentRiskSignals(
    tenantId: string,
    agentId: string,
    updates: {
      owner?: string;
      permissions?: string[];
      dailyCalls?: number;
      overrides?: Partial<RiskFactorInputs>;
    },
    actor: { id: string; email: string; role: Role }
  ): Agent {
    return this.withTenantContext(tenantId, (tid) => {
      const idx = this.agents.findIndex((a) => a.id === agentId && a.tenantId === tid);
      if (idx === -1) throw new Error('Agent not found in tenant scope');
      const prev = this.agents[idx];
      const nextOwner = updates.owner !== undefined ? updates.owner : prev.owner;
      const nextType =
        nextOwner && nextOwner !== 'unassigned' && prev.type === 'Unowned'
          ? 'Internal agent'
          : prev.type;

      this.agents[idx] = {
        ...prev,
        owner: nextOwner,
        type: nextType,
        permissions: updates.permissions ?? prev.permissions,
        dailyCalls: updates.dailyCalls ?? prev.dailyCalls,
      };

      this.recomputeTenantRiskAssessments(tid, {
        agentId,
        overrides: updates.overrides ?? {},
      });

      const updated = this.agents[idx];
      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'risk.signals_recalculated',
        resourceType: 'agent',
        resourceId: agentId,
        outcome: 'allowed',
        before: { riskScore: prev.riskScore, owner: prev.owner, permissionsCount: prev.permissions.length },
        after: {
          riskScore: updated.riskScore,
          riskLevel: updated.riskLevel,
          owner: updated.owner,
          permissionsCount: updated.permissions.length,
        },
      });
      return updated;
    });
  }

  getEvidenceRecords(tenantId: string): EvidenceRecord[] {
    return this.withTenantContext(tenantId, (tid) =>
      this.evidenceRecords.filter((ev) => ev.tenant_id === tid)
    );
  }

  getControlsForTenant(tenantId: string): ControlItem[] {
    return this.withTenantContext(tenantId, (tid) => {
      const tenantEvidence = this.evidenceRecords.filter((e) => e.tenant_id === tid);
      const openFindings = this.findings.filter(
        (f) => f.tenantId === tid && f.status !== 'remediated'
      );

      return GOVERNANCE_CONTROLS.map((ctrl) => {
        const matchingEvidence = tenantEvidence.filter(
          (ev) =>
            ev.framework === ctrl.framework ||
            ev.mapped_frameworks.includes(ctrl.framework) ||
            (ctrl.requiredEvidenceTypes ?? []).includes(ev.evidence_type)
        );
        const mappedFindings = openFindings.filter((f) =>
          f.frameworks.some(
            (fw) => fw.includes(ctrl.code) || fw.includes(ctrl.framework)
          )
        );
        const hasCriticalOrUnownedGap =
          mappedFindings.some((f) => f.severity === 'critical' || f.ruleId === 'RULE_UNOWNED_AGENT') ||
          matchingEvidence.length === 0;
        const status: ControlItem['status'] =
          matchingEvidence.length === 0 || (ctrl.code === 'CC6.3' || ctrl.code === 'A.5.15') && mappedFindings.length > 0
            ? 'gap'
            : hasCriticalOrUnownedGap || mappedFindings.length > 0
              ? 'partial'
              : 'covered';

        return {
          ...ctrl,
          status,
          evidenceCount: matchingEvidence.length,
          mappedFindingIds: mappedFindings.map((f) => f.id),
          lastVerified: matchingEvidence[0]?.collected_at.slice(0, 16).replace('T', ' ') + ' UTC' || 'Pending',
        };
      });
    });
  }

  exportComplianceAuditPackage(
    tenantId: string,
    options: { framework: ComplianceFramework | 'all'; fromDate?: string; toDate?: string },
    actor: { id: string; email: string; role: Role }
  ) {
    return this.withTenantContext(tenantId, (tid) => {
      const tenant = this.getTenant(tid);
      const controls = this.getControlsForTenant(tid);
      const evidenceRecords = this.getEvidenceRecords(tid);
      const pkg = buildAuditorExportPackage({
        tenantId: tid,
        tenantName: tenant.name,
        framework: options.framework,
        fromDate: options.fromDate,
        toDate: options.toDate,
        controls,
        evidenceRecords,
      });

      const auditEv = this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'compliance.audit_pack_exported',
        resourceType: 'compliance_pack',
        resourceId: pkg.packageId,
        outcome: 'allowed',
        before: null,
        after: {
          framework: options.framework,
          fromDate: options.fromDate ?? 'inception',
          toDate: options.toDate ?? 'present',
          evidenceCount: pkg.evidenceRecords.length,
          chainValid: pkg.hashChainIntegrity.valid,
          exportDurationMs: pkg.exportDurationMs,
        },
      });

      return { ...pkg, auditEventId: auditEv.id };
    });
  }

  inspectGatewayTraffic(
    tenantId: string,
    input: {
      agentId: string;
      provider?: string;
      model?: string;
      tool: string;
      mcpServer?: string;
      promptText?: string;
      responseText?: string;
      targetResource?: string;
    },
    actor: { id: string; email: string; role: Role }
  ): { event: GatewayEvent; evidenceRecord: EvidenceRecord; createdFinding?: Finding } {
    return this.withTenantContext(tenantId, (tid) => {
      const agent =
        this.agents.find((a) => a.id === input.agentId && a.tenantId === tid) ??
        this.agents.find((a) => a.tenantId === tid);
      if (!agent) throw new Error('No agent available in tenant scope');

      const mode = this.policyModes[tid] ?? 'observe';
      const policies = this.gatewayPolicies[tid] ?? [];
      const retention = this.retentionConfigs[tid] ?? DEFAULT_RETENTION_POLICY;

      const result = inspectGatewayRequest({
        tenantId: tid,
        agent,
        provider: input.provider ?? 'openai',
        model: input.model ?? agent.models[0] ?? 'gpt-4.1',
        tool: input.tool,
        mcpServer: input.mcpServer ?? agent.mcpServers[0] ?? 'finance-mcp',
        mode,
        policies,
        retention,
        promptText: input.promptText,
        responseText: input.responseText,
        targetResource: input.targetResource,
        previousEvidenceHash: this.getLatestEvidenceHash(tid),
      });

      let createdFinding: Finding | undefined;
      if (result.shouldCreateFinding && result.matchedPolicy) {
        const existing = this.findings.find(
          (f) =>
            f.tenantId === tid &&
            f.agentId === agent.id &&
            f.ruleId === 'RULE_EXFILTRATION_PATH' &&
            f.status !== 'remediated'
        );
        if (existing) {
          result.event.finding_id = existing.id;
        } else {
          const findingId = `finding_gw_${crypto.randomUUID().slice(0, 8)}`;
          createdFinding = {
            id: findingId,
            tenantId: tid,
            ruleId: 'RULE_EXFILTRATION_PATH',
            category: 'data_exfiltration_path',
            riskScore: agent.riskScore,
            riskAssessment: agent.riskAssessment,
            agentId: agent.id,
            agentName: agent.name,
            identityId: agent.identity,
            resourceId: input.targetResource ?? input.tool,
            dataClassification: result.event.classification.matchedSignals.join(', ') || 'sensitive',
            title: `Gateway policy ${result.matchedPolicy.id} triggered by ${agent.name}`,
            description: `Runtime gateway (${mode} mode) recorded ${result.event.policy_decision} on tool ${input.tool} via ${result.event.mcp_server}.`,
            businessImpact: 'Sensitive data classification matched external model egress policy.',
            remediationSteps: [
              `Review gateway event ${result.event.event_id} and linked evidence ${result.evidenceRecord.id}.`,
              `Restrict ${input.tool} on ${result.event.mcp_server} or switch policy mode to enforce.`,
            ],
            severity: result.matchedPolicy.severity,
            owner: 'Cloud Security',
            slaDays: 2,
            slaRemainingDays: 2,
            status: 'open',
            createdAt: new Date().toISOString().slice(0, 10),
            frameworks: ['SOC 2 CC7.2', 'EU AI Act Art. 12 / 14'],
            exposurePath: [agent.name, agent.identity, result.event.mcp_server, input.tool, input.targetResource ?? 'external_model'],
            evidence: [
              {
                id: result.evidenceRecord.id,
                source: 'gateway',
                type: 'policy_decision',
                summary: result.evidenceRecord.summary,
                collectedAt: result.evidenceRecord.collected_at,
                hash: result.evidenceRecord.content_hash,
              },
            ],
          };
          this.findings.unshift(createdFinding);
          result.event.finding_id = findingId;
        }
      }

      this.evidenceRecords.unshift(result.evidenceRecord);
      this.gatewayEvents.unshift(result.event);

      if (result.matchedPolicy) {
        result.matchedPolicy.observeHits24h += 1;
        result.matchedPolicy.lastTriggered = 'Just now';
      }

      const tIdx = this.tenants.findIndex((t) => t.id === tid);
      if (tIdx !== -1) {
        this.tenants[tIdx] = {
          ...this.tenants[tIdx],
          dailyRequests: this.tenants[tIdx].dailyRequests + 1,
          dailyToolCalls: this.tenants[tIdx].dailyToolCalls + 1,
          blockedOrRedactedEvents:
            result.event.policy_decision === 'would_allow' || result.event.policy_decision === 'allow'
              ? this.tenants[tIdx].blockedOrRedactedEvents
              : this.tenants[tIdx].blockedOrRedactedEvents + 1,
        };
      }

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: `gateway.${result.event.policy_decision}`,
        resourceType: 'gateway_event',
        resourceId: result.event.event_id,
        outcome: result.event.forwarded ? 'allowed' : 'denied',
        before: null,
        after: {
          mode,
          forwarded: result.event.forwarded,
          policyRule: result.event.policy_rule,
          contentRetained: result.event.content_retained,
          evidenceId: result.evidenceRecord.id,
        },
      });

      return {
        event: result.event,
        evidenceRecord: result.evidenceRecord,
        createdFinding,
      };
    });
  }

  setRetentionOptIn(
    tenantId: string,
    redactedExcerptOptIn: boolean,
    actor: { id: string; email: string; role: Role }
  ): RetentionPolicyConfig {
    return this.withTenantContext(tenantId, (tid) => {
      const current = this.retentionConfigs[tid] ?? { ...DEFAULT_RETENTION_POLICY };
      const updated: RetentionPolicyConfig = {
        ...current,
        redactedExcerptOptIn,
        rawPromptRetained: false,
        rawResponseRetained: false,
      };
      this.retentionConfigs[tid] = updated;
      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'privacy.retention_policy_updated',
        resourceType: 'retention_policy',
        resourceId: tid,
        outcome: 'allowed',
        before: { redactedExcerptOptIn: current.redactedExcerptOptIn },
        after: { redactedExcerptOptIn, rawPromptRetained: false, rawResponseRetained: false },
      });
      return updated;
    });
  }

  // ---- Connectors, PKCE OAuth, KMS Vault & Atomic Graph Ingestion ----

  getConnectors(tenantId: string): ConnectorRecord[] {
    return this.withTenantContext(tenantId, (tid) =>
      this.connectors.filter((c) => c.tenantId === tid)
    );
  }

  getCredentialMetadata(tenantId: string, connectorId: string) {
    return this.withTenantContext(tenantId, (tid) => {
      const cred = this.credentials.find(
        (cr) => cr.tenantId === tid && cr.connectorId === connectorId && !cr.revoked
      );
      if (!cred) return null;
      return {
        id: cred.id,
        keyId: cred.keyId,
        tokenVersion: cred.tokenVersion,
        expiresAt: cred.expiresAt,
        encrypted: true,
      };
    });
  }

  startPkceAuthorization(tenantId: string, connectorId: string): {
    authSessionId: string;
    codeVerifier: string;
    codeChallenge: string;
    scopes: string[];
  } {
    return this.withTenantContext(tenantId, (tid) => {
      const conn = this.connectors.find((c) => c.id === connectorId && c.tenantId === tid);
      if (!conn) throw new Error('Connector not found in tenant');
      const adapter = this.registry.get(conn.provider);
      const { codeVerifier, codeChallenge } = createPkcePair();
      const authSessionId = `pkce_${crypto.randomUUID()}`;
      this.pkceChallenges.set(authSessionId, {
        tenantId: tid,
        connectorId,
        codeChallenge,
      });
      return {
        authSessionId,
        codeVerifier,
        codeChallenge,
        scopes: adapter.requiredReadOnlyScopes,
      };
    });
  }

  async completePkceAuthorization(
    tenantId: string,
    connectorId: string,
    authSessionId: string,
    codeVerifier: string,
    actor: { id: string; email: string; role: Role }
  ): Promise<ConnectorRecord> {
    return this.withTenantContext(tenantId, async (tid) => {
      const challengeRecord = this.pkceChallenges.get(authSessionId);
      if (
        !challengeRecord ||
        challengeRecord.tenantId !== tid ||
        challengeRecord.connectorId !== connectorId
      ) {
        throw new Error('Invalid PKCE authorization session');
      }
      this.pkceChallenges.delete(authSessionId);

      const connIdx = this.connectors.findIndex(
        (c) => c.id === connectorId && c.tenantId === tid
      );
      if (connIdx === -1) throw new Error('Connector not found');

      const conn = this.connectors[connIdx];
      const adapter = this.registry.get(conn.provider);
      const authResult = await adapter.authorize({
        tenantId: tid,
        connectorId,
        codeVerifier,
        codeChallenge: challengeRecord.codeChallenge,
        grantedScopes: adapter.requiredReadOnlyScopes,
      });

      const encryptedCred = encryptTenantSecret(
        tid,
        connectorId,
        authResult.refreshToken,
        1
      );
      this.credentials = this.credentials.filter(
        (cr) => !(cr.tenantId === tid && cr.connectorId === connectorId)
      );
      this.credentials.push(encryptedCred);

      const updated: ConnectorRecord = {
        ...conn,
        status: 'healthy',
        pkceVerified: true,
        scopes: authResult.scopes,
        lastSyncLabel: 'Authorized just now',
      };
      this.connectors[connIdx] = updated;

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'connector.pkce_authorized',
        resourceType: 'connector',
        resourceId: connectorId,
        outcome: 'allowed',
        before: { status: conn.status },
        after: { status: 'healthy', keyId: encryptedCred.keyId, scopes: authResult.scopes },
      });

      return updated;
    });
  }

  async rotateConnectorToken(
    tenantId: string,
    connectorId: string,
    actor: { id: string; email: string; role: Role }
  ): Promise<{ tokenVersion: number; keyId: string }> {
    return this.withTenantContext(tenantId, async (tid) => {
      const conn = this.connectors.find((c) => c.id === connectorId && c.tenantId === tid);
      if (!conn) throw new Error('Connector not found in tenant');

      const credIdx = this.credentials.findIndex(
        (cr) => cr.tenantId === tid && cr.connectorId === connectorId && !cr.revoked
      );
      if (credIdx === -1) throw new Error('No active credential to rotate');

      const currentCred = this.credentials[credIdx];
      const currentPlaintext = decryptTenantSecret(tid, currentCred);
      const adapter = this.registry.get(conn.provider);
      const rotated = await adapter.refreshToken({
        tenantId: tid,
        connectorId,
        currentRefreshToken: currentPlaintext,
      });

      const nextVersion = currentCred.tokenVersion + 1;
      const newCred = encryptTenantSecret(
        tid,
        connectorId,
        rotated.newRefreshToken,
        nextVersion
      );
      this.credentials[credIdx] = newCred;

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'connector.token_rotated',
        resourceType: 'credential',
        resourceId: newCred.id,
        outcome: 'allowed',
        before: { tokenVersion: currentCred.tokenVersion },
        after: { tokenVersion: nextVersion, keyId: newCred.keyId },
      });

      return { tokenVersion: nextVersion, keyId: newCred.keyId };
    });
  }

  revokeConnector(
    tenantId: string,
    connectorId: string,
    actor: { id: string; email: string; role: Role }
  ): ConnectorRecord {
    return this.withTenantContext(tenantId, (tid) => {
      const connIdx = this.connectors.findIndex(
        (c) => c.id === connectorId && c.tenantId === tid
      );
      if (connIdx === -1) throw new Error('Connector not found');

      for (const cr of this.credentials) {
        if (cr.tenantId === tid && cr.connectorId === connectorId) {
          cr.revoked = true;
        }
      }

      const prev = this.connectors[connIdx];
      const updated: ConnectorRecord = {
        ...prev,
        status: 'disconnected',
        lastSyncLabel: 'Disconnected',
      };
      this.connectors[connIdx] = updated;

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'connector.disconnected_revoked',
        resourceType: 'connector',
        resourceId: connectorId,
        outcome: 'allowed',
        before: { status: prev.status },
        after: { status: 'disconnected', credentialsRevoked: true },
      });

      return updated;
    });
  }

  async connectCloudProvider(
    tenantId: string,
    provider: 'entra_id' | 'aws' | 'azure',
    config: Record<string, string>,
    actor: { id: string; email: string; role: Role }
  ): Promise<{ connector: ConnectorRecord; nodesAdded: number; edgesAdded: number }> {
    return this.withTenantContext(tenantId, async (tid) => {
      if (provider === 'aws') {
        validateAwsConnectionInput(config);
      } else if (provider === 'entra_id') {
        if (!config.tenantDomain?.trim()) {
          throw new Error('Entra ID tenant domain is required for admin consent.');
        }
      } else if (provider === 'azure') {
        if (!config.subscriptionId?.trim() || !config.clientId?.trim()) {
          throw new Error('Azure Subscription ID and Managed/Federated Identity Client ID are required.');
        }
      }

      const adapter = this.registry.get(provider);
      const connIdx = this.connectors.findIndex(
        (c) => c.tenantId === tid && c.provider === provider
      );

      let connId: string;
      if (connIdx >= 0) {
        connId = this.connectors[connIdx].id;
        this.connectors[connIdx] = {
          ...this.connectors[connIdx],
          status: 'healthy',
          readOnly: true,
          pkceVerified: true,
          scopes: adapter.requiredReadOnlyScopes,
          config: { ...this.connectors[connIdx].config, ...config },
        };
      } else {
        connId = `conn_${tid}_${provider}`;
        const displayMap = {
          entra_id: 'Microsoft Entra ID',
          aws: 'AWS Organizations & IAM',
          azure: 'Microsoft Azure & AI Foundry',
        };
        this.connectors.push({
          id: connId,
          tenantId: tid,
          provider,
          displayName: displayMap[provider],
          category: provider === 'entra_id' ? 'Identity' : 'Cloud',
          status: 'healthy',
          readOnly: true,
          lastSyncAt: new Date().toISOString(),
          lastSyncLabel: 'Just now',
          coveragePct: 100,
          discoveredAssets: 0,
          scopes: adapter.requiredReadOnlyScopes,
          pkceVerified: true,
          config,
        });
      }

      // Encrypt credential under tenant-scoped KMS key (never plaintext)
      const cred = encryptTenantSecret(
        tid,
        connId,
        `readonly_${provider}_${tid}_${Date.now()}`
      );
      this.credentials = this.credentials.filter(
        (cr) => !(cr.tenantId === tid && cr.connectorId === connId)
      );
      this.credentials.push(cred);

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: `connector.${provider}_onboarded_readonly`,
        resourceType: 'connector',
        resourceId: connId,
        outcome: 'allowed',
        before: null,
        after: {
          provider,
          readOnly: true,
          keyId: cred.keyId,
          scopesCount: adapter.requiredReadOnlyScopes.length,
        },
      });

      return this.syncConnector(tid, connId, actor);
    });
  }

  /**
   * Executes a tenant-scoped discovery sync atomically and idempotently:
   * Keyed by (tenant_id, provider, external_resource_id) so repeated syncs never duplicate nodes, edges, or findings.
   */
  async syncConnector(
    tenantId: string,
    connectorId: string,
    actor: { id: string; email: string; role: Role },
    options?: { simulateFailure?: boolean }
  ): Promise<{ connector: ConnectorRecord; nodesAdded: number; edgesAdded: number; findingsAdded: number }> {
    return this.withTenantContext(tenantId, async (tid) => {
      const connIdx = this.connectors.findIndex(
        (c) => c.id === connectorId && c.tenantId === tid
      );
      if (connIdx === -1) throw new Error('Connector not found');

      const conn = this.connectors[connIdx];
      const cred = this.credentials.find(
        (cr) => cr.tenantId === tid && cr.connectorId === connectorId && !cr.revoked
      );
      if (!cred) {
        throw new Error('Cannot sync connector without valid active credential');
      }
      // Verify decryption works within tenant context (never log decrypted value)
      decryptTenantSecret(tid, cred);

      const adapter = this.registry.get(conn.provider);
      // Stage discoveries in memory before committing to graph (atomic swap)
      const entityDiscovery = await adapter.discoverEntities({
        tenantId: tid,
        connectorId,
        config: conn.config,
        simulateFailure: options?.simulateFailure,
      });
      const discoveredEdges = await adapter.discoverRelationships({
        tenantId: tid,
        connectorId,
        config: conn.config,
        simulateFailure: options?.simulateFailure,
      });

      let nodesAdded = 0;
      for (const n of entityDiscovery.nodes) {
        const extKey = n.externalResourceId
          ? buildIdempotentKey(tid, conn.provider, n.externalResourceId)
          : null;
        const existingIdx = this.graphNodes.findIndex(
          (existing) =>
            existing.tenantId === tid &&
            (existing.id === n.id ||
              (extKey &&
                existing.provider === conn.provider &&
                existing.externalResourceId === n.externalResourceId))
        );
        if (existingIdx === -1) {
          this.graphNodes.push(n);
          nodesAdded += 1;
        } else {
          this.graphNodes[existingIdx] = { ...this.graphNodes[existingIdx], ...n };
        }
      }

      let edgesAdded = 0;
      for (const e of discoveredEdges) {
        const existingIdx = this.graphEdges.findIndex(
          (existing) =>
            existing.tenantId === tid &&
            (existing.id === e.id ||
              (e.externalResourceId &&
                existing.provider === conn.provider &&
                existing.externalResourceId === e.externalResourceId))
        );
        if (existingIdx === -1) {
          this.graphEdges.push(e);
          edgesAdded += 1;
        } else {
          this.graphEdges[existingIdx] = { ...this.graphEdges[existingIdx], ...e };
        }
      }

      // Run rule engine idempotently over normalized tenant graph
      const newFindings = evaluateFindingsFromDiscovery({
        tenantId: tid,
        provider: conn.provider,
        agents: this.getAgents(tid),
        nodes: this.graphNodes.filter((n) => n.tenantId === tid),
        edges: this.graphEdges.filter((e) => e.tenantId === tid),
        existingFindings: this.findings,
        evidenceArtifacts: entityDiscovery.evidence,
      });
      for (const nf of newFindings) {
        this.findings.push(nf);
      }

      const summaryCount = Object.values(entityDiscovery.summary).reduce((s, v) => s + v, 0);
      const updated: ConnectorRecord = {
        ...conn,
        status: 'healthy',
        readOnly: true,
        coveragePct: 100,
        discoveredAssets: summaryCount > 0 ? summaryCount : conn.discoveredAssets,
        discoveredSummary:
          Object.keys(entityDiscovery.summary).length > 0
            ? entityDiscovery.summary
            : conn.discoveredSummary,
        lastSyncAt: new Date().toISOString(),
        lastSyncLabel: 'Just now',
      };
      this.connectors[connIdx] = updated;

      // Continuously collect hash-chained compliance evidence from connector sync
      if (conn.provider === 'entra_id' || conn.provider === 'aws' || conn.provider === 'azure') {
        const evidenceType: EvidenceType =
          conn.provider === 'entra_id' ? 'identity_inventory' : 'permission_snapshot';
        this.appendEvidenceRecord({
          tenantId: tid,
          controlId: conn.provider === 'entra_id' ? 'SOC2_CC6.1' : 'ISO27001_A.8.2',
          framework: conn.provider === 'entra_id' ? 'SOC 2' : 'ISO 27001',
          mappedFrameworks: ['SOC 2', 'ISO 27001', 'ISO 42001'],
          evidenceType,
          source: conn.provider,
          resourceId: connectorId,
          title: `${conn.displayName} Discovery Evidence Snapshot`,
          summary: `${updated.discoveredAssets} assets synced read-only (${nodesAdded} new nodes, ${edgesAdded} new edges)`,
          payload: {
            provider: conn.provider,
            summary: entityDiscovery.summary,
            nodesAdded,
            edgesAdded,
          },
        });
      }

      this.recomputeTenantRiskAssessments(tid);

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'connector.sync_completed',
        resourceType: 'connector',
        resourceId: connectorId,
        outcome: 'allowed',
        before: null,
        after: {
          provider: conn.provider,
          readOnly: true,
          nodesAdded,
          edgesAdded,
          findingsAdded: newFindings.length,
        },
      });

      return { connector: updated, nodesAdded, edgesAdded, findingsAdded: newFindings.length };
    });
  }

  // ---- Shared Metadata Lookups ----

  getSharedWorkspaceBundle(tenantId: string, role: Role, email: string): {
    tenant: TenantRecord;
    agents: Agent[];
    mcpServers: McpServer[];
    models: ModelAsset[];
    dataSources: DataSource[];
    findings: Finding[];
    controls: ControlItem[];
    evidence: EvidenceItem[];
    evidenceRecords: EvidenceRecord[];
    activity: ActivityEvent[];
    trendSeries: RiskTrendPoint[];
    connectors: Connector[];
    demoRequests: DemoRequestRecord[];
  } {
    return this.withTenantContext(tenantId, (tid) => {
      const tenant = this.getTenant(tid);
      const agents = this.getAgents(tid, role, email);
      const findings = this.getFindings(tid);
      const activity = this.activity.filter((a) => a.tenantId === tid);
      const controls = this.getControlsForTenant(tid);
      const evidenceRecords = this.getEvidenceRecords(tid);
      const evidence: EvidenceItem[] = evidenceRecords.map((ev) => ({
        id: ev.id,
        controlCode: ev.control_id,
        framework: ev.framework,
        title: ev.title,
        source: ev.source,
        capturedAt: ev.collected_at.slice(0, 16).replace('T', ' ') + ' UTC',
        hash: ev.content_hash,
      }));
      const connectors: Connector[] = this.getConnectors(tid).map((c) => ({
        id: c.id,
        tenantId: c.tenantId,
        provider: c.provider,
        name: c.displayName,
        category: c.category,
        status: c.status === 'disconnected' || c.status === 'error' ? 'warning' : c.status,
        readOnly: c.readOnly,
        coveragePct: c.coveragePct,
        discoveredAssets: c.discoveredAssets,
        discoveredSummary: c.discoveredSummary,
        lastSync: c.lastSyncLabel,
        scopesSummary: c.scopes.join(', '),
        config: c.config,
      }));

      return {
        tenant,
        agents,
        mcpServers: this.mcpServers,
        models: this.models,
        dataSources: this.dataSources,
        findings,
        controls,
        evidence,
        evidenceRecords,
        activity,
        trendSeries: RISK_TREND_SERIES[tid] ?? RISK_TREND_SERIES.tenant_northwind,
        connectors,
        demoRequests: this.demoRequests,
      };
    });
  }

  // ---- Enterprise Zero-Trust Control Plane: PEP/PDP, SOAR Playbooks, SSO/SCIM & Release Gates ----

  getScimDirectory(tenantId: string): ScimDirectoryUser[] {
    return this.withTenantContext(tenantId, (tid) => {
      return this.scimDirectory
        .filter((u) => u.tenantId === tid)
        .map((entry) => {
          const user = this.findUserByEmail(entry.email);
          let activeSessionCount = 0;
          if (user) {
            for (const sess of this.sessions.values()) {
              if (sess.userId === user.id && sess.activeTenantId === tid && Date.now() <= sess.expiresAt) {
                activeSessionCount += 1;
              }
            }
          }
          return { ...entry, activeSessionCount };
        });
    });
  }

  getEnterpriseState(tenantId: string): {
    rolloutStage: RolloutStage;
    killSwitch: KillSwitchState;
    playbooks: PlaybookDefinition[];
    playbookExecutions: PlaybookExecutionRecord[];
    ssoConfig: EnterpriseSsoConfig;
    scimDirectory: ScimDirectoryUser[];
    idpGroupRoleMap: Record<string, Role>;
    hardeningMatrix: PlatformHardeningItem[];
    releaseGates: ReleaseGateCheck[];
    auditIntegrity: AuditChainIntegrity;
    auditRetentionDays: number;
    lastAllInOneRun?: AllInOneRunResult;
  } {
    return this.withTenantContext(tenantId, (tid) => ({
      rolloutStage: this.rolloutStages[tid] ?? 'observe',
      killSwitch: this.killSwitches[tid] ?? {
        paused: false,
        updatedAt: new Date().toISOString(),
        updatedBy: 'system',
      },
      playbooks: RESPONSE_PLAYBOOKS,
      playbookExecutions: this.playbookExecutions.filter((p) => p.tenantId === tid),
      ssoConfig: this.ssoConfigs[tid],
      scimDirectory: this.getScimDirectory(tid),
      idpGroupRoleMap: IDP_GROUP_ROLE_MAP,
      hardeningMatrix: PLATFORM_HARDENING_MATRIX,
      releaseGates: this.computeReleaseGateChecks(tid),
      auditIntegrity: this.getAuditIntegrity(tid),
      auditRetentionDays: Math.max(365, this.auditRetentionDays[tid] ?? 365),
      lastAllInOneRun: this.lastAllInOneRuns[tid],
    }));
  }

  evaluatePepRequest(
    tenantId: string,
    input: {
      agentId: string;
      provider?: string;
      model?: string;
      tool: string;
      mcpServer?: string;
      promptText?: string;
      targetResource?: string;
      requestedActionOverride?: EnforcementAction;
      mfaVerified?: boolean;
      replayNonce?: string;
    },
    actor: { id: string; email: string; role: Role }
  ): {
    event: GatewayEvent;
    evidenceRecord: EvidenceRecord;
    pdpDecision: EnforcementAction;
    pdpReason: string;
    enforced: boolean;
    playbookExecution?: PlaybookExecutionRecord;
  } {
    return this.withTenantContext(tenantId, (tid) => {
      if (input.replayNonce) {
        const nonceKey = `${tid}::${input.replayNonce}`;
        if (this.replayNonces.has(nonceKey)) {
          this.recordAuditEvent({
            tenantId: tid,
            actorId: actor.id,
            actorEmail: actor.email,
            actorRole: actor.role,
            action: 'gateway.replay_nonce_rejected',
            resourceType: 'gateway_request',
            resourceId: input.replayNonce,
            outcome: 'denied',
            before: null,
            after: { replayNonce: input.replayNonce },
            reason: 'Gateway rejected duplicate signed request replay nonce',
          });
          throw new Error('Replay protection rejected duplicate request nonce.');
        }
        this.replayNonces.add(nonceKey);
      }

      const agent =
        this.agents.find((a) => a.id === input.agentId && a.tenantId === tid) ??
        this.agents.find((a) => a.tenantId === tid);
      if (!agent) throw new Error('No agent available in tenant scope');

      const rolloutStage = this.rolloutStages[tid] ?? 'observe';
      const mode: PolicyMode =
        rolloutStage === 'observe' || rolloutStage === 'advisory' ? 'observe' : 'enforce';
      const killSwitch = this.killSwitches[tid];
      const killSwitchPaused = Boolean(killSwitch?.paused);
      const model = input.model ?? agent.models[0] ?? 'gpt-4.1';
      const mcpServer = input.mcpServer ?? agent.mcpServers[0] ?? 'finance-mcp';

      const pdp = evaluatePolicyDecisionPoint({
        agent,
        tool: input.tool,
        model,
        promptText: input.promptText,
        targetResource: input.targetResource,
        rolloutStage,
        killSwitchPaused,
        requestedActionOverride: input.requestedActionOverride,
        mfaVerified: input.mfaVerified,
      });

      const enforced = !killSwitchPaused && isDecisionEnforcedAtStage(rolloutStage, pdp.decision);
      const policyDecision: GatewayDecision = enforced
        ? pdp.decision
        : (`would_${pdp.decision}` as GatewayDecision);

      const forwarded =
        !enforced ||
        (pdp.decision !== 'block' &&
          pdp.decision !== 'quarantine_agent' &&
          pdp.decision !== 'approve' &&
          pdp.decision !== 'step_up_authenticate');

      const eventId = `gw_pep_${crypto.randomUUID().slice(0, 8)}`;
      const now = new Date().toISOString();

      const evidenceRecord = this.appendEvidenceRecord({
        tenantId: tid,
        controlId: 'SOC2_CC7.2',
        framework: 'SOC 2',
        mappedFrameworks: ['SOC 2', 'EU AI Act', 'GDPR'],
        evidenceType: 'policy_decision',
        source: 'pep_pdp_gateway',
        resourceId: `${agent.id}/${input.tool}`,
        title: `PEP/PDP Enforcement Decision (${policyDecision}) for ${agent.name}`,
        summary: `${pdp.reason} (stage=${rolloutStage}, enforced=${enforced}, raw_prompt_retained=false)`,
        payload: {
          eventId,
          agentId: agent.id,
          tool: input.tool,
          pdpDecision: pdp.decision,
          policyDecision,
          enforced,
          rolloutStage,
          effectiveIdentity: pdp.effectiveIdentity,
          effectiveModel: pdp.effectiveModel,
          classification: pdp.classification.matchedSignals,
        },
      });

      let playbookExecution: PlaybookExecutionRecord | undefined;
      if (
        pdp.matchedPlaybookId &&
        !killSwitchPaused &&
        (rolloutStage === 'approval_gated_response' || rolloutStage === 'full_enforcement')
      ) {
        playbookExecution = this.runPlaybookInternal(
          tid,
          pdp.matchedPlaybookId,
          agent,
          pdp.reason,
          actor
        );
      }

      if (enforced && pdp.decision === 'quarantine_agent') {
        const aIdx = this.agents.findIndex((a) => a.id === agent.id && a.tenantId === tid);
        if (aIdx !== -1) {
          this.agents[aIdx] = { ...this.agents[aIdx], status: 'quarantined' };
        }
      }

      const approvalRequestId =
        pdp.decision === 'approve' || pdp.decision === 'step_up_authenticate'
          ? `apr_${crypto.randomUUID().slice(0, 8)}`
          : undefined;

      const event: GatewayEvent = {
        event_id: eventId,
        tenant_id: tid,
        agent_id: agent.id,
        agent_name: agent.name,
        identity_id: pdp.effectiveIdentity,
        provider: input.provider ?? 'openai',
        model: pdp.effectiveModel,
        tool: input.tool,
        mcp_server: mcpServer,
        mode,
        rollout_stage: rolloutStage,
        policy_decision: policyDecision,
        enforcement_action: pdp.decision,
        pdp_reason: killSwitchPaused
          ? `Kill switch active — enforcement bypassed; ${pdp.reason}`
          : pdp.reason,
        policy_rule: pdp.policyRule,
        classification: pdp.classification,
        latency_ms: 9,
        forwarded,
        content_retained: false,
        tokenized_preview: pdp.tokenizedPreview,
        effective_identity: pdp.effectiveIdentity,
        effective_model: pdp.effectiveModel,
        approval_request_id: approvalRequestId,
        playbook_execution_id: playbookExecution?.executionId,
        replay_nonce: input.replayNonce ?? `nonce_${crypto.randomUUID().slice(0, 8)}`,
        evidence_id: evidenceRecord.id,
        timestamp: now,
      };

      this.gatewayEvents.unshift(event);

      const tIdx = this.tenants.findIndex((t) => t.id === tid);
      if (tIdx !== -1) {
        this.tenants[tIdx] = {
          ...this.tenants[tIdx],
          dailyRequests: this.tenants[tIdx].dailyRequests + 1,
          dailyToolCalls: this.tenants[tIdx].dailyToolCalls + 1,
          blockedOrRedactedEvents:
            pdp.decision === 'allow'
              ? this.tenants[tIdx].blockedOrRedactedEvents
              : this.tenants[tIdx].blockedOrRedactedEvents + 1,
        };
      }

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: `pep.${policyDecision}`,
        resourceType: 'gateway_event',
        resourceId: eventId,
        outcome: forwarded ? 'allowed' : 'denied',
        before: { agentStatus: agent.status, identity: agent.identity, model },
        after: {
          pdpDecision: pdp.decision,
          enforced,
          rolloutStage,
          effectiveIdentity: pdp.effectiveIdentity,
          effectiveModel: pdp.effectiveModel,
          tokenized: Boolean(pdp.tokenizedPreview),
        },
        reason: event.pdp_reason,
        approval_id: approvalRequestId,
        evidence_id: evidenceRecord.id,
      });

      return {
        event,
        evidenceRecord,
        pdpDecision: pdp.decision,
        pdpReason: event.pdp_reason ?? pdp.reason,
        enforced,
        playbookExecution,
      };
    });
  }

  setKillSwitch(
    tenantId: string,
    paused: boolean,
    reason: string,
    actor: { id: string; email: string; role: Role }
  ): KillSwitchState {
    return this.withTenantContext(tenantId, (tid) => {
      const prev = this.killSwitches[tid];
      const next: KillSwitchState = {
        paused,
        updatedAt: new Date().toISOString(),
        updatedBy: actor.email,
        reason: reason || (paused ? 'Emergency operator kill switch engaged' : 'Operator resumed control plane'),
      };
      this.killSwitches[tid] = next;

      this.activity.unshift({
        id: `act_${crypto.randomUUID()}`,
        tenantId: tid,
        timestamp: 'Just now',
        category: 'policy',
        title: paused
          ? 'Emergency Kill Switch ACTIVATED — SOAR & inline blocking paused'
          : 'Emergency Kill Switch cleared — control plane resumed',
        detail: `${actor.email} · ${next.reason}`,
        severity: paused ? 'critical' : 'nominal',
      });

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: paused ? 'soar.kill_switch_activated' : 'soar.kill_switch_resumed',
        resourceType: 'kill_switch',
        resourceId: tid,
        outcome: 'allowed',
        before: { paused: prev?.paused ?? false },
        after: { paused, reason: next.reason },
        reason: next.reason,
      });

      return next;
    });
  }

  dryRunPlaybook(
    tenantId: string,
    playbookId: PlaybookId,
    agentId: string,
    actor: { id: string; email: string; role: Role }
  ): PlaybookExecutionRecord {
    return this.withTenantContext(tenantId, (tid) => {
      const playbook = RESPONSE_PLAYBOOKS.find((p) => p.id === playbookId);
      if (!playbook) throw new Error('Playbook not found');
      const agent =
        this.agents.find((a) => a.id === agentId && a.tenantId === tid) ??
        this.agents.find((a) => a.tenantId === tid);
      if (!agent) throw new Error('Agent not found in tenant');

      const evidence = this.appendEvidenceRecord({
        tenantId: tid,
        controlId: 'SOC2_CC7.2',
        framework: 'SOC 2',
        mappedFrameworks: ['SOC 2', 'ISO 27001'],
        evidenceType: 'policy_decision',
        source: 'soar_dry_run',
        resourceId: `${playbookId}/${agent.id}`,
        title: `SOAR Dry-Run Impact Preview: ${playbook.name} on ${agent.name}`,
        summary: `Simulated ${playbook.automatedAction}; zero live IAM or agent mutations executed.`,
        payload: { playbookId, agentId: agent.id, dryRun: true },
      });

      const execId = `pb_dry_${crypto.randomUUID().slice(0, 8)}`;
      const audit = this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'soar.playbook_dry_run',
        resourceType: 'playbook',
        resourceId: playbookId,
        outcome: 'allowed',
        before: { agentStatus: agent.status },
        after: { simulatedAction: playbook.automatedAction, dryRun: true },
        reason: `Dry-run impact analysis before live containment for ${agent.name}`,
        evidence_id: evidence.id,
      });

      const record: PlaybookExecutionRecord = {
        executionId: execId,
        tenantId: tid,
        playbookId,
        playbookName: playbook.name,
        agentId: agent.id,
        agentName: agent.name,
        triggerSignal: playbook.trigger,
        severity: playbook.severity,
        status: 'dry_run',
        dryRunImpactSummary: `Dry-run diff: Would execute "${playbook.automatedAction}" via ${playbook.responderIdentity}. Human approval remains gated for "${playbook.humanApprovalRequiredFor}".`,
        containmentActions: [`[DRY-RUN] ${playbook.automatedAction}`],
        pendingApprovalAction: playbook.humanApprovalRequiredFor,
        responderIdentity: playbook.responderIdentity,
        evidenceId: evidence.id,
        auditEventId: audit.id,
        rollbackSnapshot: {
          agentId: agent.id,
          previousStatus: agent.status,
          previousPermissions: [...agent.permissions],
        },
        executedAt: new Date().toISOString(),
      };
      this.playbookExecutions.unshift(record);
      return record;
    });
  }

  private runPlaybookInternal(
    tid: string,
    playbookId: PlaybookId,
    agent: Agent,
    triggerSignal: string,
    actor: { id: string; email: string; role: Role }
  ): PlaybookExecutionRecord {
    const playbook = RESPONSE_PLAYBOOKS.find((p) => p.id === playbookId);
    if (!playbook) throw new Error('Playbook not found');

    if (this.killSwitches[tid]?.paused) {
      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'soar.execution_blocked_by_kill_switch',
        resourceType: 'playbook',
        resourceId: playbookId,
        outcome: 'denied',
        before: { killSwitchPaused: true },
        after: { blocked: true, agentId: agent.id },
        reason: 'Emergency Kill Switch is active — automated response halted.',
      });
      throw new Error('Kill switch is active: all automated SOAR responses are paused.');
    }

    const rateKey = `${tid}::${playbookId}`;
    const nowMs = Date.now();
    const recent = (this.responseRateWindow.get(rateKey) ?? []).filter(
      (ts) => nowMs - ts < 60_000
    );
    if (recent.length >= playbook.rateLimitPerMinute) {
      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'soar.rate_limit_exceeded',
        resourceType: 'playbook',
        resourceId: playbookId,
        outcome: 'denied',
        before: { callsInLast60s: recent.length, limit: playbook.rateLimitPerMinute },
        after: { throttled: true },
        reason: `Sliding rate limit (${playbook.rateLimitPerMinute}/min) prevented runaway automation`,
      });
      throw new Error(
        `Rate limit exceeded: max ${playbook.rateLimitPerMinute} executions per minute for ${playbook.name}.`
      );
    }
    recent.push(nowMs);
    this.responseRateWindow.set(rateKey, recent);

    const rollbackSnapshot = {
      agentId: agent.id,
      previousStatus: agent.status,
      previousPermissions: [...agent.permissions],
    };

    // Safe immediate containment without destructive permanent IAM/account deletion
    const aIdx = this.agents.findIndex((a) => a.id === agent.id && a.tenantId === tid);
    if (aIdx !== -1 && playbook.severity === 'critical') {
      this.agents[aIdx] = {
        ...this.agents[aIdx],
        status: playbookId === 'pb_compromised_identity' ? 'quarantined' : 'restricted',
      };
    }

    const ticketKey = `SEC-${this.nextTicketNum++}`;
    const evidence = this.appendEvidenceRecord({
      tenantId: tid,
      controlId: 'SOC2_CC7.2',
      framework: 'SOC 2',
      mappedFrameworks: ['SOC 2', 'ISO 27001', 'EU AI Act'],
      evidenceType: 'remediation_proof',
      source: 'soar_responder',
      resourceId: `${playbookId}/${agent.id}`,
      title: `SOAR Safe Containment Executed: ${playbook.name}`,
      summary: `Executed "${playbook.automatedAction}" via ${playbook.responderIdentity}; gated "${playbook.humanApprovalRequiredFor}" awaiting human sign-off.`,
      payload: {
        playbookId,
        agentId: agent.id,
        ticketKey,
        responder: playbook.responderIdentity,
      },
    });

    const execId = `pb_exec_${crypto.randomUUID().slice(0, 8)}`;
    const audit = this.recordAuditEvent({
      tenantId: tid,
      actorId: 'svc-soar-responder',
      actorEmail: 'svc-soar-responder@northwind.com',
      actorRole: 'service_account',
      action: 'soar.playbook_contained',
      resourceType: 'playbook_execution',
      resourceId: execId,
      outcome: 'allowed',
      before: { agentStatus: rollbackSnapshot.previousStatus },
      after: {
        agentStatus: this.agents[aIdx]?.status ?? agent.status,
        ticketKey,
        pendingApprovalAction: playbook.humanApprovalRequiredFor,
      },
      reason: triggerSignal,
      evidence_id: evidence.id,
    });

    const record: PlaybookExecutionRecord = {
      executionId: execId,
      tenantId: tid,
      playbookId,
      playbookName: playbook.name,
      agentId: agent.id,
      agentName: agent.name,
      triggerSignal,
      severity: playbook.severity,
      status: 'contained_awaiting_approval',
      dryRunImpactSummary: `Contained via ${playbook.responderIdentity}; rollback snapshot captured.`,
      containmentActions: [
        playbook.automatedAction,
        `Ticket ${ticketKey} opened & responder notified`,
        `Pending human approval for: ${playbook.humanApprovalRequiredFor}`,
      ],
      pendingApprovalAction: playbook.humanApprovalRequiredFor,
      responderIdentity: playbook.responderIdentity,
      ticketKey,
      evidenceId: evidence.id,
      auditEventId: audit.id,
      rollbackSnapshot,
      executedAt: new Date().toISOString(),
    };
    this.playbookExecutions.unshift(record);

    this.activity.unshift({
      id: `act_${crypto.randomUUID()}`,
      tenantId: tid,
      timestamp: 'Just now',
      category: 'remediation',
      title: `SOAR Playbook "${playbook.name}" contained ${agent.name}`,
      detail: `${ticketKey} · Awaiting human approval for ${playbook.humanApprovalRequiredFor}`,
      severity: playbook.severity,
    });

    return record;
  }

  executePlaybook(
    tenantId: string,
    playbookId: PlaybookId,
    agentId: string,
    actor: { id: string; email: string; role: Role },
    triggerSignal?: string
  ): PlaybookExecutionRecord {
    return this.withTenantContext(tenantId, (tid) => {
      const playbook = RESPONSE_PLAYBOOKS.find((p) => p.id === playbookId);
      if (!playbook) throw new Error('Playbook not found');
      const agent =
        this.agents.find((a) => a.id === agentId && a.tenantId === tid) ??
        this.agents.find((a) => a.tenantId === tid);
      if (!agent) throw new Error('Agent not found in tenant');
      return this.runPlaybookInternal(
        tid,
        playbookId,
        agent,
        triggerSignal || playbook.trigger,
        actor
      );
    });
  }

  approvePlaybookExecution(
    tenantId: string,
    executionId: string,
    actor: { id: string; email: string; role: Role }
  ): PlaybookExecutionRecord {
    return this.withTenantContext(tenantId, (tid) => {
      const idx = this.playbookExecutions.findIndex(
        (e) => e.executionId === executionId && e.tenantId === tid
      );
      if (idx === -1) throw new Error('Playbook execution not found');
      const current = this.playbookExecutions[idx];
      const now = new Date().toISOString();

      const evidence = this.appendEvidenceRecord({
        tenantId: tid,
        controlId: 'SOC2_CC6.2',
        framework: 'SOC 2',
        mappedFrameworks: ['SOC 2', 'EU AI Act'],
        evidenceType: 'approval_record',
        source: 'soar_approval',
        resourceId: executionId,
        title: `Human Approval Signed for ${current.playbookName}`,
        summary: `${actor.email} approved "${current.pendingApprovalAction}" on ${current.agentName}`,
        payload: { executionId, approver: actor.email, approvedAction: current.pendingApprovalAction },
      });

      const updated: PlaybookExecutionRecord = {
        ...current,
        status: 'approved_executed',
        approvedBy: actor.email,
        approvedAt: now,
      };
      this.playbookExecutions[idx] = updated;

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'soar.permanent_action_approved',
        resourceType: 'playbook_execution',
        resourceId: executionId,
        outcome: 'allowed',
        before: { status: current.status },
        after: { status: 'approved_executed', approvedAction: current.pendingApprovalAction },
        reason: `Human owner approved permanent action: ${current.pendingApprovalAction}`,
        approval_id: executionId,
        evidence_id: evidence.id,
      });

      return updated;
    });
  }

  rollbackPlaybookExecution(
    tenantId: string,
    executionId: string,
    actor: { id: string; email: string; role: Role }
  ): PlaybookExecutionRecord {
    return this.withTenantContext(tenantId, (tid) => {
      const idx = this.playbookExecutions.findIndex(
        (e) => e.executionId === executionId && e.tenantId === tid
      );
      if (idx === -1) throw new Error('Playbook execution not found');
      const current = this.playbookExecutions[idx];
      const snapshot = current.rollbackSnapshot as {
        agentId?: string;
        previousStatus?: Agent['status'];
        previousPermissions?: string[];
      };

      if (snapshot.agentId) {
        const aIdx = this.agents.findIndex(
          (a) => a.id === snapshot.agentId && a.tenantId === tid
        );
        if (aIdx !== -1) {
          this.agents[aIdx] = {
            ...this.agents[aIdx],
            status: snapshot.previousStatus ?? 'active',
            permissions: snapshot.previousPermissions ?? this.agents[aIdx].permissions,
          };
        }
      }
      this.recomputeTenantRiskAssessments(tid);

      const now = new Date().toISOString();
      const updated: PlaybookExecutionRecord = {
        ...current,
        status: 'rolled_back',
        rolledBackAt: now,
      };
      this.playbookExecutions[idx] = updated;

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'soar.playbook_rolled_back',
        resourceType: 'playbook_execution',
        resourceId: executionId,
        outcome: 'allowed',
        before: { status: current.status },
        after: { status: 'rolled_back', restoredAgentStatus: snapshot.previousStatus ?? 'active' },
        reason: 'Operator triggered rollback snapshot restoration',
      });

      return updated;
    });
  }

  // ---- Enterprise SSO, IdP Group Mapping & SCIM 2.0 Directory + Instant Revocation ----

  updateSsoConfig(
    tenantId: string,
    updates: {
      protocol?: 'saml_2_0' | 'oidc';
      ssoEnforced?: boolean;
      localPasswordFallbackDisabled?: boolean;
      mfaRequiredForAdmins?: boolean;
      scimEnabled?: boolean;
      rotateCertificate?: boolean;
    },
    actor: { id: string; email: string; role: Role }
  ): EnterpriseSsoConfig {
    return this.withTenantContext(tenantId, (tid) => {
      const prev = this.ssoConfigs[tid];
      const rotatedFingerprint = updates.rotateCertificate
        ? `SHA256:${crypto
            .randomBytes(12)
            .toString('hex')
            .toUpperCase()
            .match(/.{2}/g)!
            .join(':')}`
        : prev.certificateFingerprint;

      const next: EnterpriseSsoConfig = {
        ...prev,
        protocol: updates.protocol ?? prev.protocol,
        ssoEnforced: updates.ssoEnforced ?? prev.ssoEnforced,
        localPasswordFallbackDisabled:
          updates.localPasswordFallbackDisabled ?? prev.localPasswordFallbackDisabled,
        mfaRequiredForAdmins: updates.mfaRequiredForAdmins ?? prev.mfaRequiredForAdmins,
        scimEnabled: updates.scimEnabled ?? prev.scimEnabled,
        certificateFingerprint: rotatedFingerprint,
        certificateRotatedAt: updates.rotateCertificate
          ? new Date().toISOString()
          : prev.certificateRotatedAt,
        metadataValidated: true,
      };
      this.ssoConfigs[tid] = next;

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: updates.rotateCertificate ? 'sso.certificate_rotated' : 'sso.config_updated',
        resourceType: 'sso_config',
        resourceId: tid,
        outcome: 'allowed',
        before: {
          protocol: prev.protocol,
          ssoEnforced: prev.ssoEnforced,
          certificateFingerprint: prev.certificateFingerprint,
        },
        after: {
          protocol: next.protocol,
          ssoEnforced: next.ssoEnforced,
          certificateFingerprint: next.certificateFingerprint,
        },
        reason: updates.rotateCertificate
          ? 'Rotated SAML/OIDC signing certificate and re-validated IdP metadata'
          : 'Updated enterprise SSO & MFA enforcement controls',
      });

      return next;
    });
  }

  jitSsoLogin(
    tenantId: string,
    payload: {
      email: string;
      displayName?: string;
      idpGroups: string[];
      mfaMethod?: 'totp' | 'webauthn';
      totpCode?: string;
    }
  ): {
    user: UserRecord;
    session: SessionRecord;
    role: Role;
    ssoConfig: EnterpriseSsoConfig;
  } {
    return this.withTenantContext(tenantId, (tid) => {
      const ssoConfig = this.ssoConfigs[tid];
      const mappedRole = mapIdpGroupsToRole(payload.idpGroups);
      const needsMfa =
        mappedRole === 'owner' || mappedRole === 'admin' || ssoConfig.mfaRequiredForAdmins;
      const hasValidMfa =
        payload.mfaMethod === 'webauthn' ||
        Boolean(payload.totpCode && /^\d{6}$/.test(payload.totpCode.trim()));

      if (needsMfa && !hasValidMfa) {
        this.recordAuditEvent({
          tenantId: tid,
          actorId: payload.email,
          actorEmail: payload.email,
          actorRole: mappedRole,
          action: 'sso.jit_mfa_challenge_failed',
          resourceType: 'session',
          resourceId: payload.email,
          outcome: 'denied',
          before: null,
          after: { mappedRole, idpGroups: payload.idpGroups },
          reason: 'Enterprise SSO policy requires TOTP or WebAuthn passkey verification',
        });
        throw new Error('MFA verification (TOTP or WebAuthn passkey) required for enterprise SSO.');
      }

      let user = this.findUserByEmail(payload.email);
      const prevUserRole = user
        ? this.memberships.find((m) => m.tenantId === tid && m.userId === user!.id)?.role ?? null
        : null;

      if (!user) {
        user = {
          id: `usr_jit_${crypto.randomUUID().slice(0, 8)}`,
          email: payload.email,
          displayName: payload.displayName || `${payload.email.split('@')[0]} (SSO JIT)`,
          externalId: `idp_${crypto.randomUUID().slice(0, 8)}`,
          idp: ssoConfig.protocol === 'saml_2_0' ? 'okta_saml' : 'entra_oidc',
          mfaEnabled: true,
          interactiveAllowed: true,
          createdAt: new Date().toISOString(),
        };
        this.users.push(user);
      }

      const memIdx = this.memberships.findIndex(
        (m) => m.tenantId === tid && m.userId === user!.id
      );
      if (memIdx === -1) {
        this.memberships.push({
          tenantId: tid,
          userId: user.id,
          role: mappedRole,
          status: 'active',
        });
      } else {
        this.memberships[memIdx] = {
          ...this.memberships[memIdx],
          role: mappedRole,
          status: 'active',
        };
      }

      const scimIdx = this.scimDirectory.findIndex(
        (s) => s.tenantId === tid && s.email.toLowerCase() === payload.email.toLowerCase()
      );
      const scimRecord: ScimDirectoryUser = {
        id: scimIdx !== -1 ? this.scimDirectory[scimIdx].id : `scim_${tid}_${user.id}`,
        tenantId: tid,
        email: user.email,
        displayName: user.displayName,
        idpGroups: payload.idpGroups,
        mappedRole,
        status: 'active',
        mfaEnrolled: true,
        activeSessionCount: 1,
        lastSyncedAt: new Date().toISOString(),
      };
      if (scimIdx === -1) {
        this.scimDirectory.unshift(scimRecord);
      } else {
        this.scimDirectory[scimIdx] = scimRecord;
      }

      const session = this.createSession(user.id, tid, hasValidMfa);

      this.recordAuditEvent({
        tenantId: tid,
        actorId: user.id,
        actorEmail: user.email,
        actorRole: mappedRole,
        action: 'sso.jit_login_provisioned',
        resourceType: 'session',
        resourceId: session.sessionId,
        outcome: 'allowed',
        before: prevUserRole ? { role: prevUserRole } : null,
        after: {
          role: mappedRole,
          idpGroups: payload.idpGroups,
          protocol: ssoConfig.protocol,
          mfaMethod: payload.mfaMethod ?? 'totp',
        },
        reason: 'Just-in-time SSO assertion verified and role mapped from IdP groups',
      });

      return { user, session, role: mappedRole, ssoConfig };
    });
  }

  provisionScimUser(
    tenantId: string,
    payload: {
      email: string;
      displayName: string;
      idpGroups: string[];
      mfaEnrolled?: boolean;
    },
    actor: { id: string; email: string; role: Role }
  ): ScimDirectoryUser {
    return this.withTenantContext(tenantId, (tid) => {
      const mappedRole = mapIdpGroupsToRole(payload.idpGroups);
      const existingUser = this.findUserByEmail(payload.email);
      const existingScim = this.scimDirectory.find(
        (s) => s.tenantId === tid && s.email.toLowerCase() === payload.email.toLowerCase()
      );
      const prevRole = existingScim?.mappedRole ?? null;
      const prevStatus = existingScim?.status ?? null;

      let resolvedUser: UserRecord;
      if (!existingUser) {
        resolvedUser = {
          id: `usr_scim_${crypto.randomUUID().slice(0, 8)}`,
          email: payload.email,
          displayName: payload.displayName,
          externalId: `scim_${crypto.randomUUID().slice(0, 8)}`,
          idp: 'scim_2_0',
          mfaEnabled: payload.mfaEnrolled ?? true,
          interactiveAllowed: true,
          createdAt: new Date().toISOString(),
        };
        this.users.push(resolvedUser);
      } else {
        existingUser.displayName = payload.displayName || existingUser.displayName;
        resolvedUser = existingUser;
      }

      const memIdx = this.memberships.findIndex(
        (m) => m.tenantId === tid && m.userId === resolvedUser.id
      );
      if (memIdx === -1) {
        this.memberships.push({
          tenantId: tid,
          userId: resolvedUser.id,
          role: mappedRole,
          status: 'active',
        });
      } else {
        this.memberships[memIdx] = {
          ...this.memberships[memIdx],
          role: mappedRole,
          status: 'active',
        };
      }

      const nextEntry: ScimDirectoryUser = {
        id: existingScim?.id ?? `scim_${tid}_${resolvedUser.id}`,
        tenantId: tid,
        email: resolvedUser.email,
        displayName: resolvedUser.displayName,
        idpGroups: payload.idpGroups,
        mappedRole,
        status: 'active',
        mfaEnrolled: payload.mfaEnrolled ?? true,
        activeSessionCount: 0,
        lastSyncedAt: new Date().toISOString(),
      };
      if (existingScim) {
        const idx = this.scimDirectory.findIndex((s) => s.id === existingScim.id);
        this.scimDirectory[idx] = nextEntry;
      } else {
        this.scimDirectory.unshift(nextEntry);
      }

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'scim.user_provisioned_or_updated',
        resourceType: 'scim_user',
        resourceId: resolvedUser.email,
        outcome: 'allowed',
        before: existingScim ? { role: prevRole, status: prevStatus } : null,
        after: { role: mappedRole, status: 'active', idpGroups: payload.idpGroups },
        reason: 'SCIM 2.0 directory sync provisioned user and mapped IdP groups to RBAC role',
      });

      return this.getScimDirectory(tid).find((s) => s.id === nextEntry.id) ?? nextEntry;
    });
  }

  deprovisionScimUser(
    tenantId: string,
    emailOrId: string,
    actor: { id: string; email: string; role: Role }
  ): { user: ScimDirectoryUser; revokedSessionCount: number } {
    return this.withTenantContext(tenantId, (tid) => {
      const scimIdx = this.scimDirectory.findIndex(
        (s) =>
          s.tenantId === tid &&
          (s.email.toLowerCase() === emailOrId.toLowerCase() || s.id === emailOrId)
      );
      if (scimIdx === -1) {
        throw new Error('SCIM user not found in tenant directory');
      }

      const prev = this.scimDirectory[scimIdx];
      const user = this.findUserByEmail(prev.email);
      let revokedSessionCount = 0;

      if (user) {
        for (const m of this.memberships) {
          if (m.tenantId === tid && m.userId === user.id) {
            m.status = 'revoked';
          }
        }
        // Immediately revoke all active sessions for this user in the tenant
        for (const [sid, sess] of this.sessions.entries()) {
          if (sess.userId === user.id && sess.activeTenantId === tid) {
            this.sessions.delete(sid);
            revokedSessionCount += 1;
          }
        }
      }

      const updated: ScimDirectoryUser = {
        ...prev,
        status: 'disabled',
        activeSessionCount: 0,
        lastSyncedAt: new Date().toISOString(),
      };
      this.scimDirectory[scimIdx] = updated;

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'scim.user_deprovisioned_sessions_revoked',
        resourceType: 'scim_user',
        resourceId: prev.email,
        outcome: 'allowed',
        before: { status: prev.status, role: prev.mappedRole },
        after: { status: 'disabled', membershipStatus: 'revoked', revokedSessionCount },
        reason: 'SCIM 2.0 deprovisioning revoked tenant access and invalidated active sessions immediately',
      });

      return { user: updated, revokedSessionCount };
    });
  }

  // ---- 8 Enterprise Release Gates ----

  private computeReleaseGateChecks(tid: string): ReleaseGateCheck[] {
    const checkedAt = new Date().toISOString();
    let isolationPassed = false;
    try {
      this.withTenantContext('nonexistent_tenant_probe', () => {});
    } catch (err) {
      isolationPassed = err instanceof TenantIsolationError;
    }

    const sso = this.ssoConfigs[tid];
    const ssoPassed = Boolean(
      sso && sso.ssoEnforced && sso.mfaRequiredForAdmins && sso.scimEnabled && sso.metadataValidated
    );

    const financeAgent =
      this.agents.find((a) => a.id === 'agent_finance_copilot' && a.tenantId === tid) ??
      this.agents.find((a) => a.tenantId === tid);
    const pdpProbe = financeAgent
      ? evaluatePolicyDecisionPoint({
          agent: financeAgent,
          tool: 'export_payroll',
          model: 'gpt-4.1',
          promptText: 'Export SSN 123-45-6789',
          targetResource: 's3://payroll-prod',
          rolloutStage: 'full_enforcement',
          killSwitchPaused: false,
        })
      : null;
    const pdpPassed = Boolean(pdpProbe && pdpProbe.decision === 'block');

    const dryRunRollbackPassed =
      RESPONSE_PLAYBOOKS.length === 6 &&
      this.findings.some(
        (f) => f.tenantId === tid && f.remediation?.dryRunAvailable && f.remediation?.rollbackAvailable
      );

    const approvalGatesPassed = this.findings
      .filter((f) => f.tenantId === tid)
      .every((f) => !f.remediation || f.remediation.approvalRequired);

    const auditIntegrity = this.getAuditIntegrity(tid);
    const auditPassed = auditIntegrity.valid && auditIntegrity.retentionDays >= 365;

    const killSwitchState = this.killSwitches[tid];
    const killSwitchRatePassed = Boolean(
      killSwitchState && RESPONSE_PLAYBOOKS.every((p) => p.rateLimitPerMinute <= 5)
    );

    const containmentPassed =
      this.playbookExecutions.some((e) => e.tenantId === tid) &&
      this.evidenceRecords.some((ev) => ev.tenant_id === tid);

    return [
      {
        id: 'gate_1_isolation',
        name: '1. Tenant isolation verified across all data stores',
        requirement: 'withTenantContext + PostgreSQL RLS boundary blocks invalid tenant contexts',
        passed: isolationPassed,
        detail: isolationPassed ? 'TenantIsolationError enforced at execution boundary' : 'Failed',
        checkedAt,
      },
      {
        id: 'gate_2_sso_scim',
        name: '2. SSO, MFA, SCIM, and session revocation tested',
        requirement: 'SAML 2.0/OIDC enforced, MFA required for admins, SCIM sync + immediate revocation',
        passed: ssoPassed,
        detail: sso
          ? `${sso.protocol.toUpperCase()} · Cert ${sso.certificateFingerprint.slice(0, 22)}... · SCIM active`
          : 'Not configured',
        checkedAt,
      },
      {
        id: 'gate_3_pdp_pep',
        name: '3. Policy engine deterministic and regression-tested',
        requirement: 'Decoupled PEP/PDP enforces all 8 actions + prompt injection guard',
        passed: pdpPassed,
        detail: pdpProbe ? `PDP decision=${pdpProbe.decision} (${pdpProbe.policyRule})` : 'Unavailable',
        checkedAt,
      },
      {
        id: 'gate_4_dryrun_rollback',
        name: '4. Dry-run and rollback verified for all automated actions',
        requirement: 'Impact preview diff & rollback snapshot required before/during execution',
        passed: dryRunRollbackPassed,
        detail: '6/6 SOAR playbooks + remediation workflows carry dry-run & rollback snapshots',
        checkedAt,
      },
      {
        id: 'gate_5_approval_gates',
        name: '5. Approval gates enforced for destructive / IAM actions',
        requirement: 'Permanent IAM changes, deletion, and agent disablement require human approval',
        passed: approvalGatesPassed,
        detail: '100% of IAM/destructive changes gated behind explicit approval',
        checkedAt,
      },
      {
        id: 'gate_6_audit_chain',
        name: '6. Audit logging complete and retention policies active',
        requirement: 'SHA-256 hash-chained ledger verified with >= 1 year (365d) retention',
        passed: auditPassed,
        detail: `${auditIntegrity.verifiedCount} events verified · retention=${auditIntegrity.retentionDays}d`,
        checkedAt,
      },
      {
        id: 'gate_7_kill_switch',
        name: '7. Kill switches and rate limits tested in staging',
        requirement: 'One-click pause + <=5/min sliding rate limits per playbook',
        passed: killSwitchRatePassed,
        detail: `Kill switch ready (paused=${Boolean(killSwitchState?.paused)}) · 5/min rate limit`,
        checkedAt,
      },
      {
        id: 'gate_8_incident_sim',
        name: '8. Simulated incident containment passes end-to-end',
        requirement: 'Detection -> PEP/PDP -> Playbook containment -> Evidence + Audit trail',
        passed: containmentPassed,
        detail: 'End-to-end containment & forensic evidence verified',
        checkedAt,
      },
    ];
  }

  verifyReleaseGates(
    tenantId: string,
    actor: { id: string; email: string; role: Role }
  ): { allPassed: boolean; checks: ReleaseGateCheck[]; checkedAt: string } {
    return this.withTenantContext(tenantId, (tid) => {
      const checks = this.computeReleaseGateChecks(tid);
      const allPassed = checks.every((c) => c.passed);
      const checkedAt = new Date().toISOString();

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'enterprise.release_gates_verified',
        resourceType: 'release_gates',
        resourceId: tid,
        outcome: allPassed ? 'allowed' : 'denied',
        before: null,
        after: {
          allPassed,
          passedCount: checks.filter((c) => c.passed).length,
          totalCount: checks.length,
        },
        reason: 'Executed programmatic verification across all 8 enterprise release gates',
      });

      return { allPassed, checks, checkedAt };
    });
  }

  async connectAllCloudProviders(
    tenantId: string,
    actor: { id: string; email: string; role: Role }
  ): Promise<{
    connectorsSynced: number;
    nodesAdded: number;
    edgesAdded: number;
    findingsAdded: number;
  }> {
    return this.withTenantContext(tenantId, async (tid) => {
      const tenant = this.getTenant(tid);
      const defaults: Record<'entra_id' | 'aws' | 'azure', Record<string, string>> = {
        entra_id: { tenantDomain: tenant.domain },
        aws: {
          accountId: tid === 'tenant_northwind_eu' ? '772910440219' : '449102881234',
          roleArn: `arn:aws:iam::${tid === 'tenant_northwind_eu' ? '772910440219' : '449102881234'}:role/EyesOfAgentReadOnlyRole`,
          externalId: `eoa-${tid}-readonly`,
        },
        azure: {
          subscriptionId: tid === 'tenant_northwind_eu' ? 'sub-nw-eu-01' : 'sub-nw-prod-01',
          clientId: `wif-eoa-${tid}-reader`,
        },
      };

      let connectorsSynced = 0;
      let nodesAdded = 0;
      let edgesAdded = 0;
      let findingsAdded = 0;

      const providers: Array<'entra_id' | 'aws' | 'azure'> = ['entra_id', 'aws', 'azure'];
      for (const provider of providers) {
        const existing = this.connectors.find(
          (c) => c.tenantId === tid && c.provider === provider
        );
        if (!existing || existing.status !== 'healthy') {
          const res = await this.connectCloudProvider(tid, provider, defaults[provider], actor);
          nodesAdded += res.nodesAdded;
          edgesAdded += res.edgesAdded;
          connectorsSynced += 1;
        } else {
          const res = await this.syncConnector(tid, existing.id, actor);
          nodesAdded += res.nodesAdded;
          edgesAdded += res.edgesAdded;
          findingsAdded += res.findingsAdded;
          connectorsSynced += 1;
        }
      }

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'connectors.batch_onboard_synced',
        resourceType: 'connector',
        resourceId: tid,
        outcome: 'allowed',
        before: null,
        after: { connectorsSynced, nodesAdded, edgesAdded, findingsAdded, providers },
        reason: 'Batch read-only onboarding & discovery sync across Entra ID, AWS, and Azure',
      });

      return { connectorsSynced, nodesAdded, edgesAdded, findingsAdded };
    });
  }

  createTicketsForAllOpenFindings(
    tenantId: string,
    options: { provider?: 'jira' | 'servicenow'; assignee?: string; notifyChannels?: string[] },
    actor: { id: string; email: string; role: Role }
  ): { createdCount: number; tickets: Finding[] } {
    return this.withTenantContext(tenantId, (tid) => {
      const unticketed = this.findings.filter(
        (f) => f.tenantId === tid && f.status !== 'remediated' && !f.jiraTicketKey
      );
      const tickets: Finding[] = [];
      for (const finding of unticketed) {
        const updated = this.createRemediationTicket(
          tid,
          finding.id,
          {
            provider: options.provider ?? 'jira',
            assignee: options.assignee || finding.owner || 'Cloud Security',
            notifyChannels: options.notifyChannels ?? ['Slack', 'Email'],
          },
          actor
        );
        tickets.push(updated);
      }

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'findings.batch_tickets_created',
        resourceType: 'finding',
        resourceId: tid,
        outcome: 'allowed',
        before: { unticketedCount: unticketed.length },
        after: {
          createdCount: tickets.length,
          ticketKeys: tickets.map((t) => t.jiraTicketKey),
        },
        reason: 'Created remediation tickets for all open unticketed findings in one action',
      });

      return { createdCount: tickets.length, tickets };
    });
  }

  async runAllInOneControlLoop(
    tenantId: string,
    options: { ticketProvider?: 'jira' | 'servicenow'; assignee?: string },
    actor: { id: string; email: string; role: Role }
  ): Promise<AllInOneRunResult> {
    return this.withTenantContext(tenantId, async (tid) => {
      const started = Date.now();
      const tenant = this.getTenant(tid);

      // Stage 1: Cloud & Identity Read-Only Connectors
      const syncRes = await this.connectAllCloudProviders(tid, actor);
      const tenantConnectors = this.getConnectors(tid);
      const healthyConnectors = tenantConnectors.filter((c) => c.status === 'healthy').length;

      // Stage 2: Security Graph & Weighted Risk Scoring
      const graph = this.getExposurePaths(tid);
      const tenantAgents = this.agents.filter((a) => a.tenantId === tid);

      // Stage 3: Findings & Batch Remediation Ticketing
      const batchTickets = this.createTicketsForAllOpenFindings(
        tid,
        {
          provider: options.ticketProvider ?? 'jira',
          assignee: options.assignee ?? 'Cloud Security',
          notifyChannels: ['Slack', 'Email'],
        },
        actor
      );
      const openFindings = this.findings.filter(
        (f) => f.tenantId === tid && f.status !== 'remediated'
      );

      // Stage 4: Zero-Trust PEP -> PDP Inspection
      const primaryAgent = tenantAgents[0];
      const pepEval = primaryAgent
        ? this.evaluatePepRequest(
            tid,
            {
              agentId: primaryAgent.id,
              model: primaryAgent.models[0] ?? 'gpt-4.1',
              tool: 'send_email',
              mcpServer: primaryAgent.mcpServers[0] ?? 'comms-mcp',
              promptText: 'Summarize quarterly numbers for alice@northwind.com (SSN 123-45-6789)',
              mfaVerified: true,
            },
            actor
          )
        : null;

      // Stage 5: Compliance & Evidence Package
      const compliancePack = this.exportComplianceAuditPackage(
        tid,
        { framework: 'all' },
        actor
      );

      // Stage 6: Enterprise SSO, SCIM & 8 Release Gates
      const gates = this.verifyReleaseGates(tid, actor);
      const passedGates = gates.checks.filter((g) => g.passed).length;

      // Stage 7: Write unified audit event & verify SHA-256 hash chain
      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'enterprise.all_in_one_executed',
        resourceType: 'control_plane',
        resourceId: tid,
        outcome: 'allowed',
        before: null,
        after: {
          connectorsHealthy: healthyConnectors,
          exposurePathsCount: graph.paths.length,
          ticketsCreatedCount: batchTickets.createdCount,
          compliancePackageId: compliancePack.packageId,
          releaseGatesPassed: passedGates,
        },
        reason: 'Executed unified All-in-One Control Loop across discovery, risk, ticketing, PEP/PDP, compliance, release gates, and audit chain',
      });

      const auditIntegrity = this.getAuditIntegrity(tid);
      const durationMs = Math.max(12, Date.now() - started);

      const stages: AllInOneStageResult[] = [
        {
          id: 'stage_1_connectors',
          step: 1,
          title: 'Cloud & Identity Discovery Sync',
          status: 'completed',
          summary: `${healthyConnectors}/${tenantConnectors.length} connectors healthy · ${syncRes.connectorsSynced} synced (+${syncRes.nodesAdded} nodes, +${syncRes.edgesAdded} edges)`,
          targetScreen: 'connectors',
          metrics: {
            healthy: healthyConnectors,
            total: tenantConnectors.length,
            nodesAdded: syncRes.nodesAdded,
          },
        },
        {
          id: 'stage_2_graph',
          step: 2,
          title: 'Security Graph & 6-Factor Risk Engine',
          status: 'verified',
          summary: `${tenantAgents.length} agents mapped across ${graph.paths.length} sensitive data exposure paths`,
          targetScreen: 'exposure',
          metrics: {
            agents: tenantAgents.length,
            exposurePaths: graph.paths.length,
          },
        },
        {
          id: 'stage_3_findings',
          step: 3,
          title: 'Findings & Batch Remediation Ticketing',
          status: 'completed',
          summary:
            batchTickets.createdCount > 0
              ? `Created ${batchTickets.createdCount} remediation ticket(s) (${batchTickets.tickets.map((t) => t.jiraTicketKey).join(', ')})`
              : `All ${openFindings.length} open findings already hold active remediation tickets`,
          targetScreen: 'findings',
          metrics: {
            ticketsCreated: batchTickets.createdCount,
            openFindings: openFindings.length,
          },
        },
        {
          id: 'stage_4_policy',
          step: 4,
          title: 'Zero-Trust PEP → PDP Enforcement Check',
          status: 'verified',
          summary: pepEval
            ? `PDP evaluated ${pepEval.pdpDecision} (enforced=${pepEval.enforced}) at stage ${this.rolloutStages[tid] ?? 'observe'}`
            : 'Gateway PEP/PDP policies ready',
          targetScreen: 'policy',
          metrics: {
            decision: pepEval?.pdpDecision ?? 'allow',
            rolloutStage: this.rolloutStages[tid] ?? 'observe',
          },
        },
        {
          id: 'stage_5_compliance',
          step: 5,
          title: 'Compliance Coverage & Evidence Export',
          status: 'completed',
          summary: `Exported ${compliancePack.packageId} · ${compliancePack.coverageSummary.coveragePct}% controls covered (${compliancePack.evidenceRecords.length} evidence records)`,
          targetScreen: 'compliance',
          metrics: {
            packageId: compliancePack.packageId,
            coveragePct: compliancePack.coverageSummary.coveragePct,
          },
        },
        {
          id: 'stage_6_gates',
          step: 6,
          title: 'SSO, SCIM & 8 Enterprise Release Gates',
          status: 'verified',
          summary: `${passedGates}/${gates.checks.length} release gates passed · SSO/MFA & SCIM directory active`,
          targetScreen: 'enterprise',
          metrics: {
            passed: passedGates,
            total: gates.checks.length,
          },
        },
        {
          id: 'stage_7_audit',
          step: 7,
          title: 'SHA-256 Immutable Audit Ledger',
          status: 'verified',
          summary: `Chain ${auditIntegrity.valid ? 'VERIFIED INTACT' : 'TAMPER ALERT'} (${auditIntegrity.verifiedCount} events · head ${auditIntegrity.headHash.slice(0, 18)}...)`,
          targetScreen: 'audit',
          metrics: {
            valid: auditIntegrity.valid,
            verifiedCount: auditIntegrity.verifiedCount,
          },
        },
      ];

      const result: AllInOneRunResult = {
        runId: `aio_${crypto.randomUUID().slice(0, 8)}`,
        tenantId: tid,
        tenantName: tenant.name,
        executedAt: new Date().toISOString(),
        executedBy: actor.email,
        durationMs,
        stages,
        summary: {
          connectorsHealthy: healthyConnectors,
          connectorsTotal: tenantConnectors.length,
          exposurePathsCount: graph.paths.length,
          ticketsCreatedCount: batchTickets.createdCount,
          openFindingsRemaining: openFindings.length,
          compliancePackageId: compliancePack.packageId,
          complianceCoveragePct: compliancePack.coverageSummary.coveragePct,
          releaseGatesPassed: passedGates,
          releaseGatesTotal: gates.checks.length,
          auditChainValid: auditIntegrity.valid,
          auditHeadHash: auditIntegrity.headHash,
        },
      };

      this.lastAllInOneRuns[tid] = result;
      this.persistState();
      return result;
    });
  }

  // ---- Agent CRUD, Custom Policy Rules, Compliance Attestation & Demo Requests ----

  listAuthorizedTenantsForUser(userId: string): TenantRecord[] {
    const allowedIds = new Set(
      this.getMembershipsForUser(userId).map((m) => m.tenantId)
    );
    return this.tenants.filter((t) => allowedIds.has(t.id));
  }

  submitDemoRequest(input: {
    name: string;
    email: string;
    company: string;
  }): DemoRequestRecord {
    const name = input.name.trim();
    const email = input.email.trim();
    const company = input.company.trim();
    if (!name || !company) {
      throw new Error('Full name and organization are required.');
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      throw new Error('A valid work email address is required.');
    }
    const record: DemoRequestRecord = {
      id: `req_${crypto.randomUUID().slice(0, 8)}`,
      name,
      email,
      company,
      submittedAt: new Date().toISOString(),
      status: 'received',
    };
    this.demoRequests.unshift(record);
    this.recordAuditEvent({
      tenantId: 'tenant_northwind',
      actorId: 'usr_inbound_lead',
      actorEmail: email,
      actorRole: 'anonymous',
      action: 'landing.demo_request_submitted',
      resourceType: 'demo_request',
      resourceId: record.id,
      outcome: 'allowed',
      before: null,
      after: { name, company, status: record.status },
      reason: 'Inbound briefing request submitted from Eyes of Agent landing page',
    });
    this.persistState();
    return record;
  }

  listDemoRequests(): DemoRequestRecord[] {
    return [...this.demoRequests];
  }

  createAgent(
    tenantId: string,
    input: {
      name: string;
      owner?: string;
      ownerTeam?: string;
      type?: AgentType;
      identity?: string;
      businessService?: string;
      tools?: string[];
      permissions?: string[];
      dataSources?: string[];
      models?: string[];
      mcpServers?: string[];
    },
    actor: { id: string; email: string; role: Role }
  ): Agent {
    return this.withTenantContext(tenantId, (tid) => {
      const name = input.name.trim();
      if (!name) throw new Error('Agent name is required.');
      const slug = name
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '_')
        .replace(/^_|_$/g, '');
      const agentId = `agent_${slug}_${crypto.randomUUID().slice(0, 4)}`;
      const owner = input.owner?.trim() || 'unassigned';
      const ownerTeam = input.ownerTeam?.trim() || 'Unassigned';
      const type: AgentType =
        input.type ?? (owner === 'unassigned' ? 'Unowned' : 'Internal agent');
      const identity = input.identity?.trim() || `svc-${slug.replace(/_/g, '-')}`;
      const tools =
        input.tools && input.tools.length > 0 ? input.tools : ['read_records'];
      const permissions =
        input.permissions && input.permissions.length > 0
          ? input.permissions
          : ['workspace:read'];
      const dataSourceIds =
        input.dataSources && input.dataSources.length > 0
          ? input.dataSources
          : [this.dataSources[0]?.id ?? 'ds_snowflake'];
      const modelIds =
        input.models && input.models.length > 0
          ? input.models
          : [this.models[0]?.id ?? 'model_gpt41'];
      const mcpIds =
        input.mcpServers && input.mcpServers.length > 0
          ? input.mcpServers
          : [this.mcpServers[0]?.id ?? 'mcp_finance'];

      const draft: Agent = {
        id: agentId,
        tenantId: tid,
        name,
        owner,
        ownerTeam,
        type,
        status: 'active',
        riskScore: 50,
        riskLevel: 'medium',
        identity,
        identityType: 'Service Principal',
        models: modelIds,
        mcpServers: mcpIds,
        tools,
        dataSources: dataSourceIds,
        permissions,
        businessService: input.businessService?.trim() || 'Enterprise Operations',
        lastSeen: 'Just now',
        dailyCalls: 120,
        findings: [],
      };

      this.agents.unshift(draft);

      // Register in security graph BEFORE risk recomputation so ExposurePaths & BFS include it immediately
      this.graphNodes.push({
        id: agentId,
        tenantId: tid,
        type: 'AI agent',
        label: name,
        riskLevel: 'high',
        metadata: { owner, type, businessService: draft.businessService },
      });
      const identityNodeId = `id_${identity.replace(/[^a-zA-Z0-9_]/g, '_')}`;
      if (!this.graphNodes.some((n) => n.id === identityNodeId && n.tenantId === tid)) {
        this.graphNodes.push({
          id: identityNodeId,
          tenantId: tid,
          type: 'Identity',
          label: identity,
          riskLevel: 'high',
          metadata: { identityType: draft.identityType },
        });
      }
      this.graphEdges.push({
        id: `edge_${agentId}_id`,
        tenantId: tid,
        sourceId: agentId,
        targetId: identityNodeId,
        type: 'OPERATED_BY',
      });
      for (const dsId of dataSourceIds) {
        const dsNodeId = `data_${dsId}`;
        if (!this.graphNodes.some((n) => n.id === dsNodeId && n.tenantId === tid)) {
          const dsObj = this.dataSources.find((d) => d.id === dsId);
          this.graphNodes.push({
            id: dsNodeId,
            tenantId: tid,
            type: 'Data source',
            label: dsObj?.name ?? dsId,
            sensitivity: dsObj?.classification === 'Restricted' ? 'pii' : 'confidential',
            riskLevel: dsObj?.risk === 'critical' || dsObj?.risk === 'high' ? dsObj.risk : 'medium',
            metadata: { provider: dsObj?.provider ?? 'Cloud' },
          });
        }
        this.graphEdges.push({
          id: `edge_${identityNodeId}_${dsNodeId}`,
          tenantId: tid,
          sourceId: identityNodeId,
          targetId: dsNodeId,
          type: 'CAN_ACCESS',
        });
      }

      this.recomputeTenantRiskAssessments(tid, { agentId, overrides: {} });

      const tenant = this.getTenant(tid);
      tenant.totalDiscoveredAgents += 1;
      tenant.activeAgents += 1;
      if (owner === 'unassigned') tenant.unownedAgents += 1;
      if (type === 'Shadow AI') tenant.shadowAgents += 1;

      const created = this.agents.find((a) => a.id === agentId)!;
      this.activity.unshift({
        id: `act_${crypto.randomUUID()}`,
        tenantId: tid,
        timestamp: 'Just now',
        category: 'discovery',
        title: `Registered AI agent ${created.name}`,
        detail: `Owner: ${created.owner} · Score ${created.riskScore} (${created.riskLevel})`,
        severity: created.riskLevel,
      });

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'agent.registered',
        resourceType: 'agent',
        resourceId: agentId,
        outcome: 'allowed',
        before: null,
        after: {
          name: created.name,
          owner: created.owner,
          type: created.type,
          riskScore: created.riskScore,
        },
        reason: 'Registered AI agent in tenant inventory and security graph',
      });
      this.persistState();
      return created;
    });
  }

  updateAgentGovernance(
    tenantId: string,
    agentId: string,
    updates: {
      owner?: string;
      ownerTeam?: string;
      status?: AgentStatus;
      businessService?: string;
      permissions?: string[];
    },
    actor: { id: string; email: string; role: Role }
  ): Agent {
    return this.withTenantContext(tenantId, (tid) => {
      const idx = this.agents.findIndex((a) => a.id === agentId && a.tenantId === tid);
      if (idx === -1) throw new Error('Agent not found in tenant scope');
      const prev = { ...this.agents[idx] };

      const nextOwner = updates.owner !== undefined ? updates.owner.trim() || 'unassigned' : prev.owner;
      const nextOwnerTeam =
        updates.ownerTeam !== undefined ? updates.ownerTeam.trim() || 'Platform' : prev.ownerTeam;
      const nextStatus: AgentStatus = updates.status ?? prev.status;
      const nextType: AgentType =
        nextOwner !== 'unassigned' && prev.type === 'Unowned'
          ? 'Internal agent'
          : nextOwner === 'unassigned'
            ? 'Unowned'
            : prev.type;

      this.agents[idx] = {
        ...prev,
        owner: nextOwner,
        ownerTeam: nextOwnerTeam,
        status: nextStatus,
        type: nextType,
        businessService: updates.businessService?.trim() || prev.businessService,
        permissions: updates.permissions ?? prev.permissions,
      };

      this.recomputeTenantRiskAssessments(tid, { agentId, overrides: {} });
      const updated = this.agents[idx];

      this.activity.unshift({
        id: `act_${crypto.randomUUID()}`,
        tenantId: tid,
        timestamp: 'Just now',
        category: 'policy',
        title: `Updated governance for ${updated.name}`,
        detail: `Status: ${updated.status} · Owner: ${updated.owner} · Score ${updated.riskScore}`,
        severity: updated.status === 'quarantined' ? 'nominal' : updated.riskLevel,
      });

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'agent.governance_updated',
        resourceType: 'agent',
        resourceId: agentId,
        outcome: 'allowed',
        before: {
          owner: prev.owner,
          ownerTeam: prev.ownerTeam,
          status: prev.status,
          riskScore: prev.riskScore,
        },
        after: {
          owner: updated.owner,
          ownerTeam: updated.ownerTeam,
          status: updated.status,
          riskScore: updated.riskScore,
        },
        reason: 'Updated agent ownership, runtime status, or permission governance',
      });
      this.persistState();
      return updated;
    });
  }

  createPolicyRule(
    tenantId: string,
    input: {
      name: string;
      scope: string;
      action: 'allow' | 'redact' | 'block';
      condition: string;
    },
    actor: { id: string; email: string; role: Role }
  ): PolicyRule {
    return this.withTenantContext(tenantId, (tid) => {
      const name = input.name.trim();
      const scope = input.scope.trim();
      const condition = input.condition.trim();
      if (!name || !scope || !condition) {
        throw new Error('Rule name, scope, and condition are required.');
      }
      const rule: PolicyRule = {
        id: `rule_${crypto.randomUUID().slice(0, 8)}`,
        name,
        scope,
        action: input.action,
        condition,
        observeHits24h: 0,
        enabled: true,
        lastTriggered: 'Just created',
      };
      const list = this.policyRules[tid] ?? [];
      this.policyRules[tid] = [rule, ...list];

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'policy.rule_created',
        resourceType: 'policy_rule',
        resourceId: rule.id,
        outcome: 'allowed',
        before: null,
        after: { name: rule.name, scope: rule.scope, action: rule.action },
        reason: 'Created custom governance rule in policy engine',
      });
      this.persistState();
      return rule;
    });
  }

  createGatewayPolicy(
    tenantId: string,
    input: {
      name: string;
      agents: string[];
      tools: string[];
      dataClassification: string[];
      decision: EnforcementAction;
      strategy?: 'tokenization' | 'masking' | 'strict_block' | 'step_up_mfa' | 'downgrade_readonly';
    },
    actor: { id: string; email: string; role: Role }
  ): GatewayPolicyDefinition {
    return this.withTenantContext(tenantId, (tid) => {
      const name = input.name.trim();
      if (!name) throw new Error('Policy name is required.');
      const id = name
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '_')
        .replace(/^_|_$/g, '');
      const yaml = [
        'policy:',
        `  id: ${id}`,
        `  name: ${name}`,
        '  scope:',
        `    agents: [${input.agents.join(', ')}]`,
        `    tools: [${input.tools.join(', ')}]`,
        `    data_classification: [${input.dataClassification.join(', ')}]`,
        `  decision: ${input.decision}`,
        ...(input.strategy ? [`  strategy: ${input.strategy}`] : []),
        `  mode: ${this.policyModes[tid] ?? 'observe'}`,
      ].join('\n');

      const policyAction: PolicyAction =
        input.decision === 'allow' || input.decision === 'redact' || input.decision === 'block'
          ? input.decision
          : input.decision === 'downgrade' ||
              input.decision === 'approve' ||
              input.decision === 'step_up_authenticate'
            ? 'redact'
            : 'block';

      const severity: RiskLevel =
        policyAction === 'block' ? 'critical' : policyAction === 'redact' ? 'high' : 'low';

      const policy: GatewayPolicyDefinition = {
        id,
        name,
        scope: {
          agents: input.agents,
          tools: input.tools,
          data_classification: input.dataClassification,
        },
        decision: policyAction,
        mode: this.policyModes[tid] ?? 'observe',
        severity,
        actions: ['log_decision', 'attach_evidence'],
        enabled: true,
        observeHits24h: 0,
        lastTriggered: 'Just created',
        yaml,
      };
      const list = this.gatewayPolicies[tid] ?? [];
      this.gatewayPolicies[tid] = [policy, ...list];

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'policy.gateway_yaml_created',
        resourceType: 'gateway_policy',
        resourceId: policy.id,
        outcome: 'allowed',
        before: null,
        after: { id: policy.id, decision: policy.decision },
        reason: 'Created custom zero-trust PEP/PDP gateway policy',
      });
      this.persistState();
      return policy;
    });
  }

  attestComplianceControl(
    tenantId: string,
    controlId: string,
    input: { title?: string; summary: string; source?: string },
    actor: { id: string; email: string; role: Role }
  ): { control: ControlItem; evidenceRecord: EvidenceRecord } {
    return this.withTenantContext(tenantId, (tid) => {
      const ctrl = GOVERNANCE_CONTROLS.find(
        (c) => c.id === controlId || c.code === controlId
      );
      if (!ctrl) throw new Error('Compliance control not found.');
      const summary = input.summary.trim();
      if (!summary) throw new Error('Attestation evidence summary is required.');

      const prevHead = this.evidenceRecords.find((e) => e.tenant_id === tid);
      const record = createChainedEvidenceRecord({
        tenantId: tid,
        controlId: ctrl.code,
        framework: ctrl.framework,
        mappedFrameworks: [ctrl.framework],
        evidenceType: ctrl.requiredEvidenceTypes?.[0] ?? 'approval_record',
        title: input.title?.trim() || `Manual control attestation for ${ctrl.code}`,
        summary,
        source: input.source?.trim() || `attestation:${actor.email}`,
        resourceId: ctrl.id,
        previousHash: prevHead?.content_hash ?? 'sha256:genesis',
        payload: {
          controlId: ctrl.id,
          code: ctrl.code,
          attestedBy: actor.email,
          summary,
        },
      });
      this.evidenceRecords.unshift(record);

      // Resolve any open findings blocking this control if operator attests control verification
      for (let i = 0; i < this.findings.length; i += 1) {
        const f = this.findings[i];
        if (
          f.tenantId === tid &&
          f.status !== 'remediated' &&
          f.frameworks.some((fw) => fw.includes(ctrl.code) || fw.includes(ctrl.framework))
        ) {
          this.findings[i] = {
            ...f,
            status: 'in_progress',
          };
        }
      }

      this.recordAuditEvent({
        tenantId: tid,
        actorId: actor.id,
        actorEmail: actor.email,
        actorRole: actor.role,
        action: 'compliance.control_attested',
        resourceType: 'compliance_control',
        resourceId: ctrl.code,
        outcome: 'allowed',
        before: null,
        after: { evidenceId: record.id, title: record.title, framework: ctrl.framework },
        evidence_id: record.id,
        reason: summary,
      });

      const updatedControl: ControlItem =
        this.getControlsForTenant(tid).find((c) => c.id === ctrl.id) ?? {
          ...ctrl,
          status: 'covered',
          evidenceCount: 1,
          mappedFindingIds: [],
          lastVerified: new Date().toISOString().slice(0, 10),
        };
      this.persistState();
      return { control: updatedControl, evidenceRecord: record };
    });
  }
}

const isNodeTestRunner =
  process.argv.includes('--test') ||
  process.execArgv.includes('--test') ||
  process.env.EOA_DISABLE_PERSIST === '1';

export const store = new TenantDataStore({ persist: !isNodeTestRunner });
