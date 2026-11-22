export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type AgentType = 'Internal agent' | 'Customer-facing' | 'Shadow AI' | 'Unowned';
export type AgentStatus = 'active' | 'restricted' | 'quarantined';
export type FindingStatus = 'open' | 'in_progress' | 'remediated';
export type PolicyAction = 'allow' | 'redact' | 'block';
export type PolicyMode = 'observe' | 'enforce';

export type ComplianceFramework =
  | 'SOC 2'
  | 'ISO 27001'
  | 'ISO 42001'
  | 'GDPR'
  | 'EU AI Act';

export type EvidenceType =
  | 'identity_inventory'
  | 'permission_snapshot'
  | 'data_access_evidence'
  | 'agent_inventory'
  | 'policy_decision'
  | 'approval_record'
  | 'remediation_proof'
  | 'audit_event';

export interface RiskFactorInputs {
  dataSensitivity: number;
  identityPrivilege: number;
  exposureBreadth: number;
  agentAutonomy: number;
  governanceGap: number;
  activity: number;
}

export interface RiskFactorContribution {
  key: keyof RiskFactorInputs;
  label: string;
  signalSummary: string;
  normalizedScore: number;
  weight: number;
  weightedPoints: number;
}

export interface NistAiRmfStatus {
  govern: string;
  map: string;
  measure: string;
  manage: string;
}

export interface ExposurePathRiskSummary {
  agent: string;
  identity: string;
  enablingPermission: string;
  sensitiveResource: string;
  blastRadius: string;
  shortestRemediation: string;
}

export interface RiskFactorAssessment {
  inputs: RiskFactorInputs;
  factors: RiskFactorContribution[];
  totalScore: number;
  level: RiskLevel;
  actionRequired: string;
  recommendedSlaDays: number;
  nistAiRmf: NistAiRmfStatus;
  exposureSummary?: ExposurePathRiskSummary;
  calculatedAt: string;
}

export type ScreenId =
  | 'overview'
  | 'all-in-one'
  | 'inventory'
  | 'agent-detail'
  | 'exposure'
  | 'findings'
  | 'compliance'
  | 'policy'
  | 'connectors'
  | 'enterprise'
  | 'audit';

export type RbacRole =
  | 'owner'
  | 'admin'
  | 'security_analyst'
  | 'compliance_manager'
  | 'agent_owner'
  | 'auditor'
  | 'service_account';

export interface AuthMembershipSummary {
  tenantId: string;
  tenantName: string;
  role: RbacRole;
}

export interface AuthSessionState {
  user: {
    id: string;
    email: string;
    displayName: string;
    idp: string;
    mfaEnabled: boolean;
  };
  activeTenantId: string;
  role: RbacRole;
  permissions: string[];
  mfaVerified: boolean;
  memberships: AuthMembershipSummary[];
}

export interface GraphTraversalPath {
  pathId: string;
  tenantId: string;
  agentId: string;
  agentLabel: string;
  targetDataId: string;
  targetDataLabel: string;
  targetSensitivity: string;
  hopCount: number;
  riskLevel: RiskLevel;
  steps: {
    nodeId: string;
    nodeType: string;
    label: string;
    sensitivity?: string;
    edgeFromPrev?: string;
  }[];
}

export interface AuditActorMeta {
  type: 'user' | 'service' | 'automation';
  id: string;
  email: string;
  ip: string;
  user_agent: string;
}

export interface AuditEventRecord {
  id: string;
  event_id?: string;
  tenantId: string;
  actorId: string;
  actorEmail: string;
  actorRole: string;
  actor?: AuditActorMeta;
  action: string;
  resourceType: string;
  resourceId: string;
  resource?: { type: string; id: string };
  outcome: 'allowed' | 'denied';
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
  reason?: string;
  approval_id?: string;
  evidence_id?: string;
  occurredAt: string;
  prev_hash?: string;
  event_hash?: string;
  retention_until?: string;
}

export interface AuditChainIntegrity {
  valid: boolean;
  verifiedCount: number;
  headHash: string;
  tamperAlerts: string[];
  retentionDays: number;
}

export interface Tenant {
  id: string;
  name: string;
  domain: string;
  industry: string;
  totalDiscoveredAgents: number;
  activeAgents: number;
  unownedAgents: number;
  shadowAgents: number;
  overallRiskScore: number;
  riskTrendDelta: number;
  overPrivilegedIdentities: number;
  unusedCredentials: number;
  riskyServiceAccounts: number;
  dailyRequests: number;
  dailyToolCalls: number;
  blockedOrRedactedEvents: number;
}

export interface AgentFindingRef {
  id: string;
  title: string;
  severity: RiskLevel;
  owner: string;
  status: FindingStatus;
}

export interface Agent {
  id: string;
  tenantId: string;
  name: string;
  owner: string;
  ownerTeam: string;
  type: AgentType;
  status: AgentStatus;
  riskScore: number;
  riskLevel: RiskLevel;
  riskAssessment?: RiskFactorAssessment;
  identity: string;
  identityType: string;
  models: string[];
  mcpServers: string[];
  tools: string[];
  dataSources: string[];
  permissions: string[];
  businessService: string;
  lastSeen: string;
  dailyCalls: number;
  findings: AgentFindingRef[];
}

export interface McpServer {
  id: string;
  name: string;
  tools: string[];
  connectedAgentIds: string[];
  risk: RiskLevel;
  transport: 'stdio' | 'sse' | 'streamable-http';
}

export interface ModelAsset {
  id: string;
  name: string;
  provider: string;
  usedByAgentIds: string[];
  sensitivity: string;
  promptRetention: 'Zero retention' | 'Enterprise DPA';
}

export interface DataSource {
  id: string;
  name: string;
  provider: string;
  sensitivity: string;
  classification: 'Restricted' | 'Confidential' | 'Internal';
  agentIdsWithAccess: string[];
  risk: RiskLevel;
  recordsCount: string;
}

export interface FindingEvidenceArtifact {
  id: string;
  source: string;
  type: string;
  summary: string;
  collectedAt: string;
  hash: string;
}

export interface FindingRemediationControl {
  action: string;
  target: string;
  targetEdgeId?: string;
  dryRunAvailable: boolean;
  rollbackAvailable: boolean;
  approvalRequired: boolean;
  dryRunExecuted: boolean;
  dryRunDiff?: string;
  rollbackSnapshot?: string;
  approvalStatus: 'pending_approval' | 'approved' | 'applied' | 'rolled_back';
  approvedBy?: string;
  approvedAt?: string;
  appliedAt?: string;
  breakGlassDualApproval?: boolean;
}

export interface FindingVerificationResult {
  status: 'unverified' | 'path_still_present' | 'verified_closed';
  lastSyncCheckedAt?: string;
  remainingPathCount?: number;
  proofHash?: string;
  message?: string;
}

export interface Finding {
  id: string;
  tenantId: string;
  ruleId?: string;
  category?: string;
  riskScore?: number;
  riskAssessment?: RiskFactorAssessment;
  agentId: string;
  agentName: string;
  identityId?: string;
  resourceId?: string;
  dataClassification?: string;
  title: string;
  description: string;
  businessImpact: string;
  remediationSteps: string[];
  severity: RiskLevel;
  owner: string;
  ownerEmail?: string;
  slaDays: number;
  slaRemainingDays: number;
  slaDueAt?: string;
  status: FindingStatus;
  jiraTicketKey?: string;
  ticketProvider?: 'jira' | 'servicenow';
  ticketPayloadPreview?: string;
  notifiedChannels?: string[];
  createdAt: string;
  frameworks: string[];
  exposurePath?: string[];
  evidence?: FindingEvidenceArtifact[];
  remediation?: FindingRemediationControl;
  verification?: FindingVerificationResult;
}

export interface PolicyRule {
  id: string;
  name: string;
  scope: string;
  condition: string;
  action: PolicyAction;
  observeHits24h: number;
  enabled: boolean;
  lastTriggered: string;
}

export interface GatewayPolicyDefinition {
  id: string;
  name: string;
  scope: {
    agents: string[];
    tools: string[];
    data_classification: string[];
  };
  decision: PolicyAction;
  mode: PolicyMode;
  severity: RiskLevel;
  actions: string[];
  enabled: boolean;
  observeHits24h: number;
  lastTriggered: string;
  yaml: string;
}

export interface DlpClassification {
  pii: boolean;
  phi: boolean;
  pci: boolean;
  financial: boolean;
  secrets: boolean;
  source_code: boolean;
  matchedSignals: string[];
}

export type EnforcementAction =
  | 'allow'
  | 'redact'
  | 'approve'
  | 'step_up_authenticate'
  | 'downgrade'
  | 'block'
  | 'quarantine_agent'
  | 'escalate';

export type RolloutStage =
  | 'observe'
  | 'advisory'
  | 'selective_enforcement'
  | 'approval_gated_response'
  | 'full_enforcement';

export type GatewayDecision =
  | 'would_allow'
  | 'would_redact'
  | 'would_approve'
  | 'would_step_up_authenticate'
  | 'would_downgrade'
  | 'would_block'
  | 'would_quarantine_agent'
  | 'would_escalate'
  | EnforcementAction;

export interface GatewayEvent {
  event_id: string;
  tenant_id: string;
  agent_id: string;
  agent_name: string;
  identity_id: string;
  provider: string;
  model: string;
  tool: string;
  mcp_server: string;
  mode: PolicyMode;
  rollout_stage?: RolloutStage;
  policy_decision: GatewayDecision;
  enforcement_action?: EnforcementAction;
  pdp_reason?: string;
  policy_rule: string;
  classification: DlpClassification;
  latency_ms: number;
  forwarded: boolean;
  content_retained: boolean;
  redacted_excerpt?: string;
  tokenized_preview?: string;
  effective_identity?: string;
  effective_model?: string;
  approval_request_id?: string;
  playbook_execution_id?: string;
  replay_nonce?: string;
  evidence_id: string;
  finding_id?: string;
  timestamp: string;
}

export interface RetentionPolicyConfig {
  requestMetadataDays: number;
  policyDecisionDays: number;
  classificationResultDays: number;
  rawPromptRetained: boolean;
  rawResponseRetained: boolean;
  redactedExcerptOptIn: boolean;
  redactedExcerptDays: number;
  evidenceHashRetention: string;
}

export interface PolicySimulationEvent {
  id: string;
  timestamp: string;
  agentName: string;
  tool: string;
  dataSource: string;
  ruleName: string;
  wouldAction: PolicyAction;
  samplePayloadSummary: string;
}

export interface ControlItem {
  id: string;
  framework: ComplianceFramework;
  code: string;
  title: string;
  requiredEvidenceTypes?: EvidenceType[];
  status: 'covered' | 'partial' | 'gap';
  evidenceCount: number;
  mappedFindingIds: string[];
  lastVerified: string;
}

export interface EvidenceItem {
  id: string;
  controlCode: string;
  framework: ComplianceFramework;
  title: string;
  source: string;
  capturedAt: string;
  hash: string;
}

export interface EvidenceRecord {
  id: string;
  tenant_id: string;
  control_id: string;
  framework: ComplianceFramework;
  mapped_frameworks: ComplianceFramework[];
  evidence_type: EvidenceType;
  source: string;
  resource_id: string;
  title: string;
  summary: string;
  collected_at: string;
  collector_version: string;
  content_hash: string;
  previous_hash: string;
  storage_uri: string;
  retention_until: string;
  status: 'valid' | 'gap_flagged';
  redacted: boolean;
}

export interface Connector {
  id: string;
  tenantId: string;
  provider?: string;
  name: string;
  category: 'Identity' | 'Cloud' | 'Code' | 'Collaboration' | 'Ticketing' | 'Data';
  status: 'healthy' | 'warning' | 'syncing';
  readOnly?: boolean;
  coveragePct: number;
  discoveredAssets: number;
  discoveredSummary?: Record<string, number>;
  lastSync: string;
  scopesSummary: string;
  config?: Record<string, string>;
}

export interface ActivityEvent {
  id: string;
  tenantId: string;
  timestamp: string;
  category: 'discovery' | 'violation' | 'remediation' | 'policy';
  title: string;
  detail: string;
  severity: RiskLevel | 'nominal';
}

export interface RiskTrendPoint {
  date: string;
  riskScore: number;
  shadowAgents: number;
  blockedEvents: number;
}

export type PlaybookId =
  | 'pb_sensitive_exfiltration'
  | 'pb_prompt_injection'
  | 'pb_compromised_identity'
  | 'pb_shadow_ai'
  | 'pb_overprivileged_agent'
  | 'pb_data_loss';

export interface PlaybookDefinition {
  id: PlaybookId;
  name: string;
  trigger: string;
  severity: RiskLevel;
  automatedAction: string;
  humanApprovalRequiredFor: string;
  responderIdentity: string;
  rateLimitPerMinute: number;
}

export interface PlaybookExecutionRecord {
  executionId: string;
  tenantId: string;
  playbookId: PlaybookId;
  playbookName: string;
  agentId: string;
  agentName: string;
  triggerSignal: string;
  severity: RiskLevel;
  status: 'dry_run' | 'contained_awaiting_approval' | 'approved_executed' | 'rolled_back' | 'paused_by_kill_switch';
  dryRunImpactSummary: string;
  containmentActions: string[];
  pendingApprovalAction: string;
  responderIdentity: string;
  ticketKey?: string;
  evidenceId: string;
  auditEventId: string;
  rollbackSnapshot: Record<string, unknown>;
  approvedBy?: string;
  approvedAt?: string;
  rolledBackAt?: string;
  executedAt: string;
}

export interface KillSwitchState {
  paused: boolean;
  updatedAt: string;
  updatedBy: string;
  reason?: string;
}

export interface EnterpriseSsoConfig {
  tenantId: string;
  protocol: 'saml_2_0' | 'oidc';
  idpName: string;
  idpEntityId: string;
  ssoEnforced: boolean;
  localPasswordFallbackDisabled: boolean;
  mfaRequiredForAdmins: boolean;
  allowedMfaMethods: Array<'totp' | 'webauthn'>;
  scimEnabled: boolean;
  certificateFingerprint: string;
  certificateRotatedAt: string;
  metadataValidated: boolean;
}

export interface ScimDirectoryUser {
  id: string;
  tenantId: string;
  email: string;
  displayName: string;
  idpGroups: string[];
  mappedRole: RbacRole;
  status: 'active' | 'disabled';
  mfaEnrolled: boolean;
  activeSessionCount: number;
  lastSyncedAt: string;
}

export interface ReleaseGateCheck {
  id: string;
  name: string;
  requirement: string;
  passed: boolean;
  detail: string;
  checkedAt: string;
}

export interface PlatformHardeningItem {
  area: string;
  control: string;
  status: 'enforced' | 'verified';
}

export interface AllInOneStageResult {
  id: string;
  step: number;
  title: string;
  status: 'completed' | 'verified';
  summary: string;
  targetScreen: ScreenId;
  metrics: Record<string, string | number | boolean>;
}

export interface AllInOneRunResult {
  runId: string;
  tenantId: string;
  tenantName: string;
  executedAt: string;
  executedBy: string;
  durationMs: number;
  stages: AllInOneStageResult[];
  summary: {
    connectorsHealthy: number;
    connectorsTotal: number;
    exposurePathsCount: number;
    ticketsCreatedCount: number;
    openFindingsRemaining: number;
    compliancePackageId: string;
    complianceCoveragePct: number;
    releaseGatesPassed: number;
    releaseGatesTotal: number;
    auditChainValid: boolean;
    auditHeadHash: string;
  };
}
export interface DemoRequestRecord {
  id: string;
  name: string;
  email: string;
  company: string;
  submittedAt: string;
  status: 'received' | 'scheduled';
}
