export type Role =
  | 'owner'
  | 'admin'
  | 'security_analyst'
  | 'compliance_manager'
  | 'agent_owner'
  | 'auditor'
  | 'service_account';

export type Permission =
  | 'tenant:read'
  | 'tenant:admin'
  | 'agents:read'
  | 'agents:remediate_owned'
  | 'findings:read'
  | 'findings:manage'
  | 'connectors:read'
  | 'connectors:manage'
  | 'policies:read'
  | 'policies:manage'
  | 'compliance:read'
  | 'compliance:export'
  | 'audit:read'
  | 'graph:read';

export interface TenantRecord {
  id: string;
  name: string;
  slug: string;
  domain: string;
  industry: string;
  plan: 'enterprise' | 'growth';
  status: 'active' | 'suspended';
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
  createdAt: string;
}

export interface UserRecord {
  id: string;
  email: string;
  displayName: string;
  externalId: string;
  idp: 'okta_saml' | 'entra_oidc' | 'workos_sso' | 'service_token' | 'scim_2_0';
  mfaEnabled: boolean;
  interactiveAllowed: boolean;
  createdAt: string;
}

export interface TenantMembership {
  tenantId: string;
  userId: string;
  role: Role;
  status: 'active' | 'revoked';
}

export interface SessionRecord {
  sessionId: string;
  refreshId: string;
  userId: string;
  activeTenantId: string;
  mfaVerified: boolean;
  createdAt: number;
  expiresAt: number;
}

export type GraphNodeType =
  | 'Tenant'
  | 'User'
  | 'Identity'
  | 'Group'
  | 'Role'
  | 'Permission'
  | 'AI agent'
  | 'MCP server'
  | 'Tool'
  | 'Model'
  | 'Data source'
  | 'Data object'
  | 'Finding'
  | 'Control';

export type GraphEdgeType =
  | 'MEMBER_OF'
  | 'ASSIGNED_ROLE'
  | 'GRANTS_PERMISSION'
  | 'CAN_ACCESS'
  | 'OPERATED_BY'
  | 'USES_MODEL'
  | 'CALLS_TOOL'
  | 'HOSTED_BY'
  | 'READS'
  | 'WRITES'
  | 'CONTAINS'
  | 'TRIGGERS';

export interface GraphNode {
  id: string;
  tenantId: string;
  provider?: ConnectorRecord['provider'];
  externalResourceId?: string;
  type: GraphNodeType;
  label: string;
  sensitivity?: 'pii' | 'phi' | 'pci' | 'restricted' | 'confidential' | 'internal';
  riskLevel?: 'critical' | 'high' | 'medium' | 'low';
  metadata: Record<string, string | number | boolean>;
}

export interface GraphEdge {
  id: string;
  tenantId: string;
  provider?: ConnectorRecord['provider'];
  externalResourceId?: string;
  sourceId: string;
  targetId: string;
  type: GraphEdgeType;
  metadata?: Record<string, string>;
}

export interface ExposureTraversalResult {
  pathId: string;
  tenantId: string;
  agentId: string;
  agentLabel: string;
  targetDataId: string;
  targetDataLabel: string;
  targetSensitivity: string;
  hopCount: number;
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  pathState?: 'potential' | 'observed' | 'active' | 'anomalous' | 'remediated';
  externalDestination?: {
    label: string;
    category: 'external_llm' | 'external_webhook' | 'saas_api' | 'internal_only';
    egressRisk: 'critical' | 'high' | 'medium' | 'low';
  };
  steps: {
    nodeId: string;
    nodeType: GraphNodeType;
    label: string;
    sensitivity?: string;
    edgeFromPrev?: GraphEdgeType;
  }[];
}

export interface EncryptedCredentialRecord {
  id: string;
  tenantId: string;
  connectorId: string;
  ciphertextHex: string;
  ivHex: string;
  authTagHex: string;
  keyId: string;
  tokenVersion: number;
  expiresAt: string;
  revoked: boolean;
}

export interface ConnectorRecord {
  id: string;
  tenantId: string;
  provider:
    | 'entra_id'
    | 'microsoft_365'
    | 'azure'
    | 'aws'
    | 'gcp'
    | 'github'
    | 'slack'
    | 'jira'
    | 'servicenow'
    | 'custom_http';
  displayName: string;
  category: 'Identity' | 'Cloud' | 'Code' | 'Collaboration' | 'Ticketing' | 'Data';
  status: 'healthy' | 'warning' | 'syncing' | 'disconnected' | 'error';
  readOnly: boolean;
  lastSyncAt: string;
  lastSyncLabel: string;
  coveragePct: number;
  discoveredAssets: number;
  discoveredSummary?: Record<string, number>;
  scopes: string[];
  pkceVerified: boolean;
  config: Record<string, string>;
}

export interface AuditEvent {
  id: string;
  event_id?: string;
  tenantId: string;
  actorId: string;
  actorEmail: string;
  actorRole: Role | 'anonymous';
  actor?: {
    type: 'user' | 'service' | 'automation';
    id: string;
    email: string;
    ip: string;
    user_agent: string;
  };
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

export interface DetectionRuleDefinition {
  id: string;
  name: string;
  trigger: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
}

