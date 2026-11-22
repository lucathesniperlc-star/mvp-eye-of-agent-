import type { FindingEvidenceArtifact } from '../src/types/security.ts';
import { createPkcePair, verifyPkceChallenge } from './cryptoVault.ts';
import { computeEvidenceHash } from './findingsEngine.ts';
import type { ConnectorRecord, GraphEdge, GraphNode } from './types.ts';

export interface AuthorizeInput {
  tenantId: string;
  connectorId: string;
  codeVerifier: string;
  codeChallenge: string;
  grantedScopes: string[];
}

export interface AuthorizationResult {
  authorized: boolean;
  refreshToken: string;
  scopes: string[];
}

export interface RefreshInput {
  tenantId: string;
  connectorId: string;
  currentRefreshToken: string;
}

export interface TokenResult {
  newRefreshToken: string;
  rotatedAt: string;
}

export interface ConnectionInput {
  tenantId: string;
  connectorId: string;
}

export interface HealthResult {
  healthy: boolean;
  latencyMs: number;
  message: string;
}

export interface SyncContext {
  tenantId: string;
  connectorId: string;
  config?: Record<string, string>;
  simulateFailure?: boolean;
}

export interface EvidenceRecord {
  id: string;
  controlCode: string;
  framework: 'SOC 2' | 'ISO 27001';
  title: string;
  source: string;
  capturedAt: string;
}

export interface ConnectorAdapter {
  id: string;
  provider: ConnectorRecord['provider'];
  readOnly: boolean;
  requiredReadOnlyScopes: string[];

  authorize(input: AuthorizeInput): Promise<AuthorizationResult>;
  refreshToken(input: RefreshInput): Promise<TokenResult>;
  testConnection(input: ConnectionInput): Promise<HealthResult>;
  discoverEntities(input: SyncContext): Promise<{
    nodes: GraphNode[];
    summary: Record<string, number>;
    evidence: FindingEvidenceArtifact[];
  }>;
  discoverRelationships(input: SyncContext): Promise<GraphEdge[]>;
  collectEvidence(input: SyncContext): Promise<EvidenceRecord[]>;
}

export function validateAwsConnectionInput(input: {
  accountId?: string;
  roleArn?: string;
  externalId?: string;
  accessKeyId?: string;
  secretAccessKey?: string;
}): void {
  if (input.accessKeyId || input.secretAccessKey) {
    throw new Error(
      'Long-lived AWS access keys are prohibited. Configure a cross-account IAM Role ARN with an External ID.'
    );
  }
  const accountId = (input.accountId ?? '').trim();
  const roleArn = (input.roleArn ?? '').trim();
  const externalId = (input.externalId ?? '').trim();
  if (!/^\d{12}$/.test(accountId)) {
    throw new Error('AWS Account ID must be a 12-digit identifier.');
  }
  if (!/^arn:aws:iam::\d{12}:role\/[\w+=,.@/-]+$/.test(roleArn)) {
    throw new Error(
      'Role ARN must match arn:aws:iam::<account-id>:role/<role-name>.'
    );
  }
  if (externalId.length < 8) {
    throw new Error('External ID must be at least 8 characters for cross-account confused-deputy protection.');
  }
}

export const AWS_READ_ONLY_POLICY_DOCUMENT = {
  Version: '2012-10-17',
  Statement: [
    {
      Effect: 'Allow',
      Action: [
        'iam:ListUsers',
        'iam:ListRoles',
        'iam:ListPolicies',
        'iam:GetPolicy',
        'iam:GetPolicyVersion',
        'iam:ListAttachedRolePolicies',
        'iam:ListRolePolicies',
        'iam:GetRole',
        's3:ListAllMyBuckets',
        's3:GetBucketPolicy',
        's3:GetBucketAcl',
        'kms:ListKeys',
        'kms:DescribeKey',
        'access-analyzer:ListFindings',
      ],
      Resource: '*',
    },
  ],
};

export const AZURE_SECURITY_READER_ACTIONS = [
  'Microsoft.Resources/subscriptions/read',
  'Microsoft.Resources/subscriptions/resourceGroups/read',
  'Microsoft.Authorization/roleAssignments/read',
  'Microsoft.Authorization/roleDefinitions/read',
  'Microsoft.ManagedIdentity/userAssignedIdentities/read',
  'Microsoft.KeyVault/vaults/read',
  'Microsoft.Storage/storageAccounts/read',
  'Microsoft.CognitiveServices/accounts/read',
  'Microsoft.Insights/activitylogs/read',
];

function createEntraAdapter(): ConnectorAdapter {
  const scopes = [
    'User.Read.All',
    'Group.Read.All',
    'Application.Read.All',
    'Directory.Read.All',
    'RoleManagement.Read.Directory',
  ];

  return {
    id: 'adapter_entra_id',
    provider: 'entra_id',
    readOnly: true,
    requiredReadOnlyScopes: scopes,

    async authorize(input) {
      if (!verifyPkceChallenge(input.codeVerifier, input.codeChallenge)) {
        throw new Error('PKCE verification failed during Entra ID admin consent flow');
      }
      return {
        authorized: true,
        refreshToken: `rt_entra_app_only_${input.tenantId}_${Date.now()}`,
        scopes: input.grantedScopes.length > 0 ? input.grantedScopes : scopes,
      };
    },

    async refreshToken(input) {
      if (!input.currentRefreshToken) throw new Error('Missing refresh token for rotation');
      return {
        newRefreshToken: `rt_entra_app_only_${input.tenantId}_rot_${Date.now()}`,
        rotatedAt: new Date().toISOString(),
      };
    },

    async testConnection() {
      return {
        healthy: true,
        latencyMs: 34,
        message: 'Microsoft Graph read-only app permissions verified (/users, /groups, /servicePrincipals)',
      };
    },

    async discoverEntities(ctx) {
      if (ctx.simulateFailure) {
        throw new Error('Upstream Microsoft Graph throttling (429) during directory sync');
      }
      const now = new Date().toISOString();
      const prefix = ctx.tenantId === 'tenant_northwind' ? 'nw' : 'eu';
      const nodes: GraphNode[] = [
        {
          id: `node_${prefix}_entra_user_owner`,
          tenantId: ctx.tenantId,
          provider: 'entra_id',
          externalResourceId: `graph:/users/usr_${prefix}_finops`,
          type: 'User',
          label: ctx.tenantId === 'tenant_northwind' ? 'finance-ops@northwind.com' : 'treasury-ops@northwind.eu',
          metadata: { source: '/users', mfaEnabled: true },
        },
        {
          id: `node_${prefix}_entra_group_ai`,
          tenantId: ctx.tenantId,
          provider: 'entra_id',
          externalResourceId: `graph:/groups/grp_${prefix}_ai_admins`,
          type: 'Group',
          label: 'AI Platform Admins',
          riskLevel: 'high',
          metadata: { source: '/groups/{id}/members', memberCount: 6 },
        },
        {
          id: `node_${prefix}_entra_dir_role`,
          tenantId: ctx.tenantId,
          provider: 'entra_id',
          externalResourceId: `graph:/directoryRoles/app_admin`,
          type: 'Role',
          label: 'Application Administrator (Entra ID)',
          riskLevel: 'critical',
          metadata: { source: '/directoryRoles', signInRiskSignal: 'low' },
        },
        {
          id: `node_${prefix}_entra_oauth_grant`,
          tenantId: ctx.tenantId,
          provider: 'entra_id',
          externalResourceId: `graph:/oauth2PermissionGrants/sites_rw`,
          type: 'Permission',
          label: 'oauth2:Sites.ReadWrite.All',
          riskLevel: 'critical',
          metadata: { source: '/oauth2PermissionGrants', consentType: 'AllPrincipals' },
        },
      ];

      const summary = {
        Users: 24,
        Groups: 8,
        'Service Principals': 14,
        'Directory Roles': 5,
        'OAuth Grants': 11,
      };

      const evidence: FindingEvidenceArtifact[] = [
        {
          id: `ev_entra_sp_${prefix}`,
          source: 'entra_id',
          type: 'appRoleAssignedTo',
          summary: '/servicePrincipals/{id}/appRoleAssignedTo & /oauth2PermissionGrants snapshot',
          collectedAt: now,
          hash: computeEvidenceHash({ tenantId: ctx.tenantId, provider: 'entra_id', summary, nodes }),
        },
      ];

      return { nodes, summary, evidence };
    },

    async discoverRelationships(ctx) {
      if (ctx.simulateFailure) {
        throw new Error('Upstream Microsoft Graph failure during relationship sync');
      }
      const prefix = ctx.tenantId === 'tenant_northwind' ? 'nw' : 'eu';
      const spNode =
        ctx.tenantId === 'tenant_northwind' ? 'node_nw_id_proc' : 'node_eu_id_sepa';
      return [
        {
          id: `edge_${prefix}_entra_user_grp`,
          tenantId: ctx.tenantId,
          provider: 'entra_id',
          externalResourceId: `graph:/groups/grp_${prefix}_ai_admins/members`,
          sourceId: `node_${prefix}_entra_user_owner`,
          targetId: `node_${prefix}_entra_group_ai`,
          type: 'MEMBER_OF',
        },
        {
          id: `edge_${prefix}_entra_sp_role`,
          tenantId: ctx.tenantId,
          provider: 'entra_id',
          externalResourceId: `graph:/directoryRoles/app_admin/${spNode}`,
          sourceId: spNode,
          targetId: `node_${prefix}_entra_dir_role`,
          type: 'ASSIGNED_ROLE',
        },
        {
          id: `edge_${prefix}_entra_role_grant`,
          tenantId: ctx.tenantId,
          provider: 'entra_id',
          externalResourceId: `graph:/oauth2PermissionGrants/edge_${prefix}`,
          sourceId: `node_${prefix}_entra_dir_role`,
          targetId: `node_${prefix}_entra_oauth_grant`,
          type: 'GRANTS_PERMISSION',
        },
      ];
    },

    async collectEvidence(ctx) {
      return [
        {
          id: `ev_entra_${ctx.tenantId}`,
          controlCode: 'CC6.1',
          framework: 'SOC 2',
          title: 'Entra ID service principals, directory roles & OAuth grants synced read-only',
          source: 'entra_id',
          capturedAt: new Date().toISOString(),
        },
      ];
    },
  };
}

function createAwsAdapter(): ConnectorAdapter {
  const scopes = AWS_READ_ONLY_POLICY_DOCUMENT.Statement[0].Action;

  return {
    id: 'adapter_aws',
    provider: 'aws',
    readOnly: true,
    requiredReadOnlyScopes: scopes,

    async authorize(input) {
      if (!verifyPkceChallenge(input.codeVerifier, input.codeChallenge)) {
        throw new Error('PKCE verification failed during AWS role validation');
      }
      return {
        authorized: true,
        refreshToken: `sts_external_id_${input.tenantId}_${Date.now()}`,
        scopes,
      };
    },

    async refreshToken(input) {
      if (!input.currentRefreshToken) throw new Error('Missing STS external session token');
      return {
        newRefreshToken: `sts_external_id_${input.tenantId}_rot_${Date.now()}`,
        rotatedAt: new Date().toISOString(),
      };
    },

    async testConnection() {
      return {
        healthy: true,
        latencyMs: 42,
        message: 'AWS STS AssumeRole (External ID + Allowlisted IPs) read-only check healthy',
      };
    },

    async discoverEntities(ctx) {
      if (ctx.simulateFailure) {
        throw new Error('Upstream AWS IAM API rate limit (429) during discovery');
      }
      const now = new Date().toISOString();
      const prefix = ctx.tenantId === 'tenant_northwind' ? 'nw' : 'eu';
      const nodes: GraphNode[] = [
        {
          id: `node_${prefix}_aws_kms_payroll`,
          tenantId: ctx.tenantId,
          provider: 'aws',
          externalResourceId: `arn:aws:kms:us-east-1:${ctx.config?.accountId ?? '449102881234'}:key/payroll`,
          type: 'Resource' as GraphNode['type'],
          label: 'kms/payroll-cmk',
          riskLevel: 'high',
          metadata: { source: 'kms:DescribeKey', rotationEnabled: true },
        },
        {
          id: `node_${prefix}_aws_aa_finding`,
          tenantId: ctx.tenantId,
          provider: 'aws',
          externalResourceId: `arn:aws:access-analyzer:us-east-1:analyzer/prod:finding-01`,
          type: 'Finding',
          label: 'AccessAnalyzer: External/Excessive S3 Policy',
          riskLevel: 'critical',
          metadata: { source: 'access-analyzer:ListFindings', unusedDays: 112 },
        },
      ];

      // Note: Keep 'Resource' compatible with GraphNodeType by mapping KMS as Data source metadata node if needed
      nodes[0].type = 'Data source';
      nodes[0].sensitivity = 'restricted';

      const summary = {
        'IAM Roles': 12,
        'IAM Policies': 19,
        'S3 Buckets': 6,
        'KMS Keys': 4,
        'Access Analyzer Findings': 3,
      };

      const evidence: FindingEvidenceArtifact[] = [
        {
          id: `ev_aws_iam_${prefix}`,
          source: 'aws_iam',
          type: 'role_policy',
          summary: 'IAM GetRole + ListAttachedRolePolicies + GetPolicyVersion (PayrollExporter)',
          collectedAt: now,
          hash: computeEvidenceHash({ tenantId: ctx.tenantId, provider: 'aws', kind: 'role_policy', summary }),
        },
        {
          id: `ev_aws_s3_${prefix}`,
          source: 'aws_s3',
          type: 'bucket_policy',
          summary: 'S3 GetBucketPolicy & GetBucketAcl (s3://payroll-prod)',
          collectedAt: now,
          hash: computeEvidenceHash({ tenantId: ctx.tenantId, provider: 'aws', kind: 'bucket_policy', summary }),
        },
      ];

      return { nodes, summary, evidence };
    },

    async discoverRelationships(ctx) {
      if (ctx.simulateFailure) {
        throw new Error('Upstream AWS S3 API failure during edge discovery');
      }
      const prefix = ctx.tenantId === 'tenant_northwind' ? 'nw' : 'eu';
      const permSource =
        ctx.tenantId === 'tenant_northwind' ? 'node_nw_perm_s3' : 'node_eu_perm_sf';
      return [
        {
          id: `edge_${prefix}_aws_kms_read`,
          tenantId: ctx.tenantId,
          provider: 'aws',
          externalResourceId: `aws:kms:decrypt:${prefix}`,
          sourceId: permSource,
          targetId: `node_${prefix}_aws_kms_payroll`,
          type: 'CAN_ACCESS',
        },
      ];
    },

    async collectEvidence(ctx) {
      return [
        {
          id: `ev_aws_${ctx.tenantId}`,
          controlCode: 'CC6.3',
          framework: 'SOC 2',
          title: 'AWS IAM role trust policies, S3 bucket policies & Access Analyzer snapshots collected',
          source: 'aws',
          capturedAt: new Date().toISOString(),
        },
      ];
    },
  };
}

function createAzureAdapter(): ConnectorAdapter {
  const scopes = AZURE_SECURITY_READER_ACTIONS;

  return {
    id: 'adapter_azure',
    provider: 'azure',
    readOnly: true,
    requiredReadOnlyScopes: scopes,

    async authorize(input) {
      if (!verifyPkceChallenge(input.codeVerifier, input.codeChallenge)) {
        throw new Error('PKCE verification failed during Azure Workload Identity Federation handshake');
      }
      return {
        authorized: true,
        refreshToken: `az_wif_fed_${input.tenantId}_${Date.now()}`,
        scopes,
      };
    },

    async refreshToken(input) {
      if (!input.currentRefreshToken) throw new Error('Missing Azure federated token');
      return {
        newRefreshToken: `az_wif_fed_${input.tenantId}_rot_${Date.now()}`,
        rotatedAt: new Date().toISOString(),
      };
    },

    async testConnection() {
      return {
        healthy: true,
        latencyMs: 39,
        message: 'Azure Security Reader role verified across Subscriptions, Key Vault & AI Foundry',
      };
    },

    async discoverEntities(ctx) {
      if (ctx.simulateFailure) {
        throw new Error('Upstream Azure Resource Manager rate limit (429) during discovery');
      }
      const now = new Date().toISOString();
      const prefix = ctx.tenantId === 'tenant_northwind' ? 'nw' : 'eu';
      const nodes: GraphNode[] = [
        {
          id: `node_${prefix}_az_managed_id`,
          tenantId: ctx.tenantId,
          provider: 'azure',
          externalResourceId: `/subscriptions/sub-${prefix}-01/providers/Microsoft.ManagedIdentity/mi-ai-gateway`,
          type: 'Identity',
          label: `mi-ai-gateway-${prefix}`,
          riskLevel: 'high',
          metadata: { source: 'userAssignedIdentities/read', authMethod: 'WorkloadIdentityFederation' },
        },
        {
          id: `node_${prefix}_az_role_kv`,
          tenantId: ctx.tenantId,
          provider: 'azure',
          externalResourceId: `/subscriptions/sub-${prefix}-01/roleAssignments/kv-secrets-user`,
          type: 'Role',
          label: 'Key Vault Secrets User (Azure RBAC)',
          riskLevel: 'high',
          metadata: { source: 'Microsoft.Authorization/roleAssignments/read' },
        },
        {
          id: `node_${prefix}_az_keyvault`,
          tenantId: ctx.tenantId,
          provider: 'azure',
          externalResourceId: `/subscriptions/sub-${prefix}-01/resourceGroups/rg-ai/providers/Microsoft.KeyVault/vaults/kv-${prefix}-prod`,
          type: 'Data source',
          label: `kv-${prefix}-prod (Azure Key Vault)`,
          sensitivity: 'restricted',
          riskLevel: 'high',
          metadata: { source: 'Microsoft.KeyVault/vaults/read' },
        },
        {
          id: `node_${prefix}_az_openai`,
          tenantId: ctx.tenantId,
          provider: 'azure',
          externalResourceId: `/subscriptions/sub-${prefix}-01/providers/Microsoft.CognitiveServices/accounts/aoai-${prefix}`,
          type: 'Model',
          label: `Azure OpenAI (${prefix.toUpperCase()})`,
          riskLevel: 'medium',
          metadata: { source: 'Microsoft.CognitiveServices/accounts/read' },
        },
      ];

      const summary = {
        Subscriptions: ctx.tenantId === 'tenant_northwind' ? 4 : 2,
        'Managed Identities': 7,
        'RBAC Role Assignments': 16,
        'Key Vaults': 3,
        'Storage Accounts': 5,
        'Azure OpenAI Resources': 4,
      };

      const evidence: FindingEvidenceArtifact[] = [
        {
          id: `ev_az_rbac_${prefix}`,
          source: 'azure_arm',
          type: 'role_assignment',
          summary: 'Azure RBAC roleAssignments + Managed Identity + Key Vault metadata snapshot',
          collectedAt: now,
          hash: computeEvidenceHash({ tenantId: ctx.tenantId, provider: 'azure', summary }),
        },
      ];

      return { nodes, summary, evidence };
    },

    async discoverRelationships(ctx) {
      if (ctx.simulateFailure) {
        throw new Error('Upstream Azure RBAC discovery failure');
      }
      const prefix = ctx.tenantId === 'tenant_northwind' ? 'nw' : 'eu';
      return [
        {
          id: `edge_${prefix}_az_mi_role`,
          tenantId: ctx.tenantId,
          provider: 'azure',
          externalResourceId: `az:rbac:assign:${prefix}`,
          sourceId: `node_${prefix}_az_managed_id`,
          targetId: `node_${prefix}_az_role_kv`,
          type: 'ASSIGNED_ROLE',
        },
        {
          id: `edge_${prefix}_az_role_kv`,
          tenantId: ctx.tenantId,
          provider: 'azure',
          externalResourceId: `az:rbac:kv:${prefix}`,
          sourceId: `node_${prefix}_az_role_kv`,
          targetId: `node_${prefix}_az_keyvault`,
          type: 'CAN_ACCESS',
        },
      ];
    },

    async collectEvidence(ctx) {
      return [
        {
          id: `ev_az_${ctx.tenantId}`,
          controlCode: 'A.5.15',
          framework: 'ISO 27001',
          title: 'Azure Security Reader verified RBAC assignments, Managed Identities & Key Vaults',
          source: 'azure',
          capturedAt: new Date().toISOString(),
        },
      ];
    },
  };
}

function createProviderAdapter(
  provider: ConnectorRecord['provider'],
  requiredReadOnlyScopes: string[]
): ConnectorAdapter {
  return {
    id: `adapter_${provider}`,
    provider,
    readOnly: true,
    requiredReadOnlyScopes,

    async authorize(input) {
      const pkceValid = verifyPkceChallenge(input.codeVerifier, input.codeChallenge);
      if (!pkceValid) {
        throw new Error('PKCE verification failed during OAuth authorization');
      }
      return {
        authorized: true,
        refreshToken: `rt_${provider}_${input.tenantId}_${Date.now()}`,
        scopes:
          input.grantedScopes.length > 0 ? input.grantedScopes : requiredReadOnlyScopes,
      };
    },

    async refreshToken(input) {
      if (!input.currentRefreshToken) {
        throw new Error('Missing refresh token for rotation');
      }
      return {
        newRefreshToken: `rt_${provider}_${input.tenantId}_rot_${Date.now()}`,
        rotatedAt: new Date().toISOString(),
      };
    },

    async testConnection() {
      return {
        healthy: true,
        latencyMs: 38,
        message: `${provider} read-only discovery endpoint reachable`,
      };
    },

    async discoverEntities(ctx): Promise<{
      nodes: GraphNode[];
      summary: Record<string, number>;
      evidence: FindingEvidenceArtifact[];
    }> {
      if (ctx.simulateFailure) {
        throw new Error(`Upstream ${provider} API rate limit (429) during discovery`);
      }
      if (provider === 'slack') {
        const nodes: GraphNode[] = [
          {
            id: `node_${ctx.tenantId}_slack_bot_ops`,
            tenantId: ctx.tenantId,
            provider: 'slack',
            externalResourceId: `slack:app:ops_triage_bot`,
            type: 'AI agent',
            label: 'Slack Ops Triage Bot',
            riskLevel: 'medium',
            metadata: { discoveredBy: 'slack', owner: 'it-ops@' },
          },
        ];
        return {
          nodes,
          summary: { 'Slack AI Apps': 3, Workspaces: 2 },
          evidence: [],
        };
      }
      if (provider === 'custom_http') {
        const nodes: GraphNode[] = [
          {
            id: `node_${ctx.tenantId}_custom_mcp`,
            tenantId: ctx.tenantId,
            provider: 'custom_http',
            externalResourceId: 'custom_http:internal-risk-mcp',
            type: 'MCP server',
            label: 'internal-risk-mcp',
            riskLevel: 'medium',
            metadata: { discoveredBy: 'custom_http' },
          },
        ];
        return {
          nodes,
          summary: { 'MCP Endpoints': 1 },
          evidence: [],
        };
      }
      return { nodes: [], summary: {}, evidence: [] };
    },

    async discoverRelationships(ctx) {
      if (ctx.simulateFailure) {
        throw new Error(`Upstream ${provider} API failure during edge discovery`);
      }
      if (provider === 'slack') {
        return [
          {
            id: `edge_${ctx.tenantId}_slack_ops_identity`,
            tenantId: ctx.tenantId,
            provider: 'slack',
            externalResourceId: 'slack:edge:ops_triage_identity',
            sourceId: `node_${ctx.tenantId}_slack_bot_ops`,
            targetId:
              ctx.tenantId === 'tenant_northwind'
                ? 'node_nw_id_support'
                : 'node_eu_id_gdpr',
            type: 'OPERATED_BY',
          },
        ];
      }
      return [];
    },

    async collectEvidence() {
      return [
        {
          id: `ev_${provider}_${Date.now()}`,
          controlCode: 'CC7.2',
          framework: 'SOC 2',
          title: `${provider} read-only metadata sync verified for tenant`,
          source: provider,
          capturedAt: new Date().toISOString(),
        },
      ];
    },
  };
}

export class ConnectorRegistry {
  private adapters = new Map<ConnectorRecord['provider'], ConnectorAdapter>();

  constructor() {
    this.register(createEntraAdapter());
    this.register(createAwsAdapter());
    this.register(createAzureAdapter());
    this.register(
      createProviderAdapter('microsoft_365', ['Sites.Read.All', 'Application.Read.All'])
    );
    this.register(
      createProviderAdapter('gcp', ['aiplatform.endpoints.list', 'iam.roles.list'])
    );
    this.register(
      createProviderAdapter('github', ['read:org', 'repo:status', 'installations:read'])
    );
    this.register(
      createProviderAdapter('slack', ['app_mentions:read', 'team:read'])
    );
    this.register(
      createProviderAdapter('jira', ['write:jira-work', 'read:jira-user'])
    );
    this.register(
      createProviderAdapter('servicenow', ['cmdb_ci_ai_agent.read', 'incident.write'])
    );
    this.register(
      createProviderAdapter('custom_http', ['mcp:metadata.read'])
    );
  }

  register(adapter: ConnectorAdapter) {
    this.adapters.set(adapter.provider, adapter);
  }

  get(provider: ConnectorRecord['provider']): ConnectorAdapter {
    const adapter = this.adapters.get(provider);
    if (!adapter) {
      throw new Error(`Unsupported connector provider: ${provider}`);
    }
    return adapter;
  }

  listProviders(): ConnectorRecord['provider'][] {
    return Array.from(this.adapters.keys());
  }
}

export { createPkcePair };
