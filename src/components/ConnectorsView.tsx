import React, { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Cloud,
  KeyRound,
  Plus,
  RefreshCw,
  ShieldCheck,
  Unplug,
  X,
} from 'lucide-react';
import type { Connector } from '../types/security';

export type CloudOnboardProvider = 'entra_id' | 'aws' | 'azure';

interface ConnectorsViewProps {
  tenantId: string;
  connectors: Connector[];
  canManageConnectors: boolean;
  onRunSync: (connectorId: string) => Promise<void>;
  onRunAllSyncs: () => Promise<void>;
  onOnboardAllClouds?: () => Promise<{ connectorsSynced: number; nodesAdded: number; edgesAdded: number } | null>;
  onPkceAuthorize: (connectorId: string) => Promise<string>;
  onRotateToken: (connectorId: string) => Promise<string>;
  onDisconnect: (connectorId: string) => Promise<void>;
  onOnboardCloud: (
    provider: CloudOnboardProvider,
    config: Record<string, string>
  ) => Promise<string>;
}

const AWS_POLICY_JSON = `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "iam:ListUsers", "iam:ListRoles", "iam:ListPolicies",
      "iam:GetPolicy", "iam:GetPolicyVersion", "iam:GetRole",
      "iam:ListAttachedRolePolicies", "iam:ListRolePolicies",
      "s3:ListAllMyBuckets", "s3:GetBucketPolicy", "s3:GetBucketAcl",
      "kms:ListKeys", "kms:DescribeKey", "access-analyzer:ListFindings"
    ],
    "Resource": "*"
  }]
}`;

const AZURE_READER_ACTIONS = [
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

const ENTRA_SCOPES = [
  'User.Read.All',
  'Group.Read.All',
  'Application.Read.All',
  'Directory.Read.All',
  'RoleManagement.Read.Directory',
];

export const ConnectorsView: React.FC<ConnectorsViewProps> = ({
  tenantId,
  connectors,
  canManageConnectors,
  onRunSync,
  onRunAllSyncs,
  onOnboardAllClouds,
  onPkceAuthorize,
  onRotateToken,
  onDisconnect,
  onOnboardCloud,
}) => {
  const tenantConnectors = connectors.filter((c) => c.tenantId === tenantId);
  const [statusMessage, setStatusMessage] = useState<string>('');
  const [errorMessage, setErrorMessage] = useState<string>('');
  const [onboardOpen, setOnboardOpen] = useState(false);
  const [activeProvider, setActiveProvider] = useState<CloudOnboardProvider>('aws');
  const [submitting, setSubmitting] = useState(false);

  // Entra ID form state
  const [entraDomain, setEntraDomain] = useState('northwind.com');
  const [entraConsentConfirmed, setEntraConsentConfirmed] = useState(true);

  // AWS form state (STS External ID, never access keys)
  const [awsAccountId, setAwsAccountId] = useState('449102881234');
  const [awsRoleArn, setAwsRoleArn] = useState(
    'arn:aws:iam::449102881234:role/EyesOfAgentReadOnlyRole'
  );
  const [awsExternalId, setAwsExternalId] = useState('eoa-nw-8f3a91c2');

  // Azure form state (Workload Identity Federation)
  const [azureSubId, setAzureSubId] = useState('sub-nw-prod-01');
  const [azureClientId, setAzureClientId] = useState('wif-eoa-northwind-reader');

  const handleAction = async (fn: () => Promise<string | void>, fallbackMsg?: string) => {
    setErrorMessage('');
    try {
      const msg = await fn();
      if (typeof msg === 'string') setStatusMessage(msg);
      else if (fallbackMsg) setStatusMessage(fallbackMsg);
    } catch (err) {
      setErrorMessage((err as Error).message || 'Connector action failed');
    }
  };

  const handleOnboardSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage('');
    setStatusMessage('');
    setSubmitting(true);
    try {
      let config: Record<string, string>;
      if (activeProvider === 'entra_id') {
        if (!entraConsentConfirmed) {
          throw new Error('Tenant-wide application admin consent is required for Entra ID discovery.');
        }
        config = { tenantDomain: entraDomain.trim(), adminConsent: 'granted' };
      } else if (activeProvider === 'aws') {
        config = {
          accountId: awsAccountId.trim(),
          roleArn: awsRoleArn.trim(),
          externalId: awsExternalId.trim(),
        };
      } else {
        config = {
          subscriptionId: azureSubId.trim(),
          clientId: azureClientId.trim(),
          authMethod: 'Workload Identity Federation',
        };
      }

      const msg = await onOnboardCloud(activeProvider, config);
      setStatusMessage(msg);
      setOnboardOpen(false);
    } catch (err) {
      setErrorMessage((err as Error).message || 'Onboarding validation failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-semibold tracking-tight text-white">
            Cloud &amp; Identity Connectors
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Read-only discovery adapters across Entra ID, AWS, and Azure · Zero automated customer IAM writes
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {canManageConnectors && (
            <button
              type="button"
              onClick={() => {
                setErrorMessage('');
                setOnboardOpen((v) => !v);
              }}
              className="inline-flex items-center gap-2 rounded-lg border border-white/15 bg-[#11151D] px-3.5 py-2 text-xs font-medium text-white hover:border-sky-500/50 whitespace-nowrap"
            >
              <Plus className="w-3.5 h-3.5 text-sky-400" aria-hidden="true" />
              <span>Connect Entra / AWS / Azure</span>
            </button>
          )}
          {canManageConnectors && onOnboardAllClouds && (
            <button
              type="button"
              onClick={() =>
                handleAction(async () => {
                  const res = await onOnboardAllClouds();
                  return res
                    ? `Onboarded & synced ${res.connectorsSynced} cloud/IdP providers (+${res.nodesAdded} nodes, +${res.edgesAdded} edges).`
                    : 'Batch cloud sync completed.';
                })
              }
              className="inline-flex items-center gap-2 rounded-lg border border-white/15 bg-[#11151D] px-3.5 py-2 text-xs font-medium text-white hover:border-sky-500/50 whitespace-nowrap"
            >
              <Cloud className="w-3.5 h-3.5 text-emerald-400" aria-hidden="true" />
              <span>Onboard &amp; sync all</span>
            </button>
          )}
          <button
            type="button"
            disabled={!canManageConnectors}
            onClick={() => handleAction(onRunAllSyncs, 'Discovery scan completed for active connectors.')}
            className="inline-flex items-center gap-2 rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-40 disabled:cursor-not-allowed whitespace-nowrap"
          >
            <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" />
            <span>{canManageConnectors ? 'Run discovery scan' : 'Read-only (Admin required)'}</span>
          </button>
        </div>
      </div>

      {/* Read-Only Guardrail Notice */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-white/[0.08] bg-[#11151D] px-4 py-3 text-xs">
        <div className="flex items-center gap-2.5 text-slate-300">
          <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" aria-hidden="true" />
          <span>
            Least-privilege read-only mode enforced · Discovery syncs normalize entities idempotently by{' '}
            <span className="font-mono text-white">(tenant_id, provider, external_resource_id)</span>
          </span>
        </div>
        <span className="font-mono text-[11px] text-slate-400">
          Tenant-scoped KMS AES-256-GCM credentials
        </span>
      </div>

      {statusMessage && (
        <div
          role="status"
          className="rounded-lg border border-sky-500/30 bg-sky-500/10 px-4 py-2.5 text-xs text-sky-200 font-mono"
        >
          {statusMessage}
        </div>
      )}

      {errorMessage && (
        <div
          role="alert"
          className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-2.5 text-xs text-rose-300 font-mono"
        >
          {errorMessage}
        </div>
      )}

      {/* Three-Cloud Read-Only Onboarding Panel */}
      {onboardOpen && canManageConnectors && (
        <section
          aria-label="Connect read-only cloud or identity provider"
          className="rounded-xl border border-sky-500/30 bg-[#11151D] p-6 space-y-5"
        >
          <div className="flex items-start justify-between gap-4">
            <div>
              <h2 className="font-display text-lg font-semibold text-white">
                Read-Only Provider Onboarding
              </h2>
              <p className="mt-1 text-xs text-slate-400">
                Configure least-privilege discovery access without long-lived keys or write permissions.
              </p>
            </div>
            <button
              type="button"
              aria-label="Close onboarding panel"
              onClick={() => setOnboardOpen(false)}
              className="rounded-md p-1.5 text-slate-400 hover:bg-white/10 hover:text-white"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="flex flex-wrap gap-2 border-b border-white/[0.08] pb-4" role="tablist" aria-label="Select cloud provider">
            <button
              type="button"
              role="tab"
              aria-selected={activeProvider === 'aws'}
              onClick={() => setActiveProvider('aws')}
              className={`rounded-lg px-3.5 py-2 text-xs font-medium transition-colors ${
                activeProvider === 'aws'
                  ? 'bg-sky-500 text-slate-950 font-semibold'
                  : 'border border-white/10 bg-[#090B10] text-slate-300 hover:text-white'
              }`}
            >
              Connect AWS Cross-Account Role
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={activeProvider === 'entra_id'}
              onClick={() => setActiveProvider('entra_id')}
              className={`rounded-lg px-3.5 py-2 text-xs font-medium transition-colors ${
                activeProvider === 'entra_id'
                  ? 'bg-sky-500 text-slate-950 font-semibold'
                  : 'border border-white/10 bg-[#090B10] text-slate-300 hover:text-white'
              }`}
            >
              Connect Microsoft Entra ID
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={activeProvider === 'azure'}
              onClick={() => setActiveProvider('azure')}
              className={`rounded-lg px-3.5 py-2 text-xs font-medium transition-colors ${
                activeProvider === 'azure'
                  ? 'bg-sky-500 text-slate-950 font-semibold'
                  : 'border border-white/10 bg-[#090B10] text-slate-300 hover:text-white'
              }`}
            >
              Connect Azure Security Reader
            </button>
          </div>

          <form onSubmit={handleOnboardSubmit} className="grid grid-cols-1 gap-6 lg:grid-cols-12">
            <div className="space-y-4 lg:col-span-6">
              {activeProvider === 'aws' && (
                <>
                  <div>
                    <label htmlFor="aws-account-id" className="block text-xs font-medium text-slate-300">
                      AWS Account ID (12 digits)
                    </label>
                    <input
                      id="aws-account-id"
                      type="text"
                      value={awsAccountId}
                      onChange={(e) => setAwsAccountId(e.target.value)}
                      placeholder="449102881234"
                      className="mt-1.5 w-full rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 font-mono text-xs text-white focus:border-sky-500 focus:outline-none"
                    />
                  </div>
                  <div>
                    <label htmlFor="aws-role-arn" className="block text-xs font-medium text-slate-300">
                      Cross-Account Read-Only IAM Role ARN
                    </label>
                    <input
                      id="aws-role-arn"
                      type="text"
                      value={awsRoleArn}
                      onChange={(e) => setAwsRoleArn(e.target.value)}
                      className="mt-1.5 w-full rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 font-mono text-xs text-white focus:border-sky-500 focus:outline-none"
                    />
                  </div>
                  <div>
                    <label htmlFor="aws-external-id" className="block text-xs font-medium text-slate-300">
                      STS External ID (Confused-Deputy Guard)
                    </label>
                    <input
                      id="aws-external-id"
                      type="text"
                      value={awsExternalId}
                      onChange={(e) => setAwsExternalId(e.target.value)}
                      className="mt-1.5 w-full rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 font-mono text-xs text-white focus:border-sky-500 focus:outline-none"
                    />
                  </div>
                  <p className="text-[11px] text-slate-400">
                    Long-lived IAM access keys are blocked. Role assumption runs strictly from allowlisted control-plane egress IPs.
                  </p>
                </>
              )}

              {activeProvider === 'entra_id' && (
                <>
                  <div>
                    <label htmlFor="entra-tenant-domain" className="block text-xs font-medium text-slate-300">
                      Microsoft Entra ID Tenant Domain
                    </label>
                    <input
                      id="entra-tenant-domain"
                      type="text"
                      value={entraDomain}
                      onChange={(e) => setEntraDomain(e.target.value)}
                      placeholder="northwind.com"
                      className="mt-1.5 w-full rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 font-mono text-xs text-white focus:border-sky-500 focus:outline-none"
                    />
                  </div>
                  <label className="flex items-start gap-2.5 text-xs text-slate-300 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={entraConsentConfirmed}
                      onChange={(e) => setEntraConsentConfirmed(e.target.checked)}
                      className="mt-0.5 rounded border-white/20 bg-[#090B10]"
                    />
                    <span>
                      Tenant admin granted application read-only consent on Microsoft consent screen (app-only token flow)
                    </span>
                  </label>
                </>
              )}

              {activeProvider === 'azure' && (
                <>
                  <div>
                    <label htmlFor="azure-sub-id" className="block text-xs font-medium text-slate-300">
                      Azure Subscription ID
                    </label>
                    <input
                      id="azure-sub-id"
                      type="text"
                      value={azureSubId}
                      onChange={(e) => setAzureSubId(e.target.value)}
                      className="mt-1.5 w-full rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 font-mono text-xs text-white focus:border-sky-500 focus:outline-none"
                    />
                  </div>
                  <div>
                    <label htmlFor="azure-client-id" className="block text-xs font-medium text-slate-300">
                      Workload Identity Federation / Managed Identity Client ID
                    </label>
                    <input
                      id="azure-client-id"
                      type="text"
                      value={azureClientId}
                      onChange={(e) => setAzureClientId(e.target.value)}
                      className="mt-1.5 w-full rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 font-mono text-xs text-white focus:border-sky-500 focus:outline-none"
                    />
                  </div>
                  <p className="text-[11px] text-slate-400">
                    Uses federated workload identity with custom role Eyes of Agent Security Reader (no client secret stored).
                  </p>
                </>
              )}

              <div className="pt-2">
                <button
                  type="submit"
                  disabled={submitting}
                  className="inline-flex items-center gap-2 rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50"
                >
                  <Cloud className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>
                    {submitting
                      ? 'Syncing discovery graph...'
                      : `Verify Read-Only & Run ${activeProvider.toUpperCase()} Sync`}
                  </span>
                </button>
              </div>
            </div>

            <div className="rounded-lg border border-white/[0.08] bg-[#090B10] p-4 lg:col-span-6">
              <p className="text-xs font-medium text-white">
                {activeProvider === 'aws'
                  ? 'Minimum Read-Only IAM Policy Template'
                  : activeProvider === 'entra_id'
                    ? 'Minimum Microsoft Graph Application Permissions'
                    : 'Eyes of Agent Security Reader Role Actions'}
              </p>
              {activeProvider === 'aws' && (
                <pre className="mt-2 max-h-56 overflow-auto font-mono text-[11px] leading-relaxed text-slate-300">
                  {AWS_POLICY_JSON}
                </pre>
              )}
              {activeProvider === 'entra_id' && (
                <ul className="mt-2.5 space-y-1.5 font-mono text-[11px] text-slate-300">
                  {ENTRA_SCOPES.map((s) => (
                    <li key={s}>· {s}</li>
                  ))}
                  <li className="pt-2 text-slate-400 font-sans">
                    Discovers: /users, /groups, /servicePrincipals, appRoleAssignedTo, oauth2PermissionGrants, directoryRoles
                  </li>
                </ul>
              )}
              {activeProvider === 'azure' && (
                <ul className="mt-2.5 space-y-1 font-mono text-[11px] text-slate-300">
                  {AZURE_READER_ACTIONS.map((act) => (
                    <li key={act}>· {act}</li>
                  ))}
                </ul>
              )}
            </div>
          </form>
        </section>
      )}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
        {tenantConnectors.map((conn) => {
          const summaryEntries = conn.discoveredSummary
            ? Object.entries(conn.discoveredSummary)
            : [];
          return (
            <div
              key={conn.id}
              className="flex flex-col justify-between rounded-xl border border-white/[0.08] bg-[#11151D] p-5"
            >
              <div>
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-[11px] font-medium text-slate-400">
                      {conn.category} · Read-only
                    </p>
                    <h2 className="mt-0.5 font-display text-base font-semibold text-white">
                      {conn.name}
                    </h2>
                  </div>
                  {conn.status === 'healthy' ? (
                    <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-400">
                      <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" />
                      <span>Healthy</span>
                    </span>
                  ) : conn.status === 'syncing' ? (
                    <span className="inline-flex items-center gap-1 text-xs font-medium text-sky-400">
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
                      <span>Syncing</span>
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-xs font-medium text-amber-400">
                      <AlertTriangle className="w-3.5 h-3.5" aria-hidden="true" />
                      <span>{conn.lastSync === 'Disconnected' ? 'Disconnected' : 'Partial'}</span>
                    </span>
                  )}
                </div>

                <p className="mt-3 font-mono text-[11px] text-slate-400 line-clamp-2">
                  {conn.scopesSummary}
                </p>

                {summaryEntries.length > 0 && (
                  <p className="mt-2.5 text-[11px] text-slate-300 tabular-nums">
                    {summaryEntries.map(([k, v], idx) => (
                      <React.Fragment key={k}>
                        {idx > 0 && ' · '}
                        <span>
                          {k}: <strong className="font-mono text-white">{v}</strong>
                        </span>
                      </React.Fragment>
                    ))}
                  </p>
                )}
              </div>

              <div className="mt-5 border-t border-white/[0.08] pt-4 space-y-3">
                <div className="flex items-center justify-between text-xs">
                  <div className="font-mono text-slate-300 tabular-nums">
                    {conn.coveragePct}% coverage · {conn.discoveredAssets} assets
                  </div>
                  <button
                    type="button"
                    disabled={!canManageConnectors}
                    onClick={() => handleAction(() => onRunSync(conn.id), `${conn.name} synced idempotently.`)}
                    className="font-medium text-sky-400 hover:text-sky-300 disabled:opacity-40"
                  >
                    Sync ({conn.lastSync})
                  </button>
                </div>

                {canManageConnectors && (
                  <div className="flex flex-wrap items-center gap-2 pt-1 text-[11px]">
                    <button
                      type="button"
                      onClick={() => handleAction(() => onPkceAuthorize(conn.id))}
                      className="inline-flex items-center gap-1 rounded border border-white/15 bg-[#090B10] px-2 py-1 text-slate-300 hover:text-white"
                    >
                      <KeyRound className="w-3 h-3 text-sky-400" aria-hidden="true" />
                      <span>OAuth PKCE</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => handleAction(() => onRotateToken(conn.id))}
                      className="rounded border border-white/15 bg-[#090B10] px-2 py-1 text-slate-300 hover:text-white"
                    >
                      Rotate KMS token
                    </button>
                    <button
                      type="button"
                      onClick={() =>
                        handleAction(() => onDisconnect(conn.id), `${conn.name} disconnected & credentials revoked.`)
                      }
                      className="inline-flex items-center gap-1 rounded border border-white/15 bg-[#090B10] px-2 py-1 text-rose-300 hover:border-rose-500/40"
                    >
                      <Unplug className="w-3 h-3" aria-hidden="true" />
                      <span>Revoke</span>
                    </button>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
