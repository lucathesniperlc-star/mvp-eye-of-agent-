import React, { useState } from 'react';
import {
  CheckCircle2,
  KeyRound,
  RefreshCw,
  ShieldCheck,
  UserMinus,
  UserPlus,
  XCircle,
} from 'lucide-react';
import type {
  EnterpriseSsoConfig,
  PlatformHardeningItem,
  RbacRole,
  ReleaseGateCheck,
  ScimDirectoryUser,
} from '../types/security';

interface EnterpriseViewProps {
  tenantName: string;
  canAdminTenant: boolean;
  ssoConfig: EnterpriseSsoConfig;
  scimDirectory: ScimDirectoryUser[];
  idpGroupRoleMap: Record<string, RbacRole>;
  hardeningMatrix: PlatformHardeningItem[];
  releaseGates: ReleaseGateCheck[];
  onUpdateSsoConfig: (updates: {
    protocol?: 'saml_2_0' | 'oidc';
    ssoEnforced?: boolean;
    localPasswordFallbackDisabled?: boolean;
    mfaRequiredForAdmins?: boolean;
    scimEnabled?: boolean;
    rotateCertificate?: boolean;
  }) => Promise<void>;
  onProvisionScimUser: (payload: {
    email: string;
    displayName: string;
    idpGroups: string[];
  }) => Promise<void>;
  onDeprovisionScimUser: (email: string) => Promise<{ revokedSessionCount: number } | null>;
  onVerifyReleaseGates: () => Promise<void>;
}

const IDP_GROUPS = [
  'EyesOfAgent-Owners',
  'EyesOfAgent-SecurityAdmins',
  'EyesOfAgent-Analysts',
  'EyesOfAgent-Compliance',
  'EyesOfAgent-Auditors',
  'EyesOfAgent-AgentOwners',
];

export const EnterpriseView: React.FC<EnterpriseViewProps> = ({
  tenantName,
  canAdminTenant,
  ssoConfig,
  scimDirectory,
  idpGroupRoleMap,
  hardeningMatrix,
  releaseGates,
  onUpdateSsoConfig,
  onProvisionScimUser,
  onDeprovisionScimUser,
  onVerifyReleaseGates,
}) => {
  const [scimEmail, setScimEmail] = useState('sre-lead@northwind.com');
  const [scimName, setScimName] = useState('Jordan Patel');
  const [scimGroup, setScimGroup] = useState('EyesOfAgent-SecurityAdmins');
  const [statusMessage, setStatusMessage] = useState('');
  const [busy, setBusy] = useState(false);

  const passedCount = releaseGates.filter((g) => g.passed).length;

  const handleProvisionSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!scimEmail.trim()) return;
    setBusy(true);
    setStatusMessage('');
    try {
      await onProvisionScimUser({
        email: scimEmail.trim(),
        displayName: scimName.trim() || scimEmail.trim(),
        idpGroups: [scimGroup],
      });
      setStatusMessage(
        `SCIM 2.0 synced ${scimEmail.trim()} (${scimGroup} -> ${idpGroupRoleMap[scimGroup] ?? 'auditor'})`
      );
    } finally {
      setBusy(false);
    }
  };

  const handleDeprovision = async (email: string) => {
    setBusy(true);
    setStatusMessage('');
    try {
      const res = await onDeprovisionScimUser(email);
      if (res) {
        setStatusMessage(
          `SCIM deprovisioned ${email}: membership revoked and ${res.revokedSessionCount} active session(s) invalidated immediately.`
        );
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-semibold tracking-tight text-white">
            Enterprise SSO, SCIM 2.0 &amp; Hardening
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Identity federation, automated group-to-role provisioning, instant session revocation, and release gate verification for {tenantName}
          </p>
        </div>

        <button
          type="button"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            try {
              await onVerifyReleaseGates();
              setStatusMessage('Executed programmatic verification across all 8 enterprise release gates.');
            } finally {
              setBusy(false);
            }
          }}
          className="inline-flex items-center gap-2 rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50 whitespace-nowrap shrink-0"
        >
          <ShieldCheck className="w-4 h-4" aria-hidden="true" />
          <span>Verify all 8 release gates</span>
        </button>
      </div>

      {statusMessage && (
        <div
          role="status"
          className="rounded-lg border border-sky-500/30 bg-sky-500/10 px-4 py-2.5 text-xs text-sky-200"
        >
          {statusMessage}
        </div>
      )}

      {/* SSO Federation Config & IdP Group Mapping */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5 space-y-4 lg:col-span-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-sky-400 shrink-0" aria-hidden="true" />
              <h2 className="font-display text-base font-semibold text-white">
                Enterprise SSO &amp; MFA controls
              </h2>
            </div>
            <div className="flex items-center gap-1 rounded-lg border border-white/10 bg-[#090B10] p-1">
              <button
                type="button"
                disabled={!canAdminTenant}
                onClick={() => onUpdateSsoConfig({ protocol: 'saml_2_0' })}
                className={`rounded px-2.5 py-1 font-mono text-[11px] font-medium whitespace-nowrap ${
                  ssoConfig.protocol === 'saml_2_0'
                    ? 'bg-sky-500 text-slate-950'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                SAML 2.0
              </button>
              <button
                type="button"
                disabled={!canAdminTenant}
                onClick={() => onUpdateSsoConfig({ protocol: 'oidc' })}
                className={`rounded px-2.5 py-1 font-mono text-[11px] font-medium whitespace-nowrap ${
                  ssoConfig.protocol === 'oidc'
                    ? 'bg-sky-500 text-slate-950'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                OIDC
              </button>
            </div>
          </div>

          <div className="rounded-lg border border-white/[0.06] bg-[#090B10] p-3.5 space-y-2 text-xs">
            <div className="flex items-center justify-between gap-2">
              <span className="text-slate-400">Identity provider</span>
              <span className="font-medium text-white">{ssoConfig.idpName}</span>
            </div>
            <div className="flex items-center justify-between gap-2">
              <span className="text-slate-400">Issuer / Entity ID</span>
              <span className="font-mono text-[11px] text-slate-300 truncate max-w-[260px]">
                {ssoConfig.idpEntityId}
              </span>
            </div>
            <div className="flex items-center justify-between gap-2">
              <span className="text-slate-400">Signing cert fingerprint</span>
              <span className="font-mono text-[11px] text-emerald-400 break-all">
                {ssoConfig.certificateFingerprint}
              </span>
            </div>
            <div className="flex items-center justify-between gap-2">
              <span className="text-slate-400">MFA methods</span>
              <span className="font-mono text-[11px] text-slate-200">
                {ssoConfig.allowedMfaMethods.join(' + ').toUpperCase()} (enforced for admins)
              </span>
            </div>
          </div>

          <div className="space-y-2 text-xs">
            <label className="flex items-center justify-between rounded-lg border border-white/[0.06] bg-[#090B10] px-3 py-2 cursor-pointer">
              <span className="text-slate-200">Enforce enterprise SSO for all tenant logins</span>
              <input
                type="checkbox"
                disabled={!canAdminTenant}
                checked={ssoConfig.ssoEnforced}
                onChange={(e) => onUpdateSsoConfig({ ssoEnforced: e.target.checked })}
              />
            </label>
            <label className="flex items-center justify-between rounded-lg border border-white/[0.06] bg-[#090B10] px-3 py-2 cursor-pointer">
              <span className="text-slate-200">Disable local password fallback</span>
              <input
                type="checkbox"
                disabled={!canAdminTenant}
                checked={ssoConfig.localPasswordFallbackDisabled}
                onChange={(e) =>
                  onUpdateSsoConfig({ localPasswordFallbackDisabled: e.target.checked })
                }
              />
            </label>
            <label className="flex items-center justify-between rounded-lg border border-white/[0.06] bg-[#090B10] px-3 py-2 cursor-pointer">
              <span className="text-slate-200">Require TOTP / WebAuthn MFA for owners &amp; admins</span>
              <input
                type="checkbox"
                disabled={!canAdminTenant}
                checked={ssoConfig.mfaRequiredForAdmins}
                onChange={(e) => onUpdateSsoConfig({ mfaRequiredForAdmins: e.target.checked })}
              />
            </label>
          </div>

          <div className="flex items-center justify-between gap-3 pt-1">
            <span className="font-mono text-[11px] text-slate-400">
              Metadata validated: {ssoConfig.metadataValidated ? 'Yes' : 'Pending'} · Last rotated{' '}
              {ssoConfig.certificateRotatedAt.slice(0, 10)}
            </span>
            <button
              type="button"
              disabled={!canAdminTenant}
              onClick={async () => {
                await onUpdateSsoConfig({ rotateCertificate: true });
                setStatusMessage('Rotated IdP signing certificate and re-validated metadata.');
              }}
              className="inline-flex items-center gap-1.5 rounded-lg border border-white/15 bg-[#090B10] px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-sky-400/50 hover:text-white disabled:opacity-50 whitespace-nowrap"
            >
              <RefreshCw className="w-3.5 h-3.5 text-sky-400" aria-hidden="true" />
              <span>Rotate IdP cert</span>
            </button>
          </div>
        </div>

        {/* IdP Group-to-Role Mapping */}
        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5 space-y-4 lg:col-span-6">
          <div>
            <h2 className="font-display text-base font-semibold text-white">
              IdP group-to-role mapping (JIT &amp; SCIM 2.0)
            </h2>
            <p className="mt-0.5 text-xs text-slate-400">
              Every login and directory sync maps Okta / Entra ID group claims deterministically to least-privilege RBAC roles
            </p>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-white/[0.08] text-slate-400">
                  <th className="py-2 font-medium">IdP Group</th>
                  <th className="py-2 text-right font-medium">Eyes of Agent Role</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.06]">
                {Object.entries(idpGroupRoleMap).map(([group, role]) => (
                  <tr key={group}>
                    <td className="py-2.5 font-mono text-[11px] text-slate-200">{group}</td>
                    <td className="py-2.5 text-right font-mono text-[11px] font-medium text-sky-300">
                      {role}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* SCIM 2.0 Directory Sync & Immediate Session Revocation */}
      <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="font-display text-base font-semibold text-white">
              SCIM 2.0 directory sync &amp; instant session revocation
            </h2>
            <p className="text-xs text-slate-400">
              Provision or update user roles from IdP groups; disabling a user revokes tenant membership and kills active sessions immediately
            </p>
          </div>
          <span className="font-mono text-[11px] text-emerald-400">
            SCIM 2.0 endpoint active · Auto-revocation enabled
          </span>
        </div>

        <form onSubmit={handleProvisionSubmit} className="grid grid-cols-1 gap-3 md:grid-cols-12">
          <div className="md:col-span-4">
            <label htmlFor="scim-email" className="block text-[11px] text-slate-400">
              Corporate email
            </label>
            <input
              id="scim-email"
              type="email"
              value={scimEmail}
              onChange={(e) => setScimEmail(e.target.value)}
              className="mt-1 w-full rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 text-xs text-white focus:border-sky-500 focus:outline-none"
            />
          </div>
          <div className="md:col-span-3">
            <label htmlFor="scim-name" className="block text-[11px] text-slate-400">
              Display name
            </label>
            <input
              id="scim-name"
              type="text"
              value={scimName}
              onChange={(e) => setScimName(e.target.value)}
              className="mt-1 w-full rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 text-xs text-white focus:border-sky-500 focus:outline-none"
            />
          </div>
          <div className="md:col-span-3">
            <label htmlFor="scim-group" className="block text-[11px] text-slate-400">
              IdP Group Claim
            </label>
            <select
              id="scim-group"
              value={scimGroup}
              onChange={(e) => setScimGroup(e.target.value)}
              className="mt-1 w-full rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 font-mono text-xs text-white focus:border-sky-500 focus:outline-none"
            >
              {IDP_GROUPS.map((g) => (
                <option key={g} value={g}>
                  {g}
                </option>
              ))}
            </select>
          </div>
          <div className="md:col-span-2 flex items-end">
            <button
              type="submit"
              disabled={!canAdminTenant || busy}
              className="inline-flex w-full items-center justify-center gap-1.5 rounded-lg bg-sky-500 px-3 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50 whitespace-nowrap"
            >
              <UserPlus className="w-3.5 h-3.5" aria-hidden="true" />
              <span>SCIM Sync</span>
            </button>
          </div>
        </form>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-white/[0.08] bg-[#0D1017] text-slate-400">
                <th className="px-3 py-2.5 font-medium">Principal</th>
                <th className="px-3 py-2.5 font-medium">IdP Group</th>
                <th className="px-3 py-2.5 font-medium">Mapped Role</th>
                <th className="px-3 py-2.5 font-medium">Directory Status</th>
                <th className="px-3 py-2.5 text-right font-medium">Active Sessions</th>
                <th className="px-3 py-2.5 text-right font-medium">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06]">
              {scimDirectory.map((user) => (
                <tr key={user.id} className="hover:bg-white/[0.03]">
                  <td className="px-3 py-3">
                    <p className="font-medium text-white">{user.displayName}</p>
                    <p className="font-mono text-[11px] text-slate-400">{user.email}</p>
                  </td>
                  <td className="px-3 py-3 font-mono text-[11px] text-slate-300">
                    {user.idpGroups.join(', ')}
                  </td>
                  <td className="px-3 py-3 font-mono text-[11px] text-sky-300">
                    {user.mappedRole}
                  </td>
                  <td className="px-3 py-3">
                    <span
                      className={`font-mono text-[11px] font-medium ${
                        user.status === 'active' ? 'text-emerald-400' : 'text-rose-400'
                      }`}
                    >
                      {user.status}
                    </span>
                  </td>
                  <td className="px-3 py-3 text-right font-mono tabular-nums text-slate-200">
                    {user.activeSessionCount}
                  </td>
                  <td className="px-3 py-3 text-right">
                    {user.status === 'active' && user.mappedRole !== 'owner' ? (
                      <button
                        type="button"
                        disabled={!canAdminTenant || busy}
                        onClick={() => handleDeprovision(user.email)}
                        className="inline-flex items-center gap-1 rounded border border-rose-500/40 bg-rose-500/10 px-2.5 py-1 text-[11px] font-medium text-rose-300 hover:bg-rose-500/20 disabled:opacity-50 whitespace-nowrap"
                      >
                        <UserMinus className="w-3 h-3" aria-hidden="true" />
                        <span>Deprovision &amp; revoke</span>
                      </button>
                    ) : (
                      <span className="font-mono text-[11px] text-slate-500">
                        {user.mappedRole === 'owner' ? 'Protected owner' : 'Revoked'}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Release Gates (8 checks) & Platform Hardening Matrix */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5 space-y-4 lg:col-span-7">
          <div className="flex items-center justify-between gap-2">
            <h2 className="font-display text-base font-semibold text-white">
              Enterprise release gates ({passedCount} / {releaseGates.length} passed)
            </h2>
            <span className="font-mono text-xs text-emerald-400">
              {passedCount === releaseGates.length ? 'READY FOR RELEASE' : 'ACTION REQUIRED'}
            </span>
          </div>
          <div className="divide-y divide-white/[0.06]">
            {releaseGates.map((gate) => (
              <div key={gate.id} className="py-3 first:pt-1 last:pb-0 flex items-start justify-between gap-3">
                <div className="space-y-0.5">
                  <p className="text-xs font-medium text-white">{gate.name}</p>
                  <p className="text-[11px] text-slate-400">{gate.requirement}</p>
                  <p className="font-mono text-[11px] text-slate-300">{gate.detail}</p>
                </div>
                {gate.passed ? (
                  <span className="inline-flex items-center gap-1 font-mono text-[11px] font-medium text-emerald-400 whitespace-nowrap shrink-0">
                    <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>Passed</span>
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 font-mono text-[11px] font-medium text-rose-400 whitespace-nowrap shrink-0">
                    <XCircle className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>Failed</span>
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5 space-y-4 lg:col-span-5">
          <h2 className="font-display text-base font-semibold text-white">
            Platform hardening matrix
          </h2>
          <div className="divide-y divide-white/[0.06]">
            {hardeningMatrix.map((item) => (
              <div key={item.area} className="py-2.5 first:pt-0 last:pb-0 space-y-1">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-medium text-white">{item.area}</span>
                  <span className="font-mono text-[11px] text-emerald-400 uppercase">
                    {item.status}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400">{item.control}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
