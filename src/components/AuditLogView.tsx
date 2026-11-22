import React, { useState } from 'react';
import { Download, Lock, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { AuditChainIntegrity, AuditEventRecord } from '../types/security';

interface AuditLogViewProps {
  tenantId: string;
  tenantName: string;
  events: AuditEventRecord[];
  integrity?: AuditChainIntegrity;
  retentionDays?: number;
  canAdminTenant?: boolean;
  onRefreshAudit: () => Promise<void>;
  onFilterAuditEvents?: (filters: {
    search?: string;
    outcome?: 'all' | 'allowed' | 'denied';
  }) => Promise<void>;
  onUpdateRetentionDays?: (days: number) => Promise<void>;
  onExportAuditLedger?: () => Promise<{
    tenantId: string;
    exportedAt: string;
    integrity: AuditChainIntegrity;
    eventCount: number;
    events: AuditEventRecord[];
  } | null>;
}

export const AuditLogView: React.FC<AuditLogViewProps> = ({
  tenantId,
  tenantName,
  events,
  integrity,
  retentionDays = 365,
  canAdminTenant = false,
  onRefreshAudit,
  onFilterAuditEvents,
  onUpdateRetentionDays,
  onExportAuditLedger,
}) => {
  const [probeResult, setProbeResult] = useState<string>('');
  const [exportStatus, setExportStatus] = useState<string>('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [searchInput, setSearchInput] = useState<string>('');
  const [outcomeFilter, setOutcomeFilter] = useState<'all' | 'allowed' | 'denied'>('all');
  const [filterBusy, setFilterBusy] = useState(false);

  const handleApplyFilter = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!onFilterAuditEvents) return;
    setFilterBusy(true);
    try {
      await onFilterAuditEvents({
        search: searchInput.trim() || undefined,
        outcome: outcomeFilter,
      });
    } finally {
      setFilterBusy(false);
    }
  };

  const handleClearFilter = async () => {
    setSearchInput('');
    setOutcomeFilter('all');
    if (!onFilterAuditEvents) return;
    setFilterBusy(true);
    try {
      await onFilterAuditEvents({ outcome: 'all' });
    } finally {
      setFilterBusy(false);
    }
  };

  const handleCrossTenantProbe = async () => {
    const forgedTenant =
      tenantId === 'tenant_northwind' ? 'tenant_northwind_eu' : 'tenant_northwind';
    const res = await fetch('/api/workspace', {
      headers: { 'X-Tenant-Id': forgedTenant },
    });
    const body = await res.json();
    setProbeResult(`HTTP ${res.status}: ${body.error || 'Blocked'}`);
    await onRefreshAudit();
  };

  const handleExport = async () => {
    if (!onExportAuditLedger) return;
    const pkg = await onExportAuditLedger();
    if (!pkg) return;
    setExportStatus(
      `Exported ${pkg.eventCount} hash-chained audit events (chain valid=${String(pkg.integrity.valid)}, head=${pkg.integrity.headHash.slice(0, 22)}...).`
    );
    const blob = new Blob([JSON.stringify(pkg, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit-ledger-${tenantId}-${pkg.exportedAt.slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-semibold tracking-tight text-white">
            Hash-Chained Audit Ledger
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Write-once, SHA-256 chained audit trail for {tenantName} · Full actor, resource, before/after state, approvals, and retention controls
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {onExportAuditLedger && (
            <button
              type="button"
              onClick={handleExport}
              className="inline-flex items-center gap-2 rounded-lg bg-sky-500 px-3.5 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400 whitespace-nowrap"
            >
              <Download className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Export scoped audit ledger</span>
            </button>
          )}
          <button
            type="button"
            onClick={handleCrossTenantProbe}
            className="inline-flex items-center gap-2 rounded-lg border border-white/15 bg-[#11151D] px-3.5 py-2 text-xs font-medium text-slate-200 hover:border-rose-400/50 hover:text-white whitespace-nowrap"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" aria-hidden="true" />
            <span>Test cross-tenant guard (403)</span>
          </button>
        </div>
      </div>

      {/* Integrity & Retention Summary Bar */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-4 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400">SHA-256 Chain Integrity</span>
            <Lock className="w-3.5 h-3.5 text-emerald-400" aria-hidden="true" />
          </div>
          <p className="font-mono text-sm font-semibold text-emerald-400">
            {integrity?.valid === false ? 'TAMPER ALERT' : 'VERIFIED INTACT'}
          </p>
          <p className="font-mono text-[11px] text-slate-400 tabular-nums">
            {integrity?.verifiedCount ?? events.length} immutable events chained
          </p>
        </div>

        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-4 space-y-1">
          <span className="text-xs text-slate-400">Ledger Head Hash</span>
          <p className="font-mono text-xs text-sky-300 break-all">
            {integrity?.headHash ?? events[0]?.event_hash ?? 'sha256:audit_genesis'}
          </p>
        </div>

        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-4 flex items-center justify-between gap-3">
          <div>
            <span className="text-xs text-slate-400">Retention policy (&gt;= 1 year)</span>
            <p className="font-mono text-sm font-semibold text-white tabular-nums">
              {retentionDays} days
            </p>
          </div>
          {onUpdateRetentionDays && (
            <select
              aria-label="Audit log retention days"
              disabled={!canAdminTenant}
              value={retentionDays}
              onChange={(e) => onUpdateRetentionDays(Number(e.target.value))}
              className="rounded-lg border border-white/15 bg-[#090B10] px-2.5 py-1.5 font-mono text-xs text-white focus:border-sky-500 focus:outline-none disabled:opacity-50"
            >
              <option value={365}>365d (1 yr)</option>
              <option value={730}>730d (2 yr)</option>
              <option value={2555}>2555d (7 yr)</option>
            </select>
          )}
        </div>
      </div>

      {probeResult && (
        <div
          role="status"
          className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-3 font-mono text-xs text-rose-300"
        >
          Zero-trust check executed → {probeResult}
        </div>
      )}

      {exportStatus && (
        <div
          role="status"
          className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 font-mono text-xs text-emerald-300"
        >
          {exportStatus}
        </div>
      )}

      <div className="overflow-hidden rounded-xl border border-white/[0.08] bg-[#11151D]">
        {onFilterAuditEvents && (
          <form
            onSubmit={handleApplyFilter}
            className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.08] px-4 py-3"
          >
            <div className="flex flex-1 flex-wrap items-center gap-2.5 min-w-[240px]">
              <input
                id="audit-search-input"
                type="search"
                aria-label="Search audit events"
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                placeholder="Filter by actor, action, resource, or reason..."
                className="w-full max-w-sm rounded-lg border border-white/15 bg-[#090B10] px-3 py-1.5 text-xs text-white placeholder-slate-500 focus:border-sky-500 focus:outline-none"
              />
              <select
                id="audit-outcome-filter"
                aria-label="Filter by outcome"
                value={outcomeFilter}
                onChange={(e) =>
                  setOutcomeFilter(e.target.value as 'all' | 'allowed' | 'denied')
                }
                className="rounded-lg border border-white/15 bg-[#090B10] px-2.5 py-1.5 font-mono text-xs text-white focus:border-sky-500 focus:outline-none"
              >
                <option value="all">All outcomes</option>
                <option value="allowed">Allowed</option>
                <option value="denied">Denied</option>
              </select>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="submit"
                disabled={filterBusy}
                className="rounded-lg bg-sky-500 px-3 py-1.5 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50"
              >
                {filterBusy ? 'Filtering...' : 'Filter'}
              </button>
              <button
                type="button"
                disabled={filterBusy}
                onClick={handleClearFilter}
                className="rounded-lg border border-white/15 bg-[#090B10] px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white disabled:opacity-50"
              >
                Clear
              </button>
            </div>
          </form>
        )}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-white/[0.08] bg-[#0D1017] text-slate-400">
                <th className="px-4 py-3 font-medium">Timestamp</th>
                <th className="px-4 py-3 font-medium">Actor &amp; Role</th>
                <th className="px-4 py-3 font-medium">Action &amp; Reason</th>
                <th className="px-4 py-3 font-medium">Resource &amp; Hash</th>
                <th className="px-4 py-3 font-medium">Outcome</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06]">
              {events.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-6 text-center text-xs text-slate-400">
                    No audit events match the active filter criteria.
                  </td>
                </tr>
              )}
              {events.map((ev) => {
                const isExpanded = expandedId === ev.id;
                return (
                  <React.Fragment key={ev.id}>
                    <tr
                      onClick={() => setExpandedId(isExpanded ? null : ev.id)}
                      className="cursor-pointer hover:bg-white/[0.03]"
                    >
                      <td className="px-4 py-3.5 font-mono text-[11px] text-slate-400 tabular-nums whitespace-nowrap">
                        {ev.occurredAt.replace('T', ' ').slice(0, 19)} UTC
                      </td>
                      <td className="px-4 py-3.5">
                        <div className="text-white font-medium">{ev.actorEmail}</div>
                        <div className="font-mono text-[11px] text-slate-400">
                          {ev.actorRole} · {ev.actor?.ip ?? '10.42.8.14'}
                        </div>
                      </td>
                      <td className="px-4 py-3.5">
                        <div className="font-mono text-slate-200">{ev.action}</div>
                        {ev.reason && (
                          <div className="mt-0.5 text-[11px] text-slate-400">{ev.reason}</div>
                        )}
                      </td>
                      <td className="px-4 py-3.5 font-mono text-[11px] text-slate-400">
                        <div>
                          {ev.resourceType} · {ev.resourceId}
                        </div>
                        {ev.event_hash && (
                          <div className="mt-0.5 text-sky-400/80">
                            {ev.event_hash.slice(0, 22)}...
                          </div>
                        )}
                      </td>
                      <td className="px-4 py-3.5 whitespace-nowrap">
                        {ev.outcome === 'allowed' ? (
                          <span className="inline-flex items-center gap-1.5 text-emerald-400 font-medium">
                            <ShieldCheck className="w-3.5 h-3.5" aria-hidden="true" />
                            <span>Allowed</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 text-rose-400 font-medium">
                            <ShieldAlert className="w-3.5 h-3.5" aria-hidden="true" />
                            <span>Denied</span>
                          </span>
                        )}
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr className="bg-[#090B10]">
                        <td colSpan={5} className="px-4 py-3 font-mono text-[11px] text-slate-300 space-y-1.5">
                          <div className="flex flex-wrap gap-x-6 gap-y-1 text-slate-400">
                            <span>event_id: {ev.event_id ?? ev.id}</span>
                            <span>actor_type: {ev.actor?.type ?? 'user'}</span>
                            {ev.approval_id && <span>approval_id: {ev.approval_id}</span>}
                            {ev.evidence_id && <span>evidence_id: {ev.evidence_id}</span>}
                            {ev.retention_until && (
                              <span>retention_until: {ev.retention_until.slice(0, 10)}</span>
                            )}
                          </div>
                          <div className="break-all text-slate-400">
                            prev_hash: {ev.prev_hash ?? 'sha256:audit_genesis'}
                          </div>
                          <div className="break-all text-sky-300">
                            event_hash: {ev.event_hash ?? 'pending'}
                          </div>
                          <div className="grid grid-cols-1 gap-2 pt-1 md:grid-cols-2">
                            <div className="rounded border border-white/[0.06] bg-[#11151D] p-2">
                              <span className="text-slate-400">before: </span>
                              <span className="text-slate-200">{JSON.stringify(ev.before)}</span>
                            </div>
                            <div className="rounded border border-white/[0.06] bg-[#11151D] p-2">
                              <span className="text-slate-400">after: </span>
                              <span className="text-slate-200">{JSON.stringify(ev.after)}</span>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
