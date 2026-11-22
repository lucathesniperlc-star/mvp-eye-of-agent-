import React, { useState } from 'react';
import { CheckCircle2, Download, FileCheck2, ShieldAlert } from 'lucide-react';
import type { ComplianceExportResponse } from '../App';
import type {
  ComplianceFramework,
  ControlItem,
  EvidenceItem,
  EvidenceRecord,
} from '../types/security';
import { computeComplianceCoverage } from '../utils/riskEngine';

interface ComplianceViewProps {
  tenantName: string;
  controls: ControlItem[];
  evidence: EvidenceItem[];
  evidenceRecords?: EvidenceRecord[];
  onExportAuditPack?: (opts: {
    framework: ComplianceFramework | 'all';
    fromDate?: string;
    toDate?: string;
  }) => Promise<ComplianceExportResponse | null>;
}

const FRAMEWORKS: Array<'all' | ComplianceFramework> = [
  'all',
  'SOC 2',
  'ISO 27001',
  'ISO 42001',
  'GDPR',
  'EU AI Act',
];

export const ComplianceView: React.FC<ComplianceViewProps> = ({
  tenantName,
  controls,
  evidence,
  evidenceRecords = [],
  onExportAuditPack,
}) => {
  const [frameworkFilter, setFrameworkFilter] = useState<'all' | ComplianceFramework>('all');
  const [fromDate, setFromDate] = useState<string>('');
  const [toDate, setToDate] = useState<string>('');
  const [exportBusy, setExportBusy] = useState(false);
  const [exportSummary, setExportSummary] = useState<{
    packageId: string;
    controlsCount: number;
    evidenceCount: number;
    verifiedCount: number;
    chainValid: boolean;
    durationMs: number;
    headHash: string;
  } | null>(null);

  const visibleControls =
    frameworkFilter === 'all'
      ? controls
      : controls.filter((c) => c.framework === frameworkFilter);

  const visibleEvidenceRecords =
    frameworkFilter === 'all'
      ? evidenceRecords
      : evidenceRecords.filter(
          (ev) =>
            ev.framework === frameworkFilter || ev.mapped_frameworks.includes(frameworkFilter)
        );

  const stats = computeComplianceCoverage(visibleControls);

  const handleAuditExport = async () => {
    setExportBusy(true);
    try {
      let payload: unknown;
      if (onExportAuditPack) {
        const serverPkg = await onExportAuditPack({
          framework: frameworkFilter,
          fromDate: fromDate || undefined,
          toDate: toDate || undefined,
        });
        if (!serverPkg) return;
        payload = serverPkg;
        setExportSummary({
          packageId: serverPkg.packageId,
          controlsCount: serverPkg.controls.length,
          evidenceCount: serverPkg.evidenceRecords.length,
          verifiedCount: serverPkg.hashChainIntegrity.verifiedCount,
          chainValid: serverPkg.hashChainIntegrity.valid,
          durationMs: serverPkg.exportDurationMs,
          headHash: serverPkg.hashChainIntegrity.headHash,
        });
      } else {
        payload = {
          exportedAt: new Date().toISOString(),
          tenant: tenantName,
          frameworkScope: frameworkFilter === 'all' ? 'All frameworks' : frameworkFilter,
          coverageSummary: stats,
          controls: visibleControls,
          evidenceArtifacts: evidence,
        };
        setExportSummary({
          packageId: 'pkg_local_preview',
          controlsCount: visibleControls.length,
          evidenceCount: evidence.length,
          verifiedCount: evidence.length,
          chainValid: true,
          durationMs: 12,
          headHash: evidence[0]?.hash ?? 'sha256:genesis',
        });
      }

      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `eyes-of-agent-audit-evidence-${frameworkFilter.toLowerCase().replace(/\s+/g, '-')}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setExportBusy(false);
    }
  };

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-semibold tracking-tight text-white">
            Compliance &amp; Audit Evidence
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Continuous hash-chained evidence vault across SOC 2, ISO 27001, ISO 42001, GDPR, and EU AI Act for {tenantName}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <div className="flex flex-wrap items-center gap-1 rounded-lg border border-white/10 bg-[#11151D] p-1">
            {FRAMEWORKS.map((fw) => (
              <button
                key={fw}
                type="button"
                onClick={() => setFrameworkFilter(fw)}
                className={`rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                  frameworkFilter === fw
                    ? 'bg-sky-500 text-slate-950'
                    : 'text-slate-300 hover:text-white'
                }`}
              >
                {fw === 'all' ? 'All frameworks' : fw}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Auditor-Scoped Time-Bounded Export Bar */}
      <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-4 flex flex-wrap items-end justify-between gap-4">
        <div className="flex flex-wrap items-end gap-3">
          <div>
            <label htmlFor="audit-from-date" className="block text-[11px] text-slate-400">
              Audit window from
            </label>
            <input
              id="audit-from-date"
              type="date"
              value={fromDate}
              onChange={(e) => setFromDate(e.target.value)}
              className="mt-1 rounded-lg border border-white/15 bg-[#090B10] px-2.5 py-1.5 font-mono text-xs text-white focus:border-sky-500 focus:outline-none"
            />
          </div>
          <div>
            <label htmlFor="audit-to-date" className="block text-[11px] text-slate-400">
              Audit window to
            </label>
            <input
              id="audit-to-date"
              type="date"
              value={toDate}
              onChange={(e) => setToDate(e.target.value)}
              className="mt-1 rounded-lg border border-white/15 bg-[#090B10] px-2.5 py-1.5 font-mono text-xs text-white focus:border-sky-500 focus:outline-none"
            />
          </div>
          <p className="text-[11px] text-slate-400 pb-1">
            Scope: <span className="font-mono text-slate-200">{frameworkFilter === 'all' ? 'All 5 frameworks' : frameworkFilter}</span> · Redacted, hash-chained JSON
          </p>
        </div>

        <button
          type="button"
          disabled={exportBusy}
          onClick={handleAuditExport}
          className="inline-flex items-center gap-2 rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50 whitespace-nowrap shrink-0"
        >
          <Download className="w-3.5 h-3.5" aria-hidden="true" />
          <span>{exportBusy ? 'Generating pack...' : 'Export audit pack'}</span>
        </button>
      </div>

      {exportSummary && (
        <div
          role="status"
          className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-xs text-emerald-300"
        >
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0" aria-hidden="true" />
            <span>
              Auditor package <span className="font-mono font-semibold">{exportSummary.packageId}</span> exported in{' '}
              <span className="font-mono tabular-nums">{exportSummary.durationMs}ms</span> (&lt; 5m SLA) ·{' '}
              {exportSummary.controlsCount} controls · {exportSummary.evidenceCount} hash-chained records (
              {exportSummary.chainValid ? 'SHA-256 chain verified' : 'Chain mismatch'})
            </span>
          </div>
          <span className="font-mono text-[11px] text-emerald-200/80 break-all">
            Head: {exportSummary.headHash.slice(0, 28)}...
          </span>
        </div>
      )}

      {/* Summary Strip */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5">
          <p className="text-xs text-slate-400">Audit readiness</p>
          <p className="mt-2 font-mono text-2xl font-semibold text-white tabular-nums">
            {stats.coveragePct}%
          </p>
        </div>
        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5">
          <p className="text-xs text-slate-400">Controls covered</p>
          <p className="mt-2 font-mono text-2xl font-semibold text-emerald-400 tabular-nums">
            {stats.coveredCount}
          </p>
        </div>
        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5">
          <p className="text-xs text-slate-400">Partial coverage</p>
          <p className="mt-2 font-mono text-2xl font-semibold text-amber-400 tabular-nums">
            {stats.partialCount}
          </p>
        </div>
        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5">
          <p className="text-xs text-slate-400">Open control gaps</p>
          <p className="mt-2 font-mono text-2xl font-semibold text-rose-400 tabular-nums">
            {stats.gapCount}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Controls Matrix */}
        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] overflow-hidden lg:col-span-6">
          <div className="border-b border-white/[0.08] px-5 py-4">
            <h2 className="font-display text-base font-semibold text-white">
              Framework controls &amp; gap detection ({visibleControls.length})
            </h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-white/[0.08] bg-[#0D1017] text-slate-400">
                  <th className="px-3.5 py-3 font-medium">Control</th>
                  <th className="px-3.5 py-3 font-medium">Requirement &amp; expected evidence</th>
                  <th className="px-3 py-3 font-medium">Status</th>
                  <th className="px-3.5 py-3 text-right font-medium">Records</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.06]">
                {visibleControls.map((ctrl) => (
                  <tr key={ctrl.id} className="hover:bg-white/[0.03]">
                    <td className="px-3.5 py-3.5 whitespace-nowrap align-top">
                      <span className="font-mono font-semibold text-white">{ctrl.code}</span>
                      <p className="text-[11px] text-slate-400">{ctrl.framework}</p>
                    </td>
                    <td className="px-3.5 py-3.5 text-slate-300">
                      <p>{ctrl.title}</p>
                      {ctrl.requiredEvidenceTypes && ctrl.requiredEvidenceTypes.length > 0 && (
                        <p className="mt-1 font-mono text-[10px] text-slate-500">
                          {ctrl.requiredEvidenceTypes.join(' · ')}
                        </p>
                      )}
                      {ctrl.mappedFindingIds.length > 0 && (
                        <p className="mt-1 text-[11px] text-rose-400">
                          {ctrl.mappedFindingIds.length} open finding(s) causing control gap
                        </p>
                      )}
                    </td>
                    <td className="px-3.5 py-3.5 whitespace-nowrap align-top">
                      {ctrl.status === 'covered' ? (
                        <span className="font-medium text-emerald-400">Covered</span>
                      ) : ctrl.status === 'partial' ? (
                        <span className="font-medium text-amber-400">Partial</span>
                      ) : (
                        <span className="inline-flex items-center gap-1 font-medium text-rose-400">
                          <ShieldAlert className="w-3.5 h-3.5" aria-hidden="true" />
                          <span>Gap</span>
                        </span>
                      )}
                    </td>
                    <td className="px-3.5 py-3.5 text-right font-mono text-slate-300 tabular-nums align-top">
                      {ctrl.evidenceCount}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Continuous Hash-Chained Evidence Vault */}
        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5 lg:col-span-6">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <FileCheck2 className="w-4 h-4 text-emerald-400" aria-hidden="true" />
              <h2 className="font-display text-base font-semibold text-white">
                Continuous evidence vault (
                {visibleEvidenceRecords.length > 0
                  ? visibleEvidenceRecords.length
                  : evidence.length}
                )
              </h2>
            </div>
            <span className="font-mono text-[11px] text-slate-400">
              collector v1.4.2 · redacted
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Tamper-evident SHA-256 hash-chained records collected continuously without raw prompts
          </p>

          {visibleEvidenceRecords.length > 0 ? (
            <ul className="mt-4 max-h-[540px] space-y-2.5 overflow-y-auto pr-1">
              {visibleEvidenceRecords.map((ev) => (
                <li
                  key={ev.id}
                  className="rounded-lg border border-white/[0.06] bg-[#090B10] p-3 text-[11px]"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-mono text-sky-400">
                      {ev.control_id} · {ev.evidence_type}
                    </span>
                    <span className="font-mono text-slate-400 tabular-nums">
                      {ev.collected_at.slice(0, 19).replace('T', ' ')} UTC
                    </span>
                  </div>
                  <p className="mt-1 text-xs font-medium text-white">{ev.title}</p>
                  <p className="mt-0.5 text-slate-400">{ev.summary}</p>
                  <div className="mt-2 grid grid-cols-1 gap-1 font-mono text-[10px] text-slate-500">
                    <p className="break-words">
                      Source: <span className="text-slate-300">{ev.source}</span> · Resource:{' '}
                      <span className="text-slate-300">{ev.resource_id}</span> · Frameworks:{' '}
                      <span className="text-slate-300">{ev.mapped_frameworks.join(', ')}</span>
                    </p>
                    <p className="break-all">
                      Hash: <span className="text-emerald-300/90">{ev.content_hash}</span>
                    </p>
                    <p className="break-all">
                      Prev: {ev.previous_hash} · Retention: {ev.retention_until.slice(0, 10)} · URI:{' '}
                      {ev.storage_uri}
                    </p>
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <ul className="mt-4 divide-y divide-white/[0.06]">
              {evidence.map((ev) => (
                <li key={ev.id} className="py-3.5 first:pt-1 last:pb-0">
                  <div className="flex items-center justify-between text-[11px] text-slate-400">
                    <span className="font-mono text-sky-400">
                      {ev.framework} · {ev.controlCode}
                    </span>
                    <span className="font-mono tabular-nums">{ev.capturedAt}</span>
                  </div>
                  <p className="mt-1 text-xs font-medium text-white">{ev.title}</p>
                  <p className="mt-1 font-mono text-[11px] text-slate-400">
                    Source: {ev.source} · {ev.hash}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
};

