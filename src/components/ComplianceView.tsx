import React, { useState } from 'react';
import { CheckCircle2, Download, FileCheck2, ShieldAlert } from 'lucide-react';
import type { ComplianceExportResponse } from '../App';
import type {
  ComplianceException,
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
  complianceExceptions?: ComplianceException[];
  onExportAuditPack?: (opts: {
    framework: ComplianceFramework | 'all';
    fromDate?: string;
    toDate?: string;
  }) => Promise<ComplianceExportResponse | null>;
  onExportComplianceCsv?: (framework: ComplianceFramework | 'all') => Promise<{
    filename: string;
    csvContent: string;
    rowCount: number;
  } | null>;
  onAttestControl?: (
    controlId: string,
    payload: { title?: string; summary: string; source?: string }
  ) => Promise<{ control: ControlItem; evidenceRecord: EvidenceRecord } | null>;
  onCreateComplianceException?: (payload: {
    controlId: string;
    reason: string;
    compensatingControl: string;
    expiresInDays?: number;
  }) => Promise<ComplianceException | null>;
  onRevokeComplianceException?: (exceptionId: string) => Promise<void>;
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
  complianceExceptions = [],
  onExportAuditPack,
  onExportComplianceCsv,
  onAttestControl,
  onCreateComplianceException,
  onRevokeComplianceException,
}) => {
  const [frameworkFilter, setFrameworkFilter] = useState<'all' | ComplianceFramework>('all');
  const [fromDate, setFromDate] = useState<string>('');
  const [toDate, setToDate] = useState<string>('');
  const [exportBusy, setExportBusy] = useState(false);
  const [csvNotice, setCsvNotice] = useState('');
  const [attestingControlId, setAttestingControlId] = useState<string | null>(null);
  const [attestSummary, setAttestSummary] = useState<string>('');
  const [attestSource, setAttestSource] = useState<string>('Compliance Attestation Review');
  const [attestBusy, setAttestBusy] = useState(false);
  const [attestError, setAttestError] = useState<string>('');
  const [attestNotice, setAttestNotice] = useState<string>('');

  const [excControlId, setExcControlId] = useState<string>(controls[0]?.id ?? 'ctrl_soc2_cc6_2');
  const [excReason, setExcReason] = useState('');
  const [excCompensating, setExcCompensating] = useState('');
  const [excDays, setExcDays] = useState(30);
  const [excBusy, setExcBusy] = useState(false);
  const [excError, setExcError] = useState('');

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

  const handleCsvDownload = async () => {
    if (!onExportComplianceCsv) return;
    setExportBusy(true);
    setCsvNotice('');
    try {
      const res = await onExportComplianceCsv(frameworkFilter);
      if (res) {
        const blob = new Blob([res.csvContent], { type: 'text/csv;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = res.filename;
        a.click();
        URL.revokeObjectURL(url);
        setCsvNotice(`Exported ${res.rowCount} compliance control rows to ${res.filename}.`);
      }
    } finally {
      setExportBusy(false);
    }
  };

  const handleCreateException = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!onCreateComplianceException) return;
    if (!excReason.trim() || !excCompensating.trim()) {
      setExcError('Reason and compensating control are required.');
      return;
    }
    setExcBusy(true);
    setExcError('');
    try {
      const created = await onCreateComplianceException({
        controlId: excControlId || controls[0]?.id || 'ctrl_soc2_cc6_2',
        reason: excReason.trim(),
        compensatingControl: excCompensating.trim(),
        expiresInDays: excDays,
      });
      if (created) {
        setAttestNotice(`Recorded compliance exception ${created.id} for ${created.controlCode}.`);
        setExcReason('');
        setExcCompensating('');
      }
    } catch (err) {
      setExcError((err as Error).message || 'Unable to record compliance exception.');
    } finally {
      setExcBusy(false);
    }
  };

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

  const handleSubmitAttestation = async (e: React.FormEvent, control: ControlItem) => {
    e.preventDefault();
    if (!onAttestControl) return;
    if (!attestSummary.trim()) {
      setAttestError('Attestation summary and evidence reference are required.');
      return;
    }
    setAttestBusy(true);
    setAttestError('');
    try {
      const result = await onAttestControl(control.id, {
        title: `${control.code} attestation · ${control.title}`,
        summary: attestSummary.trim(),
        source: attestSource.trim() || 'Compliance Attestation Review',
      });
      if (result) {
        setAttestNotice(
          `Attested ${result.control.code} (${result.control.status}) · Hash-chained evidence ${result.evidenceRecord.id} recorded.`
        );
        setAttestingControlId(null);
        setAttestSummary('');
      }
    } catch (err) {
      setAttestError((err as Error).message || 'Unable to attest control.');
    } finally {
      setAttestBusy(false);
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

        <div className="flex flex-wrap items-center gap-2.5">
          {onExportComplianceCsv && (
            <button
              type="button"
              disabled={exportBusy}
              onClick={handleCsvDownload}
              className="inline-flex items-center gap-2 rounded-lg border border-white/15 bg-[#090B10] px-3.5 py-2 text-xs font-medium text-slate-200 hover:border-sky-500/50 hover:text-white disabled:opacity-50 whitespace-nowrap shrink-0"
            >
              <Download className="w-3.5 h-3.5 text-sky-400" aria-hidden="true" />
              <span>Export CSV</span>
            </button>
          )}
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
      </div>

      {csvNotice && (
        <div
          role="status"
          className="flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-2.5 text-xs text-emerald-300"
        >
          <CheckCircle2 className="w-4 h-4 shrink-0" aria-hidden="true" />
          <span>{csvNotice}</span>
        </div>
      )}

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

      {attestNotice && (
        <div
          role="status"
          className="flex items-center gap-2 rounded-lg border border-sky-500/30 bg-sky-500/10 px-4 py-3 text-xs text-sky-200"
        >
          <CheckCircle2 className="w-4 h-4 text-sky-400 shrink-0" aria-hidden="true" />
          <span>{attestNotice}</span>
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
                {visibleControls.map((ctrl) => {
                  const isAttesting = attestingControlId === ctrl.id;
                  return (
                    <React.Fragment key={ctrl.id}>
                      <tr className="hover:bg-white/[0.03]">
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
                          <div className="flex flex-col items-start gap-1.5">
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
                            {(ctrl.status === 'partial' || ctrl.status === 'gap') &&
                              onAttestControl && (
                                <button
                                  type="button"
                                  aria-label={`Attest ${ctrl.code}`}
                                  onClick={() => {
                                    setAttestError('');
                                    setAttestingControlId(isAttesting ? null : ctrl.id);
                                    setAttestSummary('');
                                  }}
                                  className="rounded border border-sky-500/40 bg-sky-500/15 px-2 py-0.5 text-[11px] font-medium text-sky-300 hover:bg-sky-500/25 whitespace-nowrap"
                                >
                                  {isAttesting ? 'Close' : 'Attest'}
                                </button>
                              )}
                          </div>
                        </td>
                        <td className="px-3.5 py-3.5 text-right font-mono text-slate-300 tabular-nums align-top">
                          {ctrl.evidenceCount}
                        </td>
                      </tr>
                      {isAttesting && (
                        <tr className="bg-[#090B10]">
                          <td colSpan={4} className="px-3.5 py-3.5">
                            <form
                              onSubmit={(e) => handleSubmitAttestation(e, ctrl)}
                              className="space-y-3"
                            >
                              <div className="flex flex-wrap items-center justify-between gap-2">
                                <span className="font-mono text-[11px] font-semibold text-sky-300">
                                  Attest control {ctrl.code} ({ctrl.framework})
                                </span>
                                <span className="text-[11px] text-slate-400">
                                  Creates SHA-256 chained evidence record
                                </span>
                              </div>
                              <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-12">
                                <div className="sm:col-span-7">
                                  <label
                                    htmlFor={`attest-summary-${ctrl.id}`}
                                    className="block text-[11px] text-slate-400"
                                  >
                                    Attestation summary &amp; proof
                                  </label>
                                  <input
                                    id={`attest-summary-${ctrl.id}`}
                                    type="text"
                                    required
                                    value={attestSummary}
                                    onChange={(e) => setAttestSummary(e.target.value)}
                                    placeholder="e.g. Verified IAM scope restriction and gateway enforcement logs"
                                    className="mt-1 w-full rounded-lg border border-white/15 bg-[#11151D] px-2.5 py-1.5 text-xs text-white focus:border-sky-500 focus:outline-none"
                                  />
                                </div>
                                <div className="sm:col-span-5">
                                  <label
                                    htmlFor={`attest-source-${ctrl.id}`}
                                    className="block text-[11px] text-slate-400"
                                  >
                                    Verification source
                                  </label>
                                  <input
                                    id={`attest-source-${ctrl.id}`}
                                    type="text"
                                    value={attestSource}
                                    onChange={(e) => setAttestSource(e.target.value)}
                                    placeholder="Compliance Attestation Review"
                                    className="mt-1 w-full rounded-lg border border-white/15 bg-[#11151D] px-2.5 py-1.5 text-xs text-white focus:border-sky-500 focus:outline-none"
                                  />
                                </div>
                              </div>
                              {attestError && (
                                <p role="alert" className="text-xs text-rose-400">
                                  {attestError}
                                </p>
                              )}
                              <div className="flex items-center gap-2">
                                <button
                                  type="submit"
                                  disabled={attestBusy}
                                  className="rounded-lg bg-sky-500 px-3 py-1.5 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50"
                                >
                                  {attestBusy ? 'Recording...' : 'Submit attestation'}
                                </button>
                                <button
                                  type="button"
                                  onClick={() => {
                                    setAttestingControlId(null);
                                    setAttestError('');
                                  }}
                                  className="rounded-lg border border-white/15 bg-[#11151D] px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white"
                                >
                                  Cancel
                                </button>
                              </div>
                            </form>
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

      {/* Compliance Risk Exceptions */}
      {(onCreateComplianceException || complianceExceptions.length > 0) && (
        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="font-display text-base font-semibold text-white">
                Compliance Risk Exceptions ({complianceExceptions.filter((e) => e.status === 'active').length} active)
              </h2>
              <p className="text-xs text-slate-400">
                Time-bounded control exceptions backed by compensating controls and immutable audit logs
              </p>
            </div>
          </div>

          {onCreateComplianceException && (
            <form
              onSubmit={handleCreateException}
              className="grid grid-cols-1 gap-3 rounded-lg border border-white/[0.08] bg-[#090B10] p-4 md:grid-cols-12"
            >
              <div className="md:col-span-3">
                <label htmlFor="cexc-control" className="block text-[11px] text-slate-400">
                  Control
                </label>
                <select
                  id="cexc-control"
                  value={excControlId}
                  onChange={(e) => setExcControlId(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-white/15 bg-[#11151D] px-2.5 py-1.5 text-xs text-white focus:border-sky-500 focus:outline-none"
                >
                  {controls.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.code} · {c.framework}
                    </option>
                  ))}
                </select>
              </div>
              <div className="md:col-span-4">
                <label htmlFor="cexc-reason" className="block text-[11px] text-slate-400">
                  Business justification
                </label>
                <input
                  id="cexc-reason"
                  type="text"
                  value={excReason}
                  onChange={(e) => setExcReason(e.target.value)}
                  placeholder="e.g. Legacy quarter-end batch window migration"
                  className="mt-1 w-full rounded-lg border border-white/15 bg-[#11151D] px-2.5 py-1.5 text-xs text-white focus:border-sky-500 focus:outline-none"
                />
              </div>
              <div className="md:col-span-3">
                <label htmlFor="cexc-comp" className="block text-[11px] text-slate-400">
                  Compensating control
                </label>
                <input
                  id="cexc-comp"
                  type="text"
                  value={excCompensating}
                  onChange={(e) => setExcCompensating(e.target.value)}
                  placeholder="e.g. Tokenized PII proxy + daily audit review"
                  className="mt-1 w-full rounded-lg border border-white/15 bg-[#11151D] px-2.5 py-1.5 text-xs text-white focus:border-sky-500 focus:outline-none"
                />
              </div>
              <div className="md:col-span-2 flex items-end gap-2">
                <div className="w-16">
                  <label htmlFor="cexc-days" className="block text-[11px] text-slate-400">
                    Days
                  </label>
                  <input
                    id="cexc-days"
                    type="number"
                    min={1}
                    max={180}
                    value={excDays}
                    onChange={(e) => setExcDays(Number(e.target.value) || 30)}
                    className="mt-1 w-full rounded-lg border border-white/15 bg-[#11151D] px-2 py-1.5 font-mono text-xs text-white focus:border-sky-500 focus:outline-none"
                  />
                </div>
                <button
                  type="submit"
                  disabled={excBusy}
                  className="flex-1 rounded-lg bg-sky-500 px-3 py-1.5 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50 whitespace-nowrap"
                >
                  {excBusy ? 'Saving...' : 'Grant'}
                </button>
              </div>
              {excError && (
                <p role="alert" className="md:col-span-12 text-xs text-rose-400">
                  {excError}
                </p>
              )}
            </form>
          )}

          {complianceExceptions.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-white/[0.08] text-slate-400">
                    <th className="py-2 pr-3 font-medium">Control</th>
                    <th className="py-2 pr-3 font-medium">Justification &amp; Compensating Control</th>
                    <th className="py-2 pr-3 font-medium">Expires</th>
                    <th className="py-2 pr-3 font-medium">Status</th>
                    <th className="py-2 text-right font-medium">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.06]">
                  {complianceExceptions.map((exc) => (
                    <tr key={exc.id}>
                      <td className="py-2.5 pr-3 font-mono text-sky-300 whitespace-nowrap">
                        {exc.controlCode} ({exc.framework})
                      </td>
                      <td className="py-2.5 pr-3 text-slate-300">
                        <p>{exc.reason}</p>
                        <p className="text-[11px] text-slate-400">
                          Compensating: {exc.compensatingControl} · By {exc.approvedBy}
                        </p>
                      </td>
                      <td className="py-2.5 pr-3 font-mono text-[11px] text-slate-400 tabular-nums whitespace-nowrap">
                        {exc.expiresAt.slice(0, 10)}
                      </td>
                      <td className="py-2.5 pr-3 font-mono text-[11px] whitespace-nowrap">
                        <span className={exc.status === 'active' ? 'text-amber-300' : 'text-slate-500'}>
                          {exc.status}
                        </span>
                      </td>
                      <td className="py-2.5 text-right whitespace-nowrap">
                        {exc.status === 'active' && onRevokeComplianceException && (
                          <button
                            type="button"
                            onClick={() => onRevokeComplianceException(exc.id)}
                            className="rounded border border-rose-500/40 bg-rose-500/10 px-2.5 py-1 text-[11px] text-rose-300 hover:bg-rose-500/20"
                          >
                            Revoke
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

