import React, { useState } from 'react';
import {
  CheckCircle2,
  ExternalLink,
  FileCheck2,
  GitCompare,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Ticket,
} from 'lucide-react';
import type {
  Agent,
  ContainmentActionCatalogItem,
  ContainmentActionId,
  Finding,
  FindingStatus,
  RiskFactorInputs,
  RiskLevel,
  SecurityIncident,
} from '../types/security';
import { FindingStatusLabel, RiskLabel } from './RiskIndicator';

interface FindingsViewProps {
  tenantId: string;
  findings: Finding[];
  agents?: Agent[];
  incidents?: SecurityIncident[];
  containmentCatalog?: ContainmentActionCatalogItem[];
  onCreateRemediationTicket: (
    findingId: string,
    payload: { provider: 'jira' | 'servicenow'; assignee: string; notifyChannels: string[] }
  ) => Promise<void>;
  onTicketAllOpenFindings?: (
    provider: 'jira' | 'servicenow'
  ) => Promise<{ createdCount: number } | null>;
  onRunDryRun: (findingId: string) => Promise<void>;
  onApproveRemediation: (findingId: string, breakGlassDualApproval: boolean) => Promise<void>;
  onApplyRemediation: (findingId: string) => Promise<void>;
  onRollbackRemediation: (findingId: string) => Promise<void>;
  onVerifyAndClose: (findingId: string) => Promise<{ closed: boolean; message?: string }>;
  onRecalculateAgentRisk?: (
    agentId: string,
    payload: {
      owner?: string;
      permissions?: string[];
      dailyCalls?: number;
      overrides?: Partial<RiskFactorInputs>;
    }
  ) => Promise<void>;
  onContainIncident?: (
    incidentId: string,
    payload: { action: ContainmentActionId; approve: boolean; dryRun: boolean }
  ) => Promise<{ incident: SecurityIncident; dryRunDiff?: string } | null>;
}

export const FindingsView: React.FC<FindingsViewProps> = ({
  tenantId,
  findings,
  agents = [],
  incidents = [],
  containmentCatalog = [],
  onCreateRemediationTicket,
  onTicketAllOpenFindings,
  onRunDryRun,
  onApproveRemediation,
  onApplyRemediation,
  onRollbackRemediation,
  onVerifyAndClose,
  onRecalculateAgentRisk,
  onContainIncident,
}) => {
  const tenantFindings = findings.filter((f) => f.tenantId === tenantId);
  const tenantIncidents = incidents.filter((i) => i.tenantId === tenantId);
  const [activeTab, setActiveTab] = useState<'findings' | 'incidents'>('findings');
  const [severityFilter, setSeverityFilter] = useState<RiskLevel | 'all'>('all');
  const [statusFilter, setStatusFilter] = useState<FindingStatus | 'all'>('all');
  const [selectedFindingId, setSelectedFindingId] = useState<string>(
    tenantFindings[0]?.id ?? ''
  );
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>(
    tenantIncidents[0]?.id ?? ''
  );
  const [selectedContainmentAction, setSelectedContainmentAction] =
    useState<ContainmentActionId>('restrict_data_access');
  const [containmentApproved, setContainmentApproved] = useState(false);
  const [containmentBusy, setContainmentBusy] = useState(false);
  const [containmentFeedback, setContainmentFeedback] = useState<{
    kind: 'info' | 'error' | 'success';
    text: string;
  } | null>(null);

  const [ticketProvider, setTicketProvider] = useState<'jira' | 'servicenow'>('jira');
  const [ticketAssignee, setTicketAssignee] = useState('Cloud Security');
  const [notifySlack, setNotifySlack] = useState(true);
  const [notifyTeams, setNotifyTeams] = useState(false);
  const [showTicketPreview, setShowTicketPreview] = useState(false);
  const [breakGlass, setBreakGlass] = useState(false);
  const [workflowFeedback, setWorkflowFeedback] = useState<{
    kind: 'info' | 'error' | 'success';
    text: string;
  } | null>(null);

  const filtered = tenantFindings.filter((f) => {
    if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
    if (statusFilter !== 'all' && f.status !== statusFilter) return false;
    return true;
  });

  const activeFinding =
    tenantFindings.find((f) => f.id === selectedFindingId) ?? filtered[0] ?? tenantFindings[0];
  const activeIncident =
    tenantIncidents.find((i) => i.id === selectedIncidentId) ?? tenantIncidents[0];

  const activeAgent = activeFinding
    ? agents.find((a) => a.id === activeFinding.agentId)
    : undefined;
  const activeAssessment = activeAgent?.riskAssessment ?? activeFinding?.riskAssessment;

  const [recalcBusy, setRecalcBusy] = useState(false);

  const handleRunContainment = async (dryRun: boolean) => {
    if (!activeIncident || !onContainIncident) return;
    setContainmentBusy(true);
    setContainmentFeedback(null);
    try {
      const res = await onContainIncident(activeIncident.id, {
        action: selectedContainmentAction,
        approve: containmentApproved,
        dryRun,
      });
      if (res) {
        setContainmentFeedback({
          kind: dryRun ? 'info' : 'success',
          text: dryRun
            ? res.dryRunDiff || `Dry-run impact previewed for ${selectedContainmentAction}.`
            : `Executed containment action ${selectedContainmentAction} on ${activeIncident.agentName}.`,
        });
      }
    } catch (err) {
      setContainmentFeedback({
        kind: 'error',
        text: (err as Error).message || 'Containment action blocked.',
      });
    } finally {
      setContainmentBusy(false);
    }
  };

  const handleRecalculateSignal = async (
    label: string,
    payload: {
      owner?: string;
      permissions?: string[];
      dailyCalls?: number;
      overrides?: Partial<RiskFactorInputs>;
    }
  ) => {
    if (!activeFinding || !onRecalculateAgentRisk) return;
    setRecalcBusy(true);
    setWorkflowFeedback(null);
    try {
      await onRecalculateAgentRisk(activeFinding.agentId, payload);
      setWorkflowFeedback({
        kind: 'info',
        text: `Risk engine recalculated weighted score (${label}).`,
      });
    } finally {
      setRecalcBusy(false);
    }
  };

  const handleDispatchTicket = async () => {
    if (!activeFinding) return;
    setWorkflowFeedback(null);
    const channels: string[] = ['Email'];
    if (notifySlack) channels.unshift('Slack');
    if (notifyTeams) channels.push('Microsoft Teams');
    await onCreateRemediationTicket(activeFinding.id, {
      provider: ticketProvider,
      assignee: ticketAssignee,
      notifyChannels: channels,
    });
    setShowTicketPreview(true);
    setWorkflowFeedback({
      kind: 'success',
      text: `${ticketProvider === 'servicenow' ? 'ServiceNow' : 'Jira'} ticket created and owner notified via ${channels.join(', ')}.`,
    });
  };

  const handleVerifyClosure = async () => {
    if (!activeFinding) return;
    setWorkflowFeedback(null);
    const result = await onVerifyAndClose(activeFinding.id);
    if (!result.closed) {
      setWorkflowFeedback({
        kind: 'error',
        text:
          result.message ||
          'Cannot close finding: Exposure path still detected in security graph after re-sync.',
      });
    } else {
      setWorkflowFeedback({
        kind: 'success',
        text: result.message || 'Re-sync confirmed exposure path removed. Finding verified and closed.',
      });
    }
  };

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-semibold tracking-tight text-white">
            Risk Findings, Incidents &amp; Containment
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Evidence-backed findings, correlated security incidents, 8 containment actions, dry-runs, and sync verification
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div
            role="tablist"
            aria-label="Findings and incidents view"
            className="flex items-center gap-1 rounded-lg border border-white/15 bg-[#11151D] p-1"
          >
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'findings'}
              onClick={() => setActiveTab('findings')}
              className={`rounded-md px-3 py-1.5 text-xs font-semibold transition-colors whitespace-nowrap ${
                activeTab === 'findings'
                  ? 'bg-sky-500 text-slate-950'
                  : 'text-slate-300 hover:text-white'
              }`}
            >
              Findings ({tenantFindings.length})
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'incidents'}
              onClick={() => setActiveTab('incidents')}
              className={`rounded-md px-3 py-1.5 text-xs font-semibold transition-colors whitespace-nowrap ${
                activeTab === 'incidents'
                  ? 'bg-sky-500 text-slate-950'
                  : 'text-slate-300 hover:text-white'
              }`}
            >
              Correlated Incidents ({tenantIncidents.length})
            </button>
          </div>

          {activeTab === 'findings' && (
            <>
              <select
                aria-label="Filter findings by severity"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value as RiskLevel | 'all')}
                className="rounded-lg border border-white/15 bg-[#11151D] px-3 py-2 text-xs text-white focus:border-sky-500 focus:outline-none"
              >
                <option value="all">All severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="informational">Informational</option>
              </select>

              <select
                aria-label="Filter findings by status"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value as FindingStatus | 'all')}
                className="rounded-lg border border-white/15 bg-[#11151D] px-3 py-2 text-xs text-white focus:border-sky-500 focus:outline-none"
              >
                <option value="all">All statuses</option>
                <option value="open">Open</option>
                <option value="in_progress">In progress</option>
                <option value="remediated">Remediated</option>
              </select>

              {onTicketAllOpenFindings && (
                <button
                  type="button"
                  onClick={async () => {
                    const res = await onTicketAllOpenFindings(ticketProvider);
                    if (res) {
                      setWorkflowFeedback({
                        kind: 'success',
                        text:
                          res.createdCount > 0
                            ? `Created ${res.createdCount} ${ticketProvider === 'servicenow' ? 'ServiceNow' : 'Jira'} ticket(s) for all open unticketed findings.`
                            : 'All open findings already hold active remediation tickets.',
                      });
                    }
                  }}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-white/15 bg-[#11151D] px-3.5 py-2 text-xs font-medium text-white hover:border-sky-500/50 whitespace-nowrap"
                >
                  <Ticket className="w-3.5 h-3.5 text-sky-400" aria-hidden="true" />
                  <span>Ticket all open</span>
                </button>
              )}
            </>
          )}
        </div>
      </div>

      {activeTab === 'incidents' ? (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          <div className="rounded-xl border border-white/[0.08] bg-[#11151D] overflow-hidden lg:col-span-5">
            <div className="border-b border-white/[0.08] px-4 py-3">
              <h2 className="font-display text-sm font-semibold text-white">
                Correlated Security Incidents ({tenantIncidents.length})
              </h2>
            </div>
            {tenantIncidents.length === 0 ? (
              <p className="p-6 text-xs text-slate-400">No correlated security incidents for this tenant.</p>
            ) : (
              <ul className="divide-y divide-white/[0.06]">
                {tenantIncidents.map((inc) => {
                  const isSel = activeIncident?.id === inc.id;
                  return (
                    <li key={inc.id} className={isSel ? 'bg-sky-500/10' : 'hover:bg-white/[0.03]'}>
                      <button
                        type="button"
                        onClick={() => {
                          setSelectedIncidentId(inc.id);
                          setContainmentFeedback(null);
                        }}
                        className="w-full px-4 py-3.5 text-left"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <RiskLabel level={inc.severity} />
                          <span className="font-mono text-[11px] uppercase text-sky-300">
                            {inc.status}
                          </span>
                        </div>
                        <p className="mt-1.5 text-xs font-semibold text-white">{inc.title}</p>
                        <p className="mt-0.5 text-[11px] text-slate-400">
                          {inc.agentName} · {inc.signalSummary}
                        </p>
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>

          <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5 lg:col-span-7 space-y-4">
            {activeIncident ? (
              <>
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <RiskLabel level={activeIncident.severity} />
                      <span className="font-mono text-xs uppercase text-sky-300">
                        {activeIncident.status}
                      </span>
                    </div>
                    <h2 className="mt-2 font-display text-lg font-semibold text-white">
                      {activeIncident.title}
                    </h2>
                    <p className="mt-1 text-xs text-slate-400">{activeIncident.signalSummary}</p>
                  </div>
                </div>

                {containmentFeedback && (
                  <div
                    role={containmentFeedback.kind === 'error' ? 'alert' : 'status'}
                    className={`rounded-lg border px-3.5 py-2.5 text-xs ${
                      containmentFeedback.kind === 'error'
                        ? 'border-rose-500/40 bg-rose-500/10 text-rose-300'
                        : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'
                    }`}
                  >
                    {containmentFeedback.text}
                  </div>
                )}

                <div className="border-t border-white/[0.08] pt-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <p className="text-xs font-semibold text-white">
                      8-Action Approval-Gated Containment Workbench
                    </p>
                    <span className="font-mono text-[11px] text-slate-400">
                      Target: {activeIncident.agentName}
                    </span>
                  </div>

                  <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                    {containmentCatalog.map((item) => {
                      const active = selectedContainmentAction === item.id;
                      return (
                        <button
                          key={item.id}
                          type="button"
                          onClick={() => setSelectedContainmentAction(item.id)}
                          className={`rounded-lg border p-3 text-left transition-colors ${
                            active
                              ? 'border-sky-400 bg-sky-500/10'
                              : 'border-white/[0.08] bg-[#090B10] hover:border-white/20'
                          }`}
                        >
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-xs font-semibold text-white">{item.label}</span>
                            <span className="font-mono text-[10px] text-slate-400">
                              {item.targetType}
                            </span>
                          </div>
                          <p className="mt-1 text-[11px] text-slate-400">{item.description}</p>
                        </button>
                      );
                    })}
                  </div>

                  {onContainIncident && (
                    <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-white/[0.08] bg-[#090B10] p-3">
                      <label className="inline-flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={containmentApproved}
                          onChange={(e) => setContainmentApproved(e.target.checked)}
                          className="rounded border-white/20 bg-[#11151D]"
                        />
                        <span>Explicit human approval confirmed (required for execution)</span>
                      </label>

                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          disabled={containmentBusy}
                          onClick={() => handleRunContainment(true)}
                          className="rounded-lg border border-white/15 bg-[#11151D] px-3 py-1.5 text-xs font-medium text-slate-200 hover:text-white disabled:opacity-50"
                        >
                          Dry-run impact
                        </button>
                        <button
                          type="button"
                          disabled={containmentBusy}
                          onClick={() => handleRunContainment(false)}
                          className="rounded-lg bg-rose-500 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-rose-400 disabled:opacity-50"
                        >
                          {containmentBusy ? 'Executing...' : 'Execute containment'}
                        </button>
                      </div>
                    </div>
                  )}
                </div>

                {activeIncident.executedActions.length > 0 && (
                  <div className="border-t border-white/[0.08] pt-4">
                    <p className="text-xs font-semibold text-slate-300">
                      Containment execution &amp; evidence log ({activeIncident.executedActions.length})
                    </p>
                    <ul className="mt-2 space-y-2">
                      {activeIncident.executedActions.map((act, idx) => (
                        <li
                          key={`${act.executedAt}-${idx}`}
                          className="rounded-lg border border-white/[0.06] bg-[#090B10] px-3 py-2 text-[11px]"
                        >
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-mono text-sky-300">
                              {act.label} {act.dryRun ? '(dry-run)' : '(executed)'}
                            </span>
                            <span className="font-mono text-slate-500">
                              by {act.executedBy} · ev={act.evidenceId}
                            </span>
                          </div>
                          <p className="mt-0.5 text-slate-300">{act.summary}</p>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </>
            ) : (
              <p className="text-xs text-slate-400">Select an incident to inspect containment options.</p>
            )}
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Findings Table */}
        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] overflow-hidden lg:col-span-6">
          {filtered.length === 0 ? (
            <div className="p-10 text-center">
              <p className="text-sm font-medium text-white">No findings match these filters</p>
              <button
                type="button"
                onClick={() => {
                  setSeverityFilter('all');
                  setStatusFilter('all');
                }}
                className="mt-3 rounded-lg bg-sky-500 px-3.5 py-2 text-xs font-semibold text-slate-950"
              >
                Reset filters
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-white/[0.08] bg-[#0D1017] text-slate-400">
                    <th className="px-3 py-3 font-medium">Finding</th>
                    <th className="px-2.5 py-3 font-medium">Severity</th>
                    <th className="px-2.5 py-3 font-medium">Owner</th>
                    <th className="px-2.5 py-3 font-medium">SLA</th>
                    <th className="px-3 py-3 font-medium">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.06]">
                  {filtered.map((f) => {
                    const isSelected = activeFinding?.id === f.id;
                    return (
                      <tr
                        key={f.id}
                        className={`transition-colors ${
                          isSelected ? 'bg-sky-500/10' : 'hover:bg-white/[0.03]'
                        }`}
                      >
                        <td className="px-3 py-3.5 min-w-[150px]">
                          <button
                            type="button"
                            onClick={() => {
                              setSelectedFindingId(f.id);
                              setWorkflowFeedback(null);
                            }}
                            className="font-medium text-white hover:text-sky-400 text-left leading-snug"
                          >
                            {f.title}
                          </button>
                          <p className="mt-0.5 text-[11px] text-slate-400 break-words">
                            {f.agentName}
                            {f.jiraTicketKey ? ` · ${f.jiraTicketKey}` : ''}
                            {f.ruleId ? ` · ${f.ruleId}` : ''}
                          </p>
                        </td>
                        <td className="px-2.5 py-3.5 whitespace-nowrap">
                          <RiskLabel level={f.severity} />
                        </td>
                        <td className="px-2.5 py-3.5 text-slate-300">
                          {f.owner}
                        </td>
                        <td className="px-2.5 py-3.5 font-mono text-slate-300 tabular-nums whitespace-nowrap">
                          {f.status === 'remediated' ? 'Closed' : `${f.slaRemainingDays}d left`}
                        </td>
                        <td className="px-3 py-3.5 whitespace-nowrap">
                          <FindingStatusLabel status={f.status} />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Evidence, Ticket & Approval-Gated Remediation Panel */}
        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5 lg:col-span-6">
          {activeFinding ? (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2 text-xs">
                  <RiskLabel level={activeFinding.severity} />
                  {activeFinding.riskScore && (
                    <span className="font-mono text-slate-400 tabular-nums">
                      Score {activeFinding.riskScore}
                    </span>
                  )}
                </div>
                <FindingStatusLabel status={activeFinding.status} />
              </div>

              <div>
                <h2 className="font-display text-lg font-semibold text-white">
                  {activeFinding.title}
                </h2>
                <p className="mt-1 text-xs text-slate-400">
                  {activeFinding.agentName} · Rule {activeFinding.ruleId ?? 'RULE_SENSITIVE_DATA_REACH'} ·{' '}
                  {activeFinding.frameworks.join(', ')}
                </p>
              </div>

              {workflowFeedback && (
                <div
                  role={workflowFeedback.kind === 'error' ? 'alert' : 'status'}
                  className={`rounded-lg border px-3.5 py-2.5 text-xs ${
                    workflowFeedback.kind === 'error'
                      ? 'border-rose-500/40 bg-rose-500/10 text-rose-300'
                      : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'
                  }`}
                >
                  {workflowFeedback.text}
                </div>
              )}

              {/* Exposure Path & Root Cause */}
              <div className="border-t border-white/[0.08] pt-4 space-y-2.5">
                {activeFinding.exposurePath && activeFinding.exposurePath.length > 0 && (
                  <div>
                    <p className="text-xs font-medium text-sky-400">Exposure path</p>
                    <p className="mt-1 font-mono text-[11px] leading-relaxed text-slate-200">
                      {activeFinding.exposurePath.join(' → ')}
                    </p>
                  </div>
                )}
                <div>
                  <p className="text-xs font-medium text-slate-300">Technical root cause &amp; impact</p>
                  <p className="mt-1 text-xs leading-relaxed text-slate-400">
                    {activeFinding.description} {activeFinding.businessImpact}
                  </p>
                </div>
              </div>

              {/* 6-Factor Weighted Risk Engine & Exposure-Path Scoring */}
              {activeAssessment && (
                <div className="border-t border-white/[0.08] pt-4 space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <p className="text-xs font-medium text-white">
                        6-Factor Weighted Risk Assessment
                      </p>
                      <p className="text-[11px] text-slate-400">
                        Action: <span className="text-sky-300 font-medium">{activeAssessment.actionRequired}</span>
                        {activeAssessment.recommendedSlaDays > 0
                          ? ` (${activeAssessment.recommendedSlaDays}d SLA)`
                          : ''}
                      </p>
                    </div>
                    <div className="text-right font-mono tabular-nums">
                      <span className="text-base font-semibold text-white">
                        {activeAssessment.totalScore}
                      </span>
                      <span className="text-[11px] text-slate-400"> / 100</span>
                    </div>
                  </div>

                  <div className="overflow-x-auto rounded-lg border border-white/[0.06] bg-[#090B10]">
                    <table className="w-full text-left text-[11px]">
                      <thead>
                        <tr className="border-b border-white/[0.06] text-slate-400">
                          <th className="px-3 py-2 font-medium">Factor</th>
                          <th className="px-2 py-2 text-right font-medium">Signal</th>
                          <th className="px-2 py-2 text-right font-medium">Weight</th>
                          <th className="px-3 py-2 text-right font-medium">Points</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-white/[0.05]">
                        {activeAssessment.factors.map((factor) => (
                          <tr key={factor.key}>
                            <td className="px-3 py-1.5">
                              <p className="font-medium text-slate-200">{factor.label}</p>
                              <p className="text-[10px] text-slate-500">{factor.signalSummary}</p>
                            </td>
                            <td className="px-2 py-1.5 text-right font-mono text-slate-300 tabular-nums">
                              {factor.normalizedScore}
                            </td>
                            <td className="px-2 py-1.5 text-right font-mono text-slate-400 tabular-nums">
                              × {factor.weight.toFixed(2)}
                            </td>
                            <td className="px-3 py-1.5 text-right font-mono font-semibold text-sky-300 tabular-nums">
                              {factor.weightedPoints.toFixed(1)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  {onRecalculateAgentRisk && (
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[11px] text-slate-400">Recalculate signals:</span>
                      <button
                        type="button"
                        disabled={recalcBusy}
                        onClick={() =>
                          handleRecalculateSignal('Owner assigned: governance gap reduced', {
                            owner: 'm.chen@northwind.com',
                            overrides: { governanceGap: 10 },
                          })
                        }
                        className="rounded border border-white/15 bg-[#090B10] px-2.5 py-1 text-[11px] text-slate-200 hover:border-sky-500/50 hover:text-white disabled:opacity-50 whitespace-nowrap"
                      >
                        Assign owner
                      </button>
                      <button
                        type="button"
                        disabled={recalcBusy}
                        onClick={() =>
                          handleRecalculateSignal('Permissions scoped to read-only', {
                            permissions: ['s3:GetObject (scoped)', 'read_records'],
                            overrides: { identityPrivilege: 35, agentAutonomy: 40 },
                          })
                        }
                        className="rounded border border-white/15 bg-[#090B10] px-2.5 py-1 text-[11px] text-slate-200 hover:border-sky-500/50 hover:text-white disabled:opacity-50 whitespace-nowrap"
                      >
                        Scope permissions
                      </button>
                      <button
                        type="button"
                        disabled={recalcBusy}
                        onClick={() =>
                          handleRecalculateSignal('Anomalous high-volume activity spike', {
                            dailyCalls: 12500,
                            overrides: { activity: 95 },
                          })
                        }
                        className="rounded border border-white/15 bg-[#090B10] px-2.5 py-1 text-[11px] text-slate-200 hover:border-sky-500/50 hover:text-white disabled:opacity-50 whitespace-nowrap"
                      >
                        Spike activity
                      </button>
                    </div>
                  )}

                  {activeAssessment.exposureSummary && (
                    <div className="rounded-lg border border-white/[0.06] bg-[#090B10] p-3 space-y-2">
                      <p className="text-[11px] font-medium text-sky-400">
                        Exposure-path scoring (6 questions)
                      </p>
                      <dl className="grid grid-cols-1 gap-2 sm:grid-cols-2 text-[11px]">
                        <div>
                          <dt className="text-slate-500">Agent</dt>
                          <dd className="font-mono text-slate-200">{activeAssessment.exposureSummary.agent}</dd>
                        </div>
                        <div>
                          <dt className="text-slate-500">Identity</dt>
                          <dd className="font-mono text-slate-200">{activeAssessment.exposureSummary.identity}</dd>
                        </div>
                        <div>
                          <dt className="text-slate-500">Enabling permission</dt>
                          <dd className="font-mono text-slate-200">{activeAssessment.exposureSummary.enablingPermission}</dd>
                        </div>
                        <div>
                          <dt className="text-slate-500">Sensitive resource</dt>
                          <dd className="font-mono text-slate-200">{activeAssessment.exposureSummary.sensitiveResource}</dd>
                        </div>
                        <div>
                          <dt className="text-slate-500">Blast radius</dt>
                          <dd className="text-slate-200">{activeAssessment.exposureSummary.blastRadius}</dd>
                        </div>
                        <div>
                          <dt className="text-slate-500">Shortest remediation</dt>
                          <dd className="text-emerald-300">{activeAssessment.exposureSummary.shortestRemediation}</dd>
                        </div>
                      </dl>
                    </div>
                  )}

                  <div className="rounded-lg border border-white/[0.06] bg-[#090B10] p-3 space-y-1.5">
                    <p className="text-[11px] font-medium text-slate-300">
                      NIST AI RMF alignment (Govern · Map · Measure · Manage)
                    </p>
                    <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2 text-[11px]">
                      <p className="text-slate-400">
                        <span className="font-mono text-sky-300">GOVERN:</span>{' '}
                        {activeAssessment.nistAiRmf.govern}
                      </p>
                      <p className="text-slate-400">
                        <span className="font-mono text-sky-300">MAP:</span>{' '}
                        {activeAssessment.nistAiRmf.map}
                      </p>
                      <p className="text-slate-400">
                        <span className="font-mono text-sky-300">MEASURE:</span>{' '}
                        {activeAssessment.nistAiRmf.measure}
                      </p>
                      <p className="text-slate-400">
                        <span className="font-mono text-sky-300">MANAGE:</span>{' '}
                        {activeAssessment.nistAiRmf.manage}
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Evidence Artifacts */}
              {activeFinding.evidence && activeFinding.evidence.length > 0 && (
                <div className="border-t border-white/[0.08] pt-4">
                  <p className="text-xs font-medium text-slate-300">
                    Immutable evidence ({activeFinding.evidence.length})
                  </p>
                  <ul className="mt-2 space-y-1.5">
                    {activeFinding.evidence.map((ev) => (
                      <li
                        key={ev.id}
                        className="rounded-lg border border-white/[0.06] bg-[#090B10] px-3 py-2 text-[11px]"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono text-sky-300">
                            {ev.source} · {ev.type}
                          </span>
                          <span className="font-mono text-slate-500 tabular-nums">
                            {ev.hash.slice(0, 18)}...
                          </span>
                        </div>
                        <p className="mt-0.5 text-slate-300">{ev.summary}</p>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Ticket Routing: Jira / ServiceNow + Notifications */}
              <div className="border-t border-white/[0.08] pt-4 space-y-3">
                {activeFinding.jiraTicketKey ? (
                  <div className="space-y-2">
                    <div className="flex items-center justify-between rounded-lg border border-sky-500/30 bg-sky-500/10 p-3 text-xs">
                      <div>
                        <p className="font-semibold text-sky-300">
                          {activeFinding.ticketProvider === 'servicenow'
                            ? 'ServiceNow Incident'
                            : 'Jira Ticket'}{' '}
                          {activeFinding.jiraTicketKey}
                        </p>
                        <p className="text-[11px] text-slate-300">
                          Assigned to {activeFinding.owner}
                          {activeFinding.notifiedChannels?.length
                            ? ` · Notified ${activeFinding.notifiedChannels.join(', ')}`
                            : ''}
                        </p>
                      </div>
                      <button
                        type="button"
                        onClick={() => setShowTicketPreview((v) => !v)}
                        className="inline-flex items-center gap-1 text-[11px] font-medium text-sky-300 hover:text-white"
                      >
                        <span>{showTicketPreview ? 'Hide template' : 'Preview template'}</span>
                        <ExternalLink className="w-3.5 h-3.5" aria-hidden="true" />
                      </button>
                    </div>
                    {showTicketPreview && activeFinding.ticketPayloadPreview && (
                      <pre className="max-h-48 overflow-auto rounded-lg border border-white/[0.08] bg-[#090B10] p-3 font-mono text-[11px] leading-relaxed text-slate-300 whitespace-pre-wrap">
                        {activeFinding.ticketPayloadPreview}
                      </pre>
                    )}
                  </div>
                ) : (
                  <div className="space-y-2.5">
                    <p className="text-xs font-medium text-slate-300">
                      Create remediation ticket &amp; notify owner
                    </p>
                    <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                      <select
                        aria-label="Ticketing system"
                        value={ticketProvider}
                        onChange={(e) =>
                          setTicketProvider(e.target.value as 'jira' | 'servicenow')
                        }
                        className="rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 text-xs text-white focus:border-sky-500 focus:outline-none"
                      >
                        <option value="jira">Atlassian Jira (SEC)</option>
                        <option value="servicenow">ServiceNow ITSM (INC)</option>
                      </select>

                      <select
                        aria-label="Assign ticket to team"
                        value={ticketAssignee}
                        onChange={(e) => setTicketAssignee(e.target.value)}
                        className="rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 text-xs text-white focus:border-sky-500 focus:outline-none"
                      >
                        <option value="Cloud Security">Cloud Security</option>
                        <option value="IAM Governance">IAM Governance</option>
                        <option value="Product Security">Product Security</option>
                        <option value="AppSec">AppSec</option>
                      </select>
                    </div>

                    <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                      <div className="flex items-center gap-4 text-[11px] text-slate-300">
                        <label className="inline-flex items-center gap-1.5 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={notifySlack}
                            onChange={(e) => setNotifySlack(e.target.checked)}
                            className="rounded border-white/20 bg-[#090B10]"
                          />
                          <span>Slack</span>
                        </label>
                        <label className="inline-flex items-center gap-1.5 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={notifyTeams}
                            onChange={(e) => setNotifyTeams(e.target.checked)}
                            className="rounded border-white/20 bg-[#090B10]"
                          />
                          <span>Microsoft Teams</span>
                        </label>
                      </div>

                      <button
                        type="button"
                        onClick={handleDispatchTicket}
                        className="inline-flex items-center gap-1.5 rounded-lg bg-sky-500 px-3.5 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400 whitespace-nowrap"
                      >
                        <Ticket className="w-3.5 h-3.5" aria-hidden="true" />
                        <span>
                          Create {ticketProvider === 'servicenow' ? 'ServiceNow' : 'Jira'} ticket
                        </span>
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {/* Approval-Gated Remediation Controls */}
              <div className="border-t border-white/[0.08] pt-4 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="text-xs font-medium text-slate-300">
                    Approval-gated remediation controls
                  </p>
                  <span className="font-mono text-[11px] text-slate-400">
                    {activeFinding.remediation?.approvalStatus === 'approved'
                      ? `Approved (${activeFinding.remediation.approvedBy})`
                      : activeFinding.remediation?.approvalStatus === 'applied'
                        ? 'Least-privilege applied'
                        : activeFinding.remediation?.approvalStatus === 'rolled_back'
                          ? 'Rolled back'
                          : 'Approval required'}
                  </span>
                </div>

                {activeFinding.remediation?.dryRunExecuted && activeFinding.remediation.dryRunDiff && (
                  <div className="rounded-lg border border-white/[0.08] bg-[#090B10] p-3">
                    <p className="text-[11px] font-medium text-sky-400">
                      Dry-run proposed change (rollback snapshot preserved)
                    </p>
                    <pre className="mt-1.5 overflow-x-auto font-mono text-[11px] leading-relaxed text-slate-300">
                      {activeFinding.remediation.dryRunDiff}
                    </pre>
                  </div>
                )}

                {activeFinding.status !== 'remediated' && (
                  <div className="space-y-2.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <button
                        type="button"
                        onClick={() => onRunDryRun(activeFinding.id)}
                        className="inline-flex items-center gap-1.5 rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 text-xs font-medium text-slate-200 hover:text-white"
                      >
                        <GitCompare className="w-3.5 h-3.5 text-sky-400" aria-hidden="true" />
                        <span>Preview dry-run diff</span>
                      </button>

                      {activeFinding.remediation?.approvalStatus !== 'approved' &&
                        activeFinding.remediation?.approvalStatus !== 'applied' && (
                          <button
                            type="button"
                            onClick={() => onApproveRemediation(activeFinding.id, breakGlass)}
                            className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-xs font-medium text-emerald-300 hover:bg-emerald-500/20"
                          >
                            <ShieldCheck className="w-3.5 h-3.5" aria-hidden="true" />
                            <span>Approve remediation</span>
                          </button>
                        )}

                      {activeFinding.remediation?.approvalStatus === 'approved' && (
                        <button
                          type="button"
                          onClick={() => onApplyRemediation(activeFinding.id)}
                          className="inline-flex items-center gap-1.5 rounded-lg bg-amber-400 px-3 py-2 text-xs font-semibold text-slate-950 hover:bg-amber-300"
                        >
                          <FileCheck2 className="w-3.5 h-3.5" aria-hidden="true" />
                          <span>Apply approved change</span>
                        </button>
                      )}

                      {activeFinding.remediation?.approvalStatus === 'applied' && (
                        <button
                          type="button"
                          onClick={() => onRollbackRemediation(activeFinding.id)}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 text-xs font-medium text-slate-300 hover:text-white"
                        >
                          <RotateCcw className="w-3.5 h-3.5 text-amber-400" aria-hidden="true" />
                          <span>Rollback change</span>
                        </button>
                      )}
                    </div>

                    {activeFinding.remediation?.approvalStatus !== 'approved' &&
                      activeFinding.remediation?.approvalStatus !== 'applied' && (
                        <label className="inline-flex items-center gap-2 text-[11px] text-slate-400 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={breakGlass}
                            onChange={(e) => setBreakGlass(e.target.checked)}
                            className="rounded border-white/20 bg-[#090B10]"
                          />
                          <span>Record break-glass dual-approval audit attestation</span>
                        </label>
                      )}

                    <button
                      type="button"
                      onClick={handleVerifyClosure}
                      className="inline-flex w-full items-center justify-center gap-1.5 rounded-lg border border-sky-500/40 bg-sky-500/10 px-3.5 py-2 text-xs font-semibold text-sky-300 hover:bg-sky-500/20"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" />
                      <span>Re-sync &amp; verify closure</span>
                    </button>
                  </div>
                )}

                {activeFinding.verification?.status === 'verified_closed' && (
                  <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-xs space-y-1">
                    <div className="flex items-center gap-2 font-semibold text-emerald-300">
                      <CheckCircle2 className="w-4 h-4" aria-hidden="true" />
                      <span>Verified closed after discovery re-sync</span>
                    </div>
                    <p className="text-slate-300">{activeFinding.verification.message}</p>
                    {activeFinding.verification.proofHash && (
                      <p className="font-mono text-[11px] text-emerald-200/90 tabular-nums break-all">
                        Closure Proof: {activeFinding.verification.proofHash}
                      </p>
                    )}
                    {activeFinding.remediation?.rollbackAvailable && (
                      <button
                        type="button"
                        onClick={() => onRollbackRemediation(activeFinding.id)}
                        className="mt-1 inline-flex items-center gap-1 text-[11px] text-amber-300 hover:text-amber-200"
                      >
                        <RotateCcw className="w-3 h-3" aria-hidden="true" />
                        <span>Rollback remediation &amp; re-open finding</span>
                      </button>
                    )}
                  </div>
                )}

                {activeFinding.verification?.status === 'path_still_present' &&
                  !workflowFeedback && (
                    <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300 flex items-start gap-2">
                      <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" aria-hidden="true" />
                      <span>{activeFinding.verification.message}</span>
                    </div>
                  )}
              </div>
            </div>
          ) : (
            <p className="text-xs text-slate-400">Select a finding to inspect details.</p>
          )}
        </div>
      </div>
      )}
    </div>
  );
};
