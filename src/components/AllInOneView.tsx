import React, { useState } from 'react';
import {
  ArrowRight,
  Bot,
  CheckCircle2,
  FileCheck2,
  GitBranch,
  KeyRound,
  Layers,
  Play,
  Plug,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Ticket,
} from 'lucide-react';
import type { EnterpriseStatePayload } from '../App';
import type {
  Agent,
  AllInOneRunResult,
  Connector,
  ControlItem,
  Finding,
  GraphTraversalPath,
  RolloutStage,
  ScreenId,
  Tenant,
} from '../types/security';
import { computeComplianceCoverage } from '../utils/riskEngine';

interface AllInOneViewProps {
  tenant: Tenant;
  agents: Agent[];
  connectors: Connector[];
  graphPaths: GraphTraversalPath[];
  findings: Finding[];
  controls: ControlItem[];
  enterpriseState: EnterpriseStatePayload | null;
  lastRun?: AllInOneRunResult;
  canRunAllInOne: boolean;
  onRunAllInOne: (options?: {
    ticketProvider?: 'jira' | 'servicenow';
    assignee?: string;
  }) => Promise<AllInOneRunResult | null>;
  onOnboardAllClouds: () => Promise<{
    connectorsSynced: number;
    nodesAdded: number;
    edgesAdded: number;
  } | null>;
  onTicketAllOpenFindings: (provider: 'jira' | 'servicenow') => Promise<{
    createdCount: number;
  } | null>;
  onChangeRolloutStage: (stage: RolloutStage) => Promise<void>;
  onToggleKillSwitch: (paused: boolean, reason?: string) => Promise<void>;
  onExportCompliance: () => Promise<string | null>;
  onVerifyReleaseGates: () => Promise<void>;
  onNavigate: (screen: ScreenId) => void;
}

const ROLLOUT_STAGE_LABELS: Record<RolloutStage, string> = {
  observe: '1. Observe',
  advisory: '2. Advisory',
  selective_enforcement: '3. Selective',
  approval_gated_response: '4. Approval-Gated',
  full_enforcement: '5. Full Enforce',
};

export const AllInOneView: React.FC<AllInOneViewProps> = ({
  tenant,
  agents,
  connectors,
  graphPaths,
  findings,
  controls,
  enterpriseState,
  lastRun,
  canRunAllInOne,
  onRunAllInOne,
  onOnboardAllClouds,
  onTicketAllOpenFindings,
  onChangeRolloutStage,
  onToggleKillSwitch,
  onExportCompliance,
  onVerifyReleaseGates,
  onNavigate,
}) => {
  const [ticketProvider, setTicketProvider] = useState<'jira' | 'servicenow'>('jira');
  const [runningAll, setRunningAll] = useState(false);
  const [actionBusy, setActionBusy] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<string>('');

  const tenantAgents = agents.filter((a) => a.tenantId === tenant.id);
  const shadowAgents = tenantAgents.filter((a) => a.type === 'Shadow AI').length;
  const tenantConnectors = connectors.filter((c) => c.tenantId === tenant.id);
  const healthyConnectors = tenantConnectors.filter((c) => c.status === 'healthy').length;
  const openFindings = findings.filter(
    (f) => f.tenantId === tenant.id && f.status !== 'remediated'
  );
  const criticalFindings = openFindings.filter((f) => f.severity === 'critical').length;
  const unticketedOpen = openFindings.filter((f) => !f.jiraTicketKey);
  const complianceSummary = computeComplianceCoverage(controls);

  const passedGates = enterpriseState
    ? enterpriseState.releaseGates.filter((g) => g.passed).length
    : 0;
  const totalGates = enterpriseState?.releaseGates.length ?? 8;
  const activeScimUsers =
    enterpriseState?.scimDirectory.filter((u) => u.status === 'active').length ?? 0;

  const topPath = graphPaths[0];
  const currentRolloutStage = enterpriseState?.rolloutStage ?? 'observe';
  const killSwitchPaused = enterpriseState?.killSwitch.paused ?? false;

  const handleRunAllInOne = async () => {
    setRunningAll(true);
    setFeedback('');
    try {
      const res = await onRunAllInOne({ ticketProvider, assignee: 'Cloud Security' });
      if (res) {
        setFeedback(
          `All-in-One pipeline completed in ${res.durationMs}ms · ${res.summary.connectorsHealthy}/${res.summary.connectorsTotal} clouds synced · ${res.summary.ticketsCreatedCount} ticket(s) created · ${res.summary.releaseGatesPassed}/${res.summary.releaseGatesTotal} release gates passed.`
        );
      }
    } finally {
      setRunningAll(false);
    }
  };

  const handleBatchConnectors = async () => {
    setActionBusy('connectors');
    setFeedback('');
    try {
      const res = await onOnboardAllClouds();
      if (res) {
        setFeedback(
          `Onboarded & synced ${res.connectorsSynced} read-only cloud/IdP connectors (+${res.nodesAdded} graph nodes, +${res.edgesAdded} edges).`
        );
      }
    } finally {
      setActionBusy(null);
    }
  };

  const handleBatchTickets = async () => {
    setActionBusy('tickets');
    setFeedback('');
    try {
      const res = await onTicketAllOpenFindings(ticketProvider);
      if (res) {
        setFeedback(
          res.createdCount > 0
            ? `Created ${res.createdCount} ${ticketProvider === 'servicenow' ? 'ServiceNow' : 'Jira'} ticket(s) for all open unticketed findings.`
            : 'All open findings already have active remediation tickets.'
        );
      }
    } finally {
      setActionBusy(null);
    }
  };

  const handleQuickExport = async () => {
    setActionBusy('compliance');
    setFeedback('');
    try {
      const packageId = await onExportCompliance();
      if (packageId) {
        setFeedback(`Exported hash-chained compliance package ${packageId}.`);
      }
    } finally {
      setActionBusy(null);
    }
  };

  const handleVerifyGates = async () => {
    setActionBusy('gates');
    setFeedback('');
    try {
      await onVerifyReleaseGates();
      setFeedback('Programmatic verification completed across all 8 enterprise release gates.');
    } finally {
      setActionBusy(null);
    }
  };

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      {/* Primary Header + One-Click Orchestrator */}
      <div className="flex flex-wrap items-end justify-between gap-4 border-b border-white/[0.08] pb-5">
        <div>
          <div className="flex items-center gap-2 text-xs font-medium text-sky-400">
            <Layers className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Unified Control Plane</span>
          </div>
          <h1 className="mt-1 font-display text-2xl font-semibold tracking-tight text-white">
            All-in-One Hub
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Discover clouds, map exposure paths, ticket findings, verify PEP/PDP, export compliance evidence, and audit release gates in one flow for {tenant.name}.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-2 text-xs text-slate-400">
            <span>Ticketing</span>
            <select
              aria-label="All-in-One ticket provider"
              value={ticketProvider}
              onChange={(e) =>
                setTicketProvider(e.target.value === 'servicenow' ? 'servicenow' : 'jira')
              }
              className="rounded-lg border border-white/15 bg-[#11151D] px-2.5 py-2 text-xs font-medium text-white focus:border-sky-500 focus:outline-none"
            >
              <option value="jira">Jira</option>
              <option value="servicenow">ServiceNow</option>
            </select>
          </label>

          <button
            type="button"
            disabled={!canRunAllInOne || runningAll}
            onClick={() => void handleRunAllInOne()}
            className="inline-flex items-center gap-2 rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50 transition-colors whitespace-nowrap"
          >
            {runningAll ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
            ) : (
              <Play className="w-3.5 h-3.5" aria-hidden="true" />
            )}
            <span>{runningAll ? 'Running All-in-One...' : 'Create & Run All-in-One'}</span>
          </button>
        </div>
      </div>

      {feedback && (
        <div
          role="status"
          className="flex items-center justify-between gap-3 rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-xs text-emerald-200"
        >
          <span className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" aria-hidden="true" />
            <span>{feedback}</span>
          </span>
          {lastRun && (
            <span className="font-mono text-[11px] text-emerald-300 tabular-nums shrink-0">
              Run {lastRun.runId}
            </span>
          )}
        </div>
      )}

      {/* 7-Stage Unified Execution Trace (Rendered when executed) */}
      {lastRun && (
        <section
          aria-label="All-in-One execution trace"
          className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5"
        >
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.08] pb-3.5">
            <div>
              <h2 className="font-display text-sm font-semibold text-white">
                End-to-End Orchestration Trace
              </h2>
              <p className="mt-0.5 text-xs text-slate-400">
                Executed by {lastRun.executedBy} · <span className="font-mono tabular-nums">{lastRun.durationMs}ms</span> · Run ID <span className="font-mono">{lastRun.runId}</span>
              </p>
            </div>
            <div className="flex items-center gap-4 font-mono text-xs text-slate-300 tabular-nums">
              <span>{lastRun.summary.connectorsHealthy}/{lastRun.summary.connectorsTotal} clouds</span>
              <span aria-hidden="true" className="text-slate-600">·</span>
              <span>{lastRun.summary.exposurePathsCount} paths</span>
              <span aria-hidden="true" className="text-slate-600">·</span>
              <span>{lastRun.summary.releaseGatesPassed}/{lastRun.summary.releaseGatesTotal} gates</span>
              <span aria-hidden="true" className="text-slate-600">·</span>
              <span className={lastRun.summary.auditChainValid ? 'text-emerald-400' : 'text-rose-400'}>
                {lastRun.summary.auditChainValid ? 'SHA-256 Intact' : 'Chain Alert'}
              </span>
            </div>
          </div>

          <div className="mt-3 divide-y divide-white/[0.06]">
            {lastRun.stages.map((stage) => (
              <div
                key={stage.id}
                className="flex flex-wrap items-center justify-between gap-3 py-2.5 text-xs"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <span className="font-mono text-sky-400 tabular-nums">
                    0{stage.step}.
                  </span>
                  <span className="font-medium text-white">{stage.title}</span>
                  <span className="text-slate-400 truncate">{stage.summary}</span>
                </div>
                <button
                  type="button"
                  onClick={() => onNavigate(stage.targetScreen)}
                  className="inline-flex items-center gap-1 font-medium text-sky-400 hover:text-sky-300 whitespace-nowrap"
                >
                  <span>Inspect</span>
                  <ArrowRight className="w-3 h-3" aria-hidden="true" />
                </button>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* 6-Pillar Single-Pane Control Matrix */}
      <section
        aria-label="Unified control plane pillars"
        className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3"
      >
        {/* Pillar 1: Discovery & Cloud Connectors */}
        <div className="flex flex-col justify-between rounded-xl border border-white/[0.08] bg-[#11151D] p-5">
          <div>
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="flex items-center gap-2 font-medium text-slate-200">
                <Plug className="w-4 h-4 text-sky-400" aria-hidden="true" />
                <span>01. Discovery &amp; Connectors</span>
              </span>
              <span className="font-mono tabular-nums text-emerald-400">
                {healthyConnectors}/{tenantConnectors.length} healthy
              </span>
            </div>
            <div className="mt-3 flex items-baseline gap-3">
              <span className="font-mono text-2xl font-semibold text-white tabular-nums">
                {tenantAgents.length}
              </span>
              <span className="text-xs text-slate-400">
                discovered agents · {shadowAgents} shadow AI
              </span>
            </div>
            <ul className="mt-3 space-y-1.5 border-t border-white/[0.06] pt-3 text-xs text-slate-300">
              {tenantConnectors.slice(0, 4).map((c) => (
                <li key={c.id} className="flex items-center justify-between gap-2">
                  <span className="truncate">{c.name}</span>
                  <span className="font-mono text-[11px] text-slate-400 tabular-nums">
                    {c.readOnly ? 'read-only' : 'scoped'} · {c.discoveredAssets} assets
                  </span>
                </li>
              ))}
            </ul>
          </div>

          <div className="mt-4 flex flex-wrap items-center justify-between gap-2 border-t border-white/[0.06] pt-3">
            <button
              type="button"
              disabled={!canRunAllInOne || actionBusy === 'connectors'}
              onClick={() => void handleBatchConnectors()}
              className="rounded-lg border border-white/15 bg-[#090B10] px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-sky-500/50 disabled:opacity-50"
            >
              {actionBusy === 'connectors' ? 'Syncing...' : 'Onboard & sync all clouds'}
            </button>
            <button
              type="button"
              onClick={() => onNavigate('connectors')}
              className="inline-flex items-center gap-1 text-xs font-medium text-sky-400 hover:text-sky-300"
            >
              <span>Connectors</span>
              <ArrowRight className="w-3.5 h-3.5" aria-hidden="true" />
            </button>
          </div>
        </div>

        {/* Pillar 2: Exposure Graph & Risk Scoring */}
        <div className="flex flex-col justify-between rounded-xl border border-white/[0.08] bg-[#11151D] p-5">
          <div>
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="flex items-center gap-2 font-medium text-slate-200">
                <GitBranch className="w-4 h-4 text-orange-400" aria-hidden="true" />
                <span>02. Exposure Graph &amp; Risk</span>
              </span>
              <span className="font-mono tabular-nums text-slate-300">
                Score {tenant.overallRiskScore}/100
              </span>
            </div>
            <div className="mt-3 flex items-baseline gap-3">
              <span className="font-mono text-2xl font-semibold text-white tabular-nums">
                {graphPaths.length}
              </span>
              <span className="text-xs text-slate-400">
                agent-to-sensitive-data paths
              </span>
            </div>
            <div className="mt-3 border-t border-white/[0.06] pt-3 text-xs">
              {topPath ? (
                <div className="space-y-1">
                  <p className="font-medium text-white">
                    {topPath.agentLabel} → {topPath.targetDataLabel}
                  </p>
                  <p className="text-slate-400">
                    {topPath.hopCount} hops · {topPath.targetSensitivity} · {topPath.riskLevel} risk
                  </p>
                </div>
              ) : (
                <p className="text-slate-400">No sensitive traversal paths active.</p>
              )}
            </div>
          </div>

          <div className="mt-4 flex items-center justify-between gap-2 border-t border-white/[0.06] pt-3">
            <button
              type="button"
              onClick={() => onNavigate('inventory')}
              className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-300 hover:text-white"
            >
              <Bot className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Agent inventory</span>
            </button>
            <button
              type="button"
              onClick={() => onNavigate('exposure')}
              className="inline-flex items-center gap-1 text-xs font-medium text-sky-400 hover:text-sky-300"
            >
              <span>Exposure graph</span>
              <ArrowRight className="w-3.5 h-3.5" aria-hidden="true" />
            </button>
          </div>
        </div>

        {/* Pillar 3: Findings & Batch Ticketing */}
        <div className="flex flex-col justify-between rounded-xl border border-white/[0.08] bg-[#11151D] p-5">
          <div>
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="flex items-center gap-2 font-medium text-slate-200">
                <ShieldAlert className="w-4 h-4 text-rose-400" aria-hidden="true" />
                <span>03. Findings &amp; Remediation</span>
              </span>
              <span className="font-mono tabular-nums text-rose-400">
                {criticalFindings} critical
              </span>
            </div>
            <div className="mt-3 flex items-baseline gap-3">
              <span className="font-mono text-2xl font-semibold text-white tabular-nums">
                {openFindings.length}
              </span>
              <span className="text-xs text-slate-400">
                open findings · {unticketedOpen.length} unticketed
              </span>
            </div>
            <ul className="mt-3 space-y-1.5 border-t border-white/[0.06] pt-3 text-xs text-slate-300">
              {openFindings.slice(0, 3).map((f) => (
                <li key={f.id} className="flex items-center justify-between gap-2">
                  <span className="truncate">{f.title}</span>
                  <span className="font-mono text-[11px] text-slate-400 shrink-0">
                    {f.jiraTicketKey ?? 'unticketed'}
                  </span>
                </li>
              ))}
            </ul>
          </div>

          <div className="mt-4 flex flex-wrap items-center justify-between gap-2 border-t border-white/[0.06] pt-3">
            <button
              type="button"
              disabled={!canRunAllInOne || actionBusy === 'tickets'}
              onClick={() => void handleBatchTickets()}
              className="inline-flex items-center gap-1.5 rounded-lg border border-white/15 bg-[#090B10] px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-sky-500/50 disabled:opacity-50"
            >
              <Ticket className="w-3.5 h-3.5 text-sky-400" aria-hidden="true" />
              <span>
                {actionBusy === 'tickets' ? 'Creating...' : 'Ticket all open'}
              </span>
            </button>
            <button
              type="button"
              onClick={() => onNavigate('findings')}
              className="inline-flex items-center gap-1 text-xs font-medium text-sky-400 hover:text-sky-300"
            >
              <span>Findings</span>
              <ArrowRight className="w-3.5 h-3.5" aria-hidden="true" />
            </button>
          </div>
        </div>

        {/* Pillar 4: Zero-Trust PEP/PDP & SOAR */}
        <div className="flex flex-col justify-between rounded-xl border border-white/[0.08] bg-[#11151D] p-5">
          <div>
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="flex items-center gap-2 font-medium text-slate-200">
                <SlidersHorizontal className="w-4 h-4 text-sky-400" aria-hidden="true" />
                <span>04. PEP/PDP Policy &amp; SOAR</span>
              </span>
              <span className={`font-mono ${killSwitchPaused ? 'text-rose-400' : 'text-emerald-400'}`}>
                {killSwitchPaused ? 'Kill switch PAUSED' : 'SOAR armed'}
              </span>
            </div>
            <div className="mt-3 flex items-baseline gap-3">
              <span className="font-mono text-lg font-semibold text-white">
                {ROLLOUT_STAGE_LABELS[currentRolloutStage]}
              </span>
              <span className="text-xs text-slate-400">
                · {enterpriseState?.playbooks.length ?? 6} SOAR playbooks
              </span>
            </div>
            <div className="mt-3 border-t border-white/[0.06] pt-3">
              <label className="block text-[11px] text-slate-400">
                Progressive rollout stage
                <select
                  aria-label="All-in-One rollout stage"
                  disabled={!canRunAllInOne}
                  value={currentRolloutStage}
                  onChange={(e) => void onChangeRolloutStage(e.target.value as RolloutStage)}
                  className="mt-1 w-full rounded-lg border border-white/15 bg-[#090B10] px-2.5 py-1.5 text-xs text-white focus:border-sky-500 focus:outline-none"
                >
                  {(Object.keys(ROLLOUT_STAGE_LABELS) as RolloutStage[]).map((stage) => (
                    <option key={stage} value={stage}>
                      {ROLLOUT_STAGE_LABELS[stage]}
                    </option>
                  ))}
                </select>
              </label>
            </div>
          </div>

          <div className="mt-4 flex flex-wrap items-center justify-between gap-2 border-t border-white/[0.06] pt-3">
            <button
              type="button"
              disabled={!canRunAllInOne}
              onClick={() =>
                void onToggleKillSwitch(
                  !killSwitchPaused,
                  killSwitchPaused ? 'Resumed via All-in-One Hub' : 'Paused via All-in-One Hub'
                )
              }
              className={`rounded-lg border px-3 py-1.5 text-xs font-medium ${
                killSwitchPaused
                  ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'
                  : 'border-rose-500/40 bg-rose-500/10 text-rose-300'
              }`}
            >
              {killSwitchPaused ? 'Resume automation' : 'Pause kill switch'}
            </button>
            <button
              type="button"
              onClick={() => onNavigate('policy')}
              className="inline-flex items-center gap-1 text-xs font-medium text-sky-400 hover:text-sky-300"
            >
              <span>Policy &amp; SOAR</span>
              <ArrowRight className="w-3.5 h-3.5" aria-hidden="true" />
            </button>
          </div>
        </div>

        {/* Pillar 5: Compliance & Scoped Evidence */}
        <div className="flex flex-col justify-between rounded-xl border border-white/[0.08] bg-[#11151D] p-5">
          <div>
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="flex items-center gap-2 font-medium text-slate-200">
                <FileCheck2 className="w-4 h-4 text-emerald-400" aria-hidden="true" />
                <span>05. Compliance &amp; Evidence</span>
              </span>
              <span className="font-mono tabular-nums text-slate-300">
                {complianceSummary.coveredCount}/{controls.length} covered
              </span>
            </div>
            <div className="mt-3 flex items-baseline gap-3">
              <span className="font-mono text-2xl font-semibold text-white tabular-nums">
                {complianceSummary.coveragePct}%
              </span>
              <span className="text-xs text-slate-400">
                SOC 2 · ISO 27001 · ISO 42001 · EU AI Act
              </span>
            </div>
            <p className="mt-3 border-t border-white/[0.06] pt-3 text-xs text-slate-400">
              Zero raw prompt retention active. Auditor-scoped exports seal evidence records with verifiable SHA-256 digests.
            </p>
          </div>

          <div className="mt-4 flex flex-wrap items-center justify-between gap-2 border-t border-white/[0.06] pt-3">
            <button
              type="button"
              disabled={actionBusy === 'compliance'}
              onClick={() => void handleQuickExport()}
              className="rounded-lg border border-white/15 bg-[#090B10] px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-sky-500/50 disabled:opacity-50"
            >
              {actionBusy === 'compliance' ? 'Exporting...' : 'Export evidence pack'}
            </button>
            <button
              type="button"
              onClick={() => onNavigate('compliance')}
              className="inline-flex items-center gap-1 text-xs font-medium text-sky-400 hover:text-sky-300"
            >
              <span>Compliance</span>
              <ArrowRight className="w-3.5 h-3.5" aria-hidden="true" />
            </button>
          </div>
        </div>

        {/* Pillar 6: SSO, SCIM, Audit & Release Gates */}
        <div className="flex flex-col justify-between rounded-xl border border-white/[0.08] bg-[#11151D] p-5">
          <div>
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="flex items-center gap-2 font-medium text-slate-200">
                <KeyRound className="w-4 h-4 text-sky-400" aria-hidden="true" />
                <span>06. SSO, Audit &amp; Release Gates</span>
              </span>
              <span
                className={`font-mono tabular-nums ${
                  passedGates === totalGates ? 'text-emerald-400' : 'text-amber-400'
                }`}
              >
                {passedGates}/{totalGates} gates
              </span>
            </div>
            <div className="mt-3 flex items-baseline gap-3">
              <span className="font-mono text-lg font-semibold text-white">
                {enterpriseState?.auditIntegrity.valid ? 'VERIFIED INTACT' : 'CHECK CHAIN'}
              </span>
              <span className="font-mono text-xs text-slate-400 tabular-nums">
                {enterpriseState?.auditIntegrity.verifiedCount ?? 0} chained events
              </span>
            </div>
            <p className="mt-3 border-t border-white/[0.06] pt-3 text-xs text-slate-400">
              {enterpriseState?.ssoConfig.protocol === 'oidc' ? 'OIDC' : 'SAML 2.0'} enforced · Admin MFA active · {activeScimUsers} SCIM directory principals
            </p>
          </div>

          <div className="mt-4 flex flex-wrap items-center justify-between gap-2 border-t border-white/[0.06] pt-3">
            <button
              type="button"
              disabled={actionBusy === 'gates'}
              onClick={() => void handleVerifyGates()}
              className="inline-flex items-center gap-1.5 rounded-lg border border-white/15 bg-[#090B10] px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-sky-500/50 disabled:opacity-50"
            >
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" aria-hidden="true" />
              <span>{actionBusy === 'gates' ? 'Verifying...' : 'Verify 8 gates'}</span>
            </button>
            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={() => onNavigate('enterprise')}
                className="text-xs font-medium text-sky-400 hover:text-sky-300"
              >
                SSO
              </button>
              <button
                type="button"
                onClick={() => onNavigate('audit')}
                className="text-xs font-medium text-sky-400 hover:text-sky-300"
              >
                Audit Log
              </button>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};
