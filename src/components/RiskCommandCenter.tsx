import React, { useState } from 'react';
import {
  Activity,
  ArrowUpRight,
  Bot,
  Database,
  FileCheck2,
  KeyRound,
  ShieldAlert,
} from 'lucide-react';
import type {
  ActivityEvent,
  Agent,
  ControlItem,
  DataSource,
  Finding,
  PersonaLensId,
  RiskTrendPoint,
  ScreenId,
  Tenant,
  VerticalPackId,
  VerticalPolicyPack,
} from '../types/security';
import { computeComplianceCoverage, type DashboardMetrics } from '../utils/riskEngine';
import { RiskLabel } from './RiskIndicator';

interface RiskCommandCenterProps {
  tenant: Tenant;
  metrics: DashboardMetrics;
  agents: Agent[];
  findings: Finding[];
  controls?: ControlItem[];
  dataSources: DataSource[];
  activity: ActivityEvent[];
  trendSeries: RiskTrendPoint[];
  activeVerticalPacks?: VerticalPackId[];
  verticalPacksCatalog?: VerticalPolicyPack[];
  onSelectAgent: (agentId: string) => void;
  onNavigate: (screen: ScreenId) => void;
}

const PERSONA_LENSES: Array<{
  id: PersonaLensId;
  label: string;
  focusLine: string;
  ctaScreen: ScreenId;
  ctaLabel: string;
}> = [
  {
    id: 'ciso',
    label: 'CISO',
    focusLine: 'Board-level cyber-risk posture, shadow AI reduction & regulatory exposure',
    ctaScreen: 'exposure',
    ctaLabel: 'Inspect exposure graph →',
  },
  {
    id: 'analyst',
    label: 'Security Analyst',
    focusLine: 'Triage blast-radius paths, review low-confidence agents & contain incidents',
    ctaScreen: 'findings',
    ctaLabel: 'Open findings & incidents →',
  },
  {
    id: 'ai_owner',
    label: 'AI Platform Owner',
    focusLine: 'Sanction discovered agents, verify approved models & govern MCP tool scopes',
    ctaScreen: 'inventory',
    ctaLabel: 'Review agent queue →',
  },
  {
    id: 'compliance',
    label: 'Compliance Lead',
    focusLine: 'Close SOC 2 / ISO 42001 / EU AI Act control gaps & manage exceptions',
    ctaScreen: 'compliance',
    ctaLabel: 'Open evidence vault →',
  },
  {
    id: 'auditor',
    label: 'External Auditor',
    focusLine: 'Verify SHA-256 hash-chained evidence & export read-only audit packages',
    ctaScreen: 'compliance',
    ctaLabel: 'Export audit pack →',
  },
  {
    id: 'mssp',
    label: 'MSSP Operator',
    focusLine: 'Cross-tenant posture oversight, vertical pack rollouts & SLA tracking',
    ctaScreen: 'policy',
    ctaLabel: 'Manage vertical packs →',
  },
];

export const RiskCommandCenter: React.FC<RiskCommandCenterProps> = ({
  tenant,
  metrics,
  agents,
  findings,
  controls,
  dataSources,
  activity,
  trendSeries,
  activeVerticalPacks = [],
  verticalPacksCatalog = [],
  onSelectAgent,
  onNavigate,
}) => {
  const [hoveredIdx, setHoveredIdx] = useState<number>(trendSeries.length - 1);
  const [personaLens, setPersonaLens] = useState<PersonaLensId>('ciso');

  const activeLens = PERSONA_LENSES.find((p) => p.id === personaLens) ?? PERSONA_LENSES[0];
  const installedPackDetails = verticalPacksCatalog.filter((p) =>
    activeVerticalPacks.includes(p.id)
  );

  const tenantAgents = agents.filter((a) => a.tenantId === tenant.id);
  const topRisks = [...tenantAgents]
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 4);
  const openFindings = findings.filter(
    (f) => f.tenantId === tenant.id && f.status !== 'remediated'
  );
  const reachableStoreIds = new Set(tenantAgents.flatMap((a) => a.dataSources));
  const reachableStoreNames = dataSources
    .filter(
      (ds) =>
        reachableStoreIds.has(ds.id) &&
        (ds.classification === 'Restricted' || ds.classification === 'Confidential')
    )
    .map((ds) => ds.name)
    .slice(0, 4)
    .join(', ');

  // Build SVG coordinates for trend chart
  const chartW = 560;
  const chartH = 160;
  const padX = 24;
  const padY = 18;
  const minScore = 50;
  const maxScore = 100;

  const points = trendSeries.map((pt, i) => {
    const x =
      padX + (i / Math.max(1, trendSeries.length - 1)) * (chartW - padX * 2);
    const y =
      padY +
      ((maxScore - pt.riskScore) / (maxScore - minScore)) * (chartH - padY * 2);
    return { x, y, ...pt };
  });

  const polylinePoints = points.map((p) => `${p.x},${p.y}`).join(' ');
  const areaPoints =
    points.length > 0
      ? `${points[0].x},${chartH - padY} ${polylinePoints} ${points[points.length - 1].x},${chartH - padY}`
      : '';
  const activePoint = points[hoveredIdx] ?? points[points.length - 1];

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-semibold tracking-tight text-white">
            Risk Command Center
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            {activeLens.label} lens for {tenant.name} ({tenant.industry}) — {activeLens.focusLine}
          </p>
        </div>
        <div className="flex items-center gap-3 text-xs text-slate-400">
          <span>{openFindings.length} open findings</span>
          <span aria-hidden="true">·</span>
          <button
            type="button"
            onClick={() => onNavigate(activeLens.ctaScreen)}
            className="font-medium text-sky-400 hover:text-sky-300"
          >
            {activeLens.ctaLabel}
          </button>
        </div>
      </div>

      {/* Persona Lens Switcher + Target Performance SLAs & Active Vertical Packs */}
      <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Persona view switcher">
            <span className="mr-1 text-[11px] font-medium text-slate-400">Persona view:</span>
            {PERSONA_LENSES.map((lens) => (
              <button
                key={lens.id}
                type="button"
                onClick={() => setPersonaLens(lens.id)}
                className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap ${
                  personaLens === lens.id
                    ? 'bg-sky-500 text-slate-950 font-semibold'
                    : 'border border-white/10 bg-[#090B10] text-slate-300 hover:text-white'
                }`}
              >
                {lens.label}
              </button>
            ))}
          </div>

          <div className="flex flex-wrap items-center gap-2 text-[11px]">
            <span className="text-slate-400">Active vertical packs:</span>
            {installedPackDetails.length > 0 ? (
              installedPackDetails.map((pk) => (
                <button
                  key={pk.id}
                  type="button"
                  onClick={() => onNavigate('policy')}
                  className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 font-mono text-emerald-300 hover:bg-emerald-500/20"
                >
                  {pk.name}
                </button>
              ))
            ) : (
              <button
                type="button"
                onClick={() => onNavigate('policy')}
                className="font-mono text-slate-400 hover:text-sky-400"
              >
                None installed (Configure →)
              </button>
            )}
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-x-5 gap-y-1.5 border-t border-white/[0.06] pt-3 font-mono text-[11px] tabular-nums">
          <div className="whitespace-nowrap text-slate-300">
            <span className="text-slate-500">IdP Connect:</span>{' '}
            <span className="text-emerald-400">&lt;15m SLA</span>
          </div>
          <div className="whitespace-nowrap text-slate-300">
            <span className="text-slate-500">Full Inventory:</span>{' '}
            <span className="text-emerald-400">&lt;24h SLA</span>
          </div>
          <div className="whitespace-nowrap text-slate-300">
            <span className="text-slate-500">Exposure Report:</span>{' '}
            <span className="text-emerald-400">&lt;48h SLA</span>
          </div>
          <div className="whitespace-nowrap text-slate-300">
            <span className="text-slate-500">Audit Pack:</span>{' '}
            <span className="text-emerald-400">&lt;5m SLA</span>
          </div>
          <div className="whitespace-nowrap text-slate-300">
            <span className="text-slate-500">Privacy:</span>{' '}
            <span className="text-sky-400">Zero Raw Prompt Retention</span>
          </div>
        </div>
      </div>

      {/* Top Row: 4 Core Executive KPI Cards */}
      <section aria-label="Primary risk posture metrics" className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {/* 1. Risk Posture */}
        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Risk posture</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" aria-hidden="true" />
          </div>
          <div className="mt-3 flex items-baseline gap-2.5">
            <span className="font-mono text-3xl font-semibold text-white tabular-nums">
              {metrics.overallRiskScore}
            </span>
            <span className="font-mono text-xs text-slate-400">/ 100</span>
            <span className="font-mono text-xs text-emerald-400 tabular-nums">
              {metrics.riskTrendDelta} pts (14d)
            </span>
          </div>
          <p className="mt-2 text-xs text-slate-400 tabular-nums">
            {metrics.criticalFindingsCount} critical · {metrics.openFindingsCount} total open
            findings
          </p>
        </div>

        {/* 2. AI Agent Inventory */}
        <button
          type="button"
          onClick={() => onNavigate('inventory')}
          className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5 text-left hover:border-white/20 transition-colors"
        >
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>AI agent inventory</span>
            <Bot className="w-4 h-4 text-sky-400" aria-hidden="true" />
          </div>
          <div className="mt-3 flex items-baseline gap-2.5">
            <span className="font-mono text-3xl font-semibold text-white tabular-nums">
              {metrics.totalAgents}
            </span>
            <span className="text-xs text-slate-400 tabular-nums">
              {metrics.activeAgents} active
            </span>
          </div>
          <p className="mt-2 text-xs text-amber-400 tabular-nums">
            {metrics.shadowAgents} shadow AI · {metrics.unownedAgents} unowned
          </p>
        </button>

        {/* 3. Data Exposure */}
        <button
          type="button"
          onClick={() => onNavigate('exposure')}
          className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5 text-left hover:border-white/20 transition-colors"
        >
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Data exposure</span>
            <Database className="w-4 h-4 text-orange-400" aria-hidden="true" />
          </div>
          <div className="mt-3 flex items-baseline gap-2.5">
            <span className="font-mono text-3xl font-semibold text-white tabular-nums">
              {metrics.reachableSensitiveSources}
            </span>
            <span className="text-xs text-slate-400">sensitive stores</span>
          </div>
          <p className="mt-2 text-xs text-slate-400 truncate">
            {reachableStoreNames || 'No restricted stores reachable'}
          </p>
        </button>

        {/* 4. Identity Risk */}
        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Identity risk</span>
            <KeyRound className="w-4 h-4 text-amber-400" aria-hidden="true" />
          </div>
          <div className="mt-3 flex items-baseline gap-2.5">
            <span className="font-mono text-3xl font-semibold text-white tabular-nums">
              {metrics.overPrivilegedIdentities}
            </span>
            <span className="text-xs text-slate-400">over-privileged</span>
          </div>
          <p className="mt-2 text-xs text-slate-400 tabular-nums">
            {metrics.unusedCredentials} unused credentials · {metrics.riskyServiceAccounts} risky
            service accounts
          </p>
        </div>
      </section>

      {/* Middle Row: Risk Trend Chart + Compliance + AI Activity */}
      <section className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Risk Trend Chart */}
        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5 lg:col-span-6">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="font-display text-base font-semibold text-white">
                Risk posture &amp; shadow AI trend
              </h2>
              <p className="text-xs text-slate-400">14-day score reduction after policy rollout</p>
            </div>
            {activePoint && (
              <div className="text-right font-mono text-xs tabular-nums">
                <span className="text-slate-400">{activePoint.date}: </span>
                <span className="font-semibold text-white">Score {activePoint.riskScore}</span>
                <span className="text-slate-500"> · </span>
                <span className="text-amber-400">{activePoint.shadowAgents} shadow</span>
              </div>
            )}
          </div>

          <div className="mt-4">
            <svg
              viewBox={`0 0 ${chartW} ${chartH}`}
              className="w-full h-44 overflow-visible"
              role="img"
              aria-label="14-day risk posture trend chart"
            >
              <defs>
                <linearGradient id="riskAreaGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#38BDF8" stopOpacity="0.28" />
                  <stop offset="100%" stopColor="#38BDF8" stopOpacity="0.0" />
                </linearGradient>
              </defs>
              {[60, 75, 90].map((val) => {
                const y =
                  padY + ((maxScore - val) / (maxScore - minScore)) * (chartH - padY * 2);
                return (
                  <g key={val}>
                    <line
                      x1={padX}
                      y1={y}
                      x2={chartW - padX}
                      y2={y}
                      stroke="rgba(255,255,255,0.06)"
                      strokeDasharray="3 3"
                    />
                    <text
                      x={4}
                      y={y + 3}
                      fill="#64748B"
                      fontSize="10"
                      fontFamily="IBM Plex Mono, monospace"
                    >
                      {val}
                    </text>
                  </g>
                );
              })}
              {areaPoints && <polygon points={areaPoints} fill="url(#riskAreaGrad)" />}
              {polylinePoints && (
                <polyline
                  fill="none"
                  stroke="#38BDF8"
                  strokeWidth="2.5"
                  points={polylinePoints}
                />
              )}
              {points.map((p, idx) => (
                <g key={p.date}>
                  <circle
                    cx={p.x}
                    cy={p.y}
                    r={idx === hoveredIdx ? 5 : 3.5}
                    fill={idx === hoveredIdx ? '#38BDF8' : '#090B10'}
                    stroke="#38BDF8"
                    strokeWidth="2"
                    className="cursor-pointer"
                    onMouseEnter={() => setHoveredIdx(idx)}
                  />
                  <text
                    x={p.x}
                    y={chartH - 2}
                    textAnchor="middle"
                    fill="#94A3B8"
                    fontSize="10"
                    fontFamily="IBM Plex Mono, monospace"
                  >
                    {p.date}
                  </text>
                </g>
              ))}
            </svg>
          </div>
        </div>

        {/* 5. Compliance Coverage */}
        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5 lg:col-span-3 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Compliance readiness</span>
              <FileCheck2 className="w-4 h-4 text-emerald-400" aria-hidden="true" />
            </div>
            <div className="mt-3 flex items-baseline gap-2">
              <span className="font-mono text-3xl font-semibold text-white tabular-nums">
                {metrics.complianceCoveragePct}%
              </span>
              <span className="text-xs text-slate-400">controls verified</span>
            </div>
            <div className="mt-4 space-y-3 text-xs">
              {(() => {
                const soc2Ctrls = (controls ?? []).filter((c) => c.framework === 'SOC 2');
                const isoCtrls = (controls ?? []).filter((c) => c.framework === 'ISO 27001');
                const soc2Pct =
                  soc2Ctrls.length > 0 ? computeComplianceCoverage(soc2Ctrls).coveragePct : 62;
                const isoPct =
                  isoCtrls.length > 0 ? computeComplianceCoverage(isoCtrls).coveragePct : 58;
                return (
                  <>
                    <div>
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-medium text-slate-200 whitespace-nowrap">
                          SOC 2 Type II
                        </span>
                        <span className="font-mono text-[11px] text-slate-400 tabular-nums whitespace-nowrap">
                          {soc2Pct}% ready
                        </span>
                      </div>
                      <p className="mt-0.5 font-mono text-[11px] text-slate-400">
                        CC6.1 · CC6.2 · CC6.3 · CC7.2
                      </p>
                      <div className="mt-1.5 h-1.5 w-full rounded-full bg-white/[0.06] overflow-hidden">
                        <div className="h-full bg-sky-500" style={{ width: `${soc2Pct}%` }} />
                      </div>
                    </div>
                    <div>
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-medium text-slate-200 whitespace-nowrap">
                          ISO 27001 / 42001
                        </span>
                        <span className="font-mono text-[11px] text-slate-400 tabular-nums whitespace-nowrap">
                          {isoPct}% ready
                        </span>
                      </div>
                      <p className="mt-0.5 font-mono text-[11px] text-slate-400">
                        A.5.15 · A.8.2 · GDPR · EU AI Act
                      </p>
                      <div className="mt-1.5 h-1.5 w-full rounded-full bg-white/[0.06] overflow-hidden">
                        <div className="h-full bg-emerald-500" style={{ width: `${isoPct}%` }} />
                      </div>
                    </div>
                  </>
                );
              })()}
            </div>
          </div>
          <button
            type="button"
            onClick={() => onNavigate('compliance')}
            className="mt-5 inline-flex items-center gap-1 text-xs font-medium text-sky-400 hover:text-sky-300"
          >
            <span>Open evidence &amp; gaps</span>
            <ArrowUpRight className="w-3.5 h-3.5" aria-hidden="true" />
          </button>
        </div>

        {/* 6. AI Activity */}
        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5 lg:col-span-3 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>AI activity (24h)</span>
              <Activity className="w-4 h-4 text-sky-400" aria-hidden="true" />
            </div>
            <div className="mt-3 space-y-3">
              <div>
                <p className="text-xs text-slate-400">Model requests</p>
                <p className="font-mono text-xl font-semibold text-white tabular-nums">
                  {metrics.dailyRequests.toLocaleString()}
                </p>
              </div>
              <div>
                <p className="text-xs text-slate-400">MCP tool invocations</p>
                <p className="font-mono text-xl font-semibold text-white tabular-nums">
                  {metrics.dailyToolCalls.toLocaleString()}
                </p>
              </div>
              <div>
                <p className="text-xs text-slate-400">Blocked / redacted events</p>
                <p className="font-mono text-xl font-semibold text-amber-400 tabular-nums">
                  {metrics.blockedOrRedactedEvents.toLocaleString()}
                </p>
              </div>
            </div>
          </div>
          <button
            type="button"
            onClick={() => onNavigate('policy')}
            className="mt-4 inline-flex items-center gap-1 text-xs font-medium text-sky-400 hover:text-sky-300"
          >
            <span>Inspect policy gateway</span>
            <ArrowUpRight className="w-3.5 h-3.5" aria-hidden="true" />
          </button>
        </div>
      </section>

      {/* Bottom Row: 7. Top Risks & Prioritized Actions + 8. Recent Activity */}
      <section className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Top Risks */}
        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5 lg:col-span-7">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="font-display text-base font-semibold text-white">
                Top risks &amp; prioritized actions
              </h2>
              <p className="text-xs text-slate-400">
                Highest-risk agents mapped to affected business services
              </p>
            </div>
            <button
              type="button"
              onClick={() => onNavigate('findings')}
              className="text-xs font-medium text-sky-400 hover:text-sky-300"
            >
              View all findings →
            </button>
          </div>

          <div className="mt-4 overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-white/[0.08] text-slate-400">
                  <th className="py-2.5 pr-4 font-medium">Agent</th>
                  <th className="py-2.5 pr-4 font-medium">Business service</th>
                  <th className="py-2.5 pr-4 font-medium">Reachable data</th>
                  <th className="py-2.5 pr-4 font-medium">Severity</th>
                  <th className="py-2.5 text-right font-medium">Score</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.06]">
                {topRisks.map((agent) => {
                  const dsNames = dataSources
                    .filter((d) => agent.dataSources.includes(d.id))
                    .map((d) => d.name)
                    .join(', ');
                  return (
                    <tr
                      key={agent.id}
                      className="hover:bg-white/[0.03] transition-colors"
                    >
                      <td className="py-3 pr-4">
                        <button
                          type="button"
                          onClick={() => onSelectAgent(agent.id)}
                          className="font-medium text-white hover:text-sky-400 text-left"
                        >
                          {agent.name}
                        </button>
                        <p className="text-[11px] text-slate-400">
                          {agent.type} · {agent.owner}
                        </p>
                      </td>
                      <td className="py-3 pr-4 text-slate-300">{agent.businessService}</td>
                      <td className="py-3 pr-4 text-slate-300">{dsNames}</td>
                      <td className="py-3 pr-4">
                        <RiskLabel level={agent.riskLevel} />
                      </td>
                      <td className="py-3 text-right font-mono font-semibold text-white tabular-nums">
                        {agent.riskScore}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Recent Activity */}
        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5 lg:col-span-5">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="font-display text-base font-semibold text-white">Recent activity</h2>
              <p className="text-xs text-slate-400">
                New agents, policy violations, and remediation updates
              </p>
            </div>
          </div>

          <ul className="mt-4 divide-y divide-white/[0.06]">
            {activity.map((item) => (
              <li key={item.id} className="py-3 first:pt-1 last:pb-0">
                <div className="flex items-center justify-between gap-2">
                  <RiskLabel level={item.severity} />
                  <span className="font-mono text-[11px] text-slate-500 tabular-nums">
                    {item.timestamp}
                  </span>
                </div>
                <p className="mt-1.5 text-xs font-medium text-white">{item.title}</p>
                <p className="mt-0.5 text-xs text-slate-400">{item.detail}</p>
              </li>
            ))}
          </ul>
        </div>
      </section>
    </div>
  );
};
