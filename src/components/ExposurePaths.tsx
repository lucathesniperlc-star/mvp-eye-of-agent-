import React, { useState } from 'react';
import { ArrowRight, Bot, Database, Globe2, KeyRound, Server, ShieldAlert } from 'lucide-react';
import type {
  Agent,
  DataSource,
  ExposurePathState,
  GraphTraversalPath,
  McpServer,
} from '../types/security';
import { buildExposurePathForAgent } from '../utils/riskEngine';
import { RiskLabel } from './RiskIndicator';

interface ExposurePathsProps {
  tenantId: string;
  agents: Agent[];
  mcpServers: McpServer[];
  dataSources: DataSource[];
  graphPaths?: GraphTraversalPath[];
  selectedAgentId: string;
  onSelectAgentId: (agentId: string) => void;
  onOpenFindingsForAgent: () => void;
}

const STAGE_META = {
  agent: { label: '01 · AI Agent', icon: Bot, ring: 'border-sky-500/40' },
  identity: { label: '02 · Service Identity', icon: KeyRound, ring: 'border-orange-500/40' },
  mcp: { label: '03 · MCP & Tools', icon: Server, ring: 'border-amber-500/40' },
  data: { label: '04 · Sensitive Data', icon: Database, ring: 'border-rose-500/40' },
  egress: { label: '05 · External Destination', icon: Globe2, ring: 'border-purple-500/40' },
};

const PATH_STATES: Array<'all' | ExposurePathState> = [
  'all',
  'potential',
  'observed',
  'active',
  'anomalous',
  'remediated',
];

function pathStateColor(state?: ExposurePathState): string {
  switch (state) {
    case 'anomalous':
      return 'border-rose-500/40 bg-rose-500/10 text-rose-300';
    case 'active':
      return 'border-amber-500/40 bg-amber-500/10 text-amber-300';
    case 'observed':
      return 'border-sky-500/40 bg-sky-500/10 text-sky-300';
    case 'remediated':
      return 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300';
    default:
      return 'border-white/15 bg-white/[0.04] text-slate-300';
  }
}

export const ExposurePaths: React.FC<ExposurePathsProps> = ({
  tenantId,
  agents,
  mcpServers,
  dataSources,
  graphPaths = [],
  selectedAgentId,
  onSelectAgentId,
  onOpenFindingsForAgent,
}) => {
  const tenantAgents = agents.filter((a) => a.tenantId === tenantId);
  const activeAgent =
    tenantAgents.find((a) => a.id === selectedAgentId) ?? tenantAgents[0];

  const [selectedStage, setSelectedStage] = useState<'agent' | 'identity' | 'mcp' | 'data' | 'egress'>('data');
  const [pathStateFilter, setPathStateFilter] = useState<'all' | ExposurePathState>('all');

  if (!activeAgent) {
    return (
      <div className="mx-auto max-w-7xl rounded-xl border border-white/[0.08] bg-[#11151D] p-12 text-center">
        <p className="text-sm text-slate-300">No exposure paths discovered for this tenant.</p>
      </div>
    );
  }

  const chain = buildExposurePathForAgent(activeAgent, mcpServers, dataSources);
  const agentGraphPaths = graphPaths.filter((p) => p.agentId === activeAgent.id);
  const filteredGraphPaths =
    pathStateFilter === 'all'
      ? agentGraphPaths
      : agentGraphPaths.filter((p) => (p.pathState ?? 'potential') === pathStateFilter);

  const primaryGraphPath = agentGraphPaths[0];
  const egressNode = primaryGraphPath?.externalDestination
    ? {
        id: `node-egress-${activeAgent.id}`,
        stage: 'egress' as const,
        label: primaryGraphPath.externalDestination.label,
        sublabel: `${primaryGraphPath.externalDestination.category.replace(/_/g, ' ')}`,
        risk: primaryGraphPath.externalDestination.egressRisk,
      }
    : chain.externalDestination;

  const displayNodes = egressNode ? [...chain.nodes, egressNode] : chain.nodes;
  const activeNode = displayNodes.find((n) => n.stage === selectedStage) ?? chain.nodes[3];

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-semibold tracking-tight text-white">
            Exposure Paths
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            5-hop blast-radius graph from autonomous agents through service credentials and sensitive data to external destinations
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <label htmlFor="exposure-state-select" className="text-xs text-slate-400">
              Path state:
            </label>
            <select
              id="exposure-state-select"
              value={pathStateFilter}
              onChange={(e) => setPathStateFilter(e.target.value as 'all' | ExposurePathState)}
              className="rounded-lg border border-white/15 bg-[#11151D] px-2.5 py-2 text-xs font-medium text-white focus:border-sky-500 focus:outline-none"
            >
              {PATH_STATES.map((st) => (
                <option key={st} value={st}>
                  {st === 'all' ? 'All states' : st}
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-center gap-2">
            <label htmlFor="exposure-agent-select" className="text-xs text-slate-400">
              Focus path:
            </label>
            <select
              id="exposure-agent-select"
              value={activeAgent.id}
              onChange={(e) => onSelectAgentId(e.target.value)}
              className="rounded-lg border border-white/15 bg-[#11151D] px-3 py-2 text-xs font-medium text-white focus:border-sky-500 focus:outline-none"
            >
              {tenantAgents.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name} (Risk {a.riskScore})
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Interactive 5-Hop Graph Canvas */}
      <div
        data-testid="exposure-graph-canvas"
        className="rounded-xl border border-white/[0.08] bg-[#0C0F16] p-6"
      >
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-white/[0.08] pb-4">
          <div className="flex flex-wrap items-center gap-3">
            <h2 className="font-display text-base font-semibold text-white">
              {chain.agentName} Exposure Chain ({displayNodes.length} hops)
            </h2>
            <RiskLabel level={chain.riskLevel} />
            {primaryGraphPath?.pathState && (
              <span
                className={`rounded border px-2 py-0.5 font-mono text-[11px] uppercase ${pathStateColor(primaryGraphPath.pathState)}`}
              >
                state: {primaryGraphPath.pathState}
              </span>
            )}
          </div>
          <div className="font-mono text-xs text-slate-400 tabular-nums">
            Composite Risk Score: <span className="font-semibold text-white">{chain.riskScore}</span> / 100
          </div>
        </div>

        {/* Visual Node-Link Flow */}
        <div
          className={`mt-8 grid grid-cols-1 gap-3 ${
            displayNodes.length >= 5 ? 'lg:grid-cols-5' : 'lg:grid-cols-4'
          } lg:items-stretch`}
        >
          {displayNodes.map((node, index) => {
            const meta = STAGE_META[node.stage];
            const Icon = meta.icon;
            const isSelected = selectedStage === node.stage;
            return (
              <button
                key={node.id}
                type="button"
                onClick={() => setSelectedStage(node.stage)}
                className={`flex h-full flex-col justify-between rounded-xl border p-4 text-left transition-colors min-h-[152px] ${
                  isSelected
                    ? 'border-sky-400 bg-sky-500/10'
                    : `bg-[#11151D] hover:border-white/25 ${meta.ring}`
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[11px] text-slate-400">{meta.label}</span>
                  <div className="flex items-center gap-1">
                    {index < displayNodes.length - 1 && (
                      <ArrowRight className="hidden lg:inline w-3.5 h-3.5 text-sky-400/70" aria-hidden="true" />
                    )}
                    <Icon className="w-4 h-4 text-slate-300 shrink-0" aria-hidden="true" />
                  </div>
                </div>
                <div className="mt-3">
                  <p className="font-display text-sm font-semibold text-white break-words">
                    {node.label}
                  </p>
                  <p className="mt-1 text-[11px] text-slate-400 line-clamp-2">{node.sublabel}</p>
                </div>
                <div className="mt-3">
                  <RiskLabel level={node.risk} />
                </div>
              </button>
            );
          })}
        </div>

        {/* Selected Node Deep Inspection Bar */}
        <div className="mt-8 rounded-xl border border-white/[0.08] bg-[#11151D] p-5">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <p className="font-mono text-xs text-sky-400">
                Selected Hop · {STAGE_META[activeNode.stage].label}
              </p>
              <h3 className="mt-1 font-display text-lg font-semibold text-white">
                {activeNode.label}
              </h3>
              <p className="mt-1 text-xs text-slate-300">{activeNode.sublabel}</p>
            </div>
            <button
              type="button"
              onClick={onOpenFindingsForAgent}
              className="inline-flex items-center gap-1.5 rounded-lg bg-sky-500 px-3.5 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400"
            >
              <ShieldAlert className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Remediate exposure finding</span>
            </button>
          </div>

          <div className="mt-4 grid grid-cols-1 gap-4 border-t border-white/[0.08] pt-4 md:grid-cols-2">
            <div>
              <p className="text-xs font-medium text-slate-400">Effective permissions along path</p>
              <p className="mt-1.5 font-mono text-xs text-slate-200">
                {chain.permissions.join(' · ')}
              </p>
            </div>
            <div>
              <p className="text-xs font-medium text-slate-400">Executable MCP tools</p>
              <p className="mt-1.5 font-mono text-xs text-slate-200">{chain.tools.join(' · ')}</p>
            </div>
          </div>
        </div>

        {/* Graph Engine Multi-Hop Traversal Output */}
        {filteredGraphPaths.length > 0 && (
          <div className="mt-6 rounded-xl border border-white/[0.08] bg-[#11151D] p-5">
            <div className="flex items-center justify-between gap-2">
              <h3 className="font-display text-sm font-semibold text-white">
                Graph traversal proof ({filteredGraphPaths.length} verified path
                {filteredGraphPaths.length === 1 ? '' : 's'} to sensitive data)
              </h3>
              <span className="font-mono text-[11px] text-slate-400">
                Tenant-scoped BFS · Edge-verified
              </span>
            </div>
            <div className="mt-3 space-y-2.5">
              {filteredGraphPaths.map((gp) => (
                <div
                  key={gp.pathId}
                  className="rounded-lg border border-white/[0.06] bg-[#090B10] px-3.5 py-2.5"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2 text-[11px]">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-sky-400">
                        Target: {gp.targetDataLabel} ({gp.targetSensitivity.toUpperCase()})
                      </span>
                      {gp.pathState && (
                        <span
                          className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase ${pathStateColor(gp.pathState)}`}
                        >
                          {gp.pathState}
                        </span>
                      )}
                      {gp.externalDestination && (
                        <span className="font-mono text-purple-300">
                          Egress → {gp.externalDestination.label}
                        </span>
                      )}
                    </div>
                    <span className="font-mono text-slate-400 tabular-nums">
                      {gp.hopCount} hops
                    </span>
                  </div>
                  <p className="mt-1.5 font-mono text-[11px] leading-relaxed text-slate-200">
                    {gp.steps
                      .map((s) => (s.edgeFromPrev ? `-[${s.edgeFromPrev}]→ ${s.label}` : s.label))
                      .join(' ')}
                    {gp.externalDestination ? ` -[egress]→ ${gp.externalDestination.label}` : ''}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Quick Switcher Cards for Other High-Risk Paths */}
      <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5">
        <h2 className="font-display text-sm font-semibold text-white">
          All mapped exposure chains ({tenantAgents.length})
        </h2>
        <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-3">
          {tenantAgents.map((agent) => {
            const c = buildExposurePathForAgent(agent, mcpServers, dataSources);
            const active = agent.id === activeAgent.id;
            const gp = graphPaths.find((p) => p.agentId === agent.id);
            return (
              <button
                key={agent.id}
                type="button"
                onClick={() => onSelectAgentId(agent.id)}
                className={`rounded-lg border p-3.5 text-left transition-colors ${
                  active
                    ? 'border-sky-500/60 bg-sky-500/10'
                    : 'border-white/[0.08] bg-[#0B0E14] hover:border-white/20'
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-semibold text-white">{c.agentName}</span>
                  <div className="flex items-center gap-2">
                    {gp?.pathState && (
                      <span className="font-mono text-[10px] uppercase text-slate-400">
                        {gp.pathState}
                      </span>
                    )}
                    <span className="font-mono text-xs text-slate-300 tabular-nums">
                      Score {c.riskScore}
                    </span>
                  </div>
                </div>
                <p className="mt-1.5 font-mono text-[11px] text-slate-400 truncate">
                  {c.nodes.map((n) => n.label).join(' → ')}
                  {gp?.externalDestination ? ` → ${gp.externalDestination.label}` : ''}
                </p>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
};
