import React, { useEffect, useState } from 'react';
import {
  ArrowLeft,
  Database,
  GitBranch,
  KeyRound,
  Server,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import type {
  Agent,
  AgentStatus,
  DataSource,
  Finding,
  McpServer,
  ModelAsset,
} from '../types/security';
import { FindingStatusLabel, RiskLabel } from './RiskIndicator';

interface AgentDetailProps {
  agent: Agent;
  mcpServers: McpServer[];
  models: ModelAsset[];
  dataSources: DataSource[];
  findings: Finding[];
  canManageAgents?: boolean;
  onUpdateAgentGovernance?: (
    agentId: string,
    updates: {
      owner?: string;
      ownerTeam?: string;
      status?: AgentStatus;
      businessService?: string;
    }
  ) => Promise<Agent | null>;
  onBack: () => void;
  onViewExposurePath: (agentId: string) => void;
  onOpenFindings: () => void;
}

export const AgentDetail: React.FC<AgentDetailProps> = ({
  agent,
  mcpServers,
  models,
  dataSources,
  findings,
  canManageAgents = true,
  onUpdateAgentGovernance,
  onBack,
  onViewExposurePath,
  onOpenFindings,
}) => {
  const [ownerInput, setOwnerInput] = useState(agent.owner);
  const [ownerTeamInput, setOwnerTeamInput] = useState(agent.ownerTeam);
  const [statusInput, setStatusInput] = useState<AgentStatus>(agent.status);
  const [serviceInput, setServiceInput] = useState(agent.businessService);
  const [saving, setSaving] = useState(false);
  const [govNotice, setGovNotice] = useState('');
  const [govError, setGovError] = useState('');

  useEffect(() => {
    setOwnerInput(agent.owner);
    setOwnerTeamInput(agent.ownerTeam);
    setStatusInput(agent.status);
    setServiceInput(agent.businessService);
  }, [agent.id, agent.owner, agent.ownerTeam, agent.status, agent.businessService]);

  const connectedMcps = mcpServers.filter((m) => agent.mcpServers.includes(m.id));
  const usedModels = models.filter((m) => agent.models.includes(m.id));
  const reachableData = dataSources.filter((d) => agent.dataSources.includes(d.id));
  const agentFindings = findings.filter((f) => f.agentId === agent.id);

  const applyGovernanceUpdate = async (overrides?: { status?: AgentStatus }) => {
    if (!onUpdateAgentGovernance) return;
    setSaving(true);
    setGovNotice('');
    setGovError('');
    const targetStatus = overrides?.status ?? statusInput;
    try {
      const updated = await onUpdateAgentGovernance(agent.id, {
        owner: ownerInput,
        ownerTeam: ownerTeamInput,
        status: targetStatus,
        businessService: serviceInput,
      });
      if (updated) {
        setStatusInput(updated.status);
        setGovNotice(
          `Saved governance for ${updated.name}: status=${updated.status}, owner=${updated.owner}, recalculated risk score ${updated.riskScore} (${updated.riskLevel}).`
        );
      }
    } catch (err) {
      setGovError((err as Error).message || 'Unable to update governance.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={onBack}
            className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-[#11151D] px-3 py-2 text-xs font-medium text-slate-300 hover:text-white"
          >
            <ArrowLeft className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Back to inventory</span>
          </button>
          <div>
            <h1 className="font-display text-2xl font-semibold tracking-tight text-white">
              {agent.name}
            </h1>
            <p className="text-xs text-slate-400">
              {agent.type} · Owner: {agent.owner} ({agent.ownerTeam}) · Last seen {agent.lastSeen}
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={() => onViewExposurePath(agent.id)}
          className="inline-flex items-center gap-2 rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400"
        >
          <GitBranch className="w-3.5 h-3.5" aria-hidden="true" />
          <span>View exposure path</span>
        </button>
      </div>

      {/* Top Metadata Strip */}
      <div className="grid grid-cols-2 gap-4 rounded-xl border border-white/[0.08] bg-[#11151D] p-5 sm:grid-cols-4">
        <div>
          <p className="text-xs text-slate-400">Risk score</p>
          <div className="mt-1.5 flex items-center gap-2.5">
            <span className="font-mono text-2xl font-semibold text-white tabular-nums">
              {agent.riskScore}
            </span>
            <RiskLabel level={agent.riskLevel} />
          </div>
        </div>
        <div>
          <p className="text-xs text-slate-400">Service identity</p>
          <p className="mt-1.5 font-mono text-sm font-medium text-white truncate">
            {agent.identity}
          </p>
          <p className="text-[11px] text-slate-400 truncate">{agent.identityType}</p>
        </div>
        <div>
          <p className="text-xs text-slate-400">Business service</p>
          <p className="mt-1.5 text-sm font-medium text-white">{agent.businessService}</p>
          <p className="text-[11px] text-slate-400 font-mono tabular-nums">
            {agent.dailyCalls.toLocaleString()} calls / 24h
          </p>
        </div>
        <div>
          <p className="text-xs text-slate-400">Runtime status</p>
          <p
            className={`mt-1.5 font-mono text-sm font-medium capitalize ${
              agent.status === 'active'
                ? 'text-emerald-400'
                : agent.status === 'restricted'
                  ? 'text-amber-400'
                  : 'text-rose-400'
            }`}
          >
            {agent.status}
          </p>
          <p className="text-[11px] text-slate-400">
            {agentFindings.length} associated finding{agentFindings.length === 1 ? '' : 's'}
          </p>
        </div>
      </div>

      {/* Governance & Containment Controls */}
      {onUpdateAgentGovernance && (
        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-sky-400" aria-hidden="true" />
              <h2 className="font-display text-sm font-semibold text-white">
                Governance, ownership &amp; containment
              </h2>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                disabled={!canManageAgents || saving || agent.status === 'restricted'}
                onClick={() => applyGovernanceUpdate({ status: 'restricted' })}
                className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-xs font-medium text-amber-300 hover:bg-amber-500/20 disabled:opacity-40 whitespace-nowrap"
              >
                Restrict permissions
              </button>
              <button
                type="button"
                disabled={!canManageAgents || saving || agent.status === 'quarantined'}
                onClick={() => applyGovernanceUpdate({ status: 'quarantined' })}
                className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-1.5 text-xs font-medium text-rose-300 hover:bg-rose-500/20 disabled:opacity-40 whitespace-nowrap"
              >
                Quarantine agent
              </button>
              {agent.status !== 'active' && (
                <button
                  type="button"
                  disabled={!canManageAgents || saving}
                  onClick={() => applyGovernanceUpdate({ status: 'active' })}
                  className="rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-xs font-medium text-emerald-300 hover:bg-emerald-500/20 disabled:opacity-40 whitespace-nowrap"
                >
                  Restore active
                </button>
              )}
            </div>
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              applyGovernanceUpdate();
            }}
            className="grid grid-cols-1 gap-3 md:grid-cols-12"
          >
            <div className="md:col-span-3">
              <label htmlFor="detail-agent-owner" className="block text-[11px] text-slate-400">
                Accountable owner
              </label>
              <input
                id="detail-agent-owner"
                type="text"
                value={ownerInput}
                onChange={(e) => setOwnerInput(e.target.value)}
                disabled={!canManageAgents}
                className="mt-1 w-full rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 text-xs text-white focus:border-sky-500 focus:outline-none disabled:opacity-60"
              />
            </div>
            <div className="md:col-span-3">
              <label htmlFor="detail-agent-team" className="block text-[11px] text-slate-400">
                Owner team
              </label>
              <input
                id="detail-agent-team"
                type="text"
                value={ownerTeamInput}
                onChange={(e) => setOwnerTeamInput(e.target.value)}
                disabled={!canManageAgents}
                className="mt-1 w-full rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 text-xs text-white focus:border-sky-500 focus:outline-none disabled:opacity-60"
              />
            </div>
            <div className="md:col-span-2">
              <label htmlFor="detail-agent-status" className="block text-[11px] text-slate-400">
                Status
              </label>
              <select
                id="detail-agent-status"
                value={statusInput}
                onChange={(e) => setStatusInput(e.target.value as AgentStatus)}
                disabled={!canManageAgents}
                className="mt-1 w-full rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 text-xs text-white focus:border-sky-500 focus:outline-none disabled:opacity-60"
              >
                <option value="active">active</option>
                <option value="restricted">restricted</option>
                <option value="quarantined">quarantined</option>
              </select>
            </div>
            <div className="md:col-span-2">
              <label htmlFor="detail-agent-service" className="block text-[11px] text-slate-400">
                Business service
              </label>
              <input
                id="detail-agent-service"
                type="text"
                value={serviceInput}
                onChange={(e) => setServiceInput(e.target.value)}
                disabled={!canManageAgents}
                className="mt-1 w-full rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 text-xs text-white focus:border-sky-500 focus:outline-none disabled:opacity-60"
              />
            </div>
            <div className="md:col-span-2 flex items-end">
              <button
                type="submit"
                disabled={!canManageAgents || saving}
                className="w-full rounded-lg bg-sky-500 px-3 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50 whitespace-nowrap"
              >
                {saving ? 'Saving...' : 'Save governance'}
              </button>
            </div>
          </form>

          {govNotice && (
            <p role="status" className="text-xs text-emerald-300">
              {govNotice}
            </p>
          )}
          {govError && (
            <p role="alert" className="text-xs text-rose-400">
              {govError}
            </p>
          )}
        </div>
      )}

      {/* Permissions, Tools & MCP Servers, Models, Data Access */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5">
          <div className="flex items-center gap-2 text-sm font-semibold text-white">
            <KeyRound className="w-4 h-4 text-orange-400" aria-hidden="true" />
            <h2>Identity permissions</h2>
          </div>
          <ul className="mt-4 space-y-2">
            {agent.permissions.map((perm) => (
              <li
                key={perm}
                className="flex items-center justify-between border-b border-white/[0.06] pb-2 last:border-0 font-mono text-xs text-slate-200"
              >
                <span>{perm}</span>
                <span className="text-[11px] text-slate-400">Granted via {agent.identity}</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5">
          <div className="flex items-center gap-2 text-sm font-semibold text-white">
            <Server className="w-4 h-4 text-sky-400" aria-hidden="true" />
            <h2>MCP servers &amp; tools</h2>
          </div>
          <div className="mt-4 space-y-3">
            {connectedMcps.map((mcp) => (
              <div
                key={mcp.id}
                className="border-b border-white/[0.06] pb-3 last:border-0"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-semibold text-white">{mcp.name}</span>
                  <RiskLabel level={mcp.risk} />
                </div>
                <p className="mt-1 font-mono text-[11px] text-slate-400">
                  Transport: {mcp.transport} · Tools: {agent.tools.join(', ')}
                </p>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5">
          <div className="flex items-center gap-2 text-sm font-semibold text-white">
            <Database className="w-4 h-4 text-rose-400" aria-hidden="true" />
            <h2>Reachable data sources</h2>
          </div>
          <ul className="mt-4 divide-y divide-white/[0.06]">
            {reachableData.map((ds) => (
              <li key={ds.id} className="py-2.5 first:pt-0 last:pb-0 flex items-center justify-between gap-4">
                <div>
                  <p className="text-xs font-medium text-white">{ds.name}</p>
                  <p className="text-[11px] text-slate-400">
                    {ds.provider} · {ds.sensitivity} · {ds.recordsCount}
                  </p>
                </div>
                <RiskLabel level={ds.risk} />
              </li>
            ))}
          </ul>
        </div>

        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5">
          <div className="flex items-center gap-2 text-sm font-semibold text-white">
            <ShieldAlert className="w-4 h-4 text-amber-400" aria-hidden="true" />
            <h2>Models &amp; risk findings</h2>
          </div>
          <div className="mt-4 space-y-4">
            <div>
              <p className="text-xs text-slate-400">Foundation models</p>
              <ul className="mt-2 space-y-1.5">
                {usedModels.map((m) => (
                  <li key={m.id} className="flex items-center justify-between text-xs">
                    <span className="font-medium text-white">
                      {m.name} ({m.provider})
                    </span>
                    <span className="text-slate-400">
                      {m.sensitivity} · {m.promptRetention}
                    </span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="border-t border-white/[0.08] pt-3">
              <div className="flex items-center justify-between">
                <p className="text-xs text-slate-400">Active findings</p>
                <button
                  type="button"
                  onClick={onOpenFindings}
                  className="text-xs font-medium text-sky-400 hover:text-sky-300"
                >
                  Manage in Findings →
                </button>
              </div>
              {agentFindings.length === 0 ? (
                <p className="mt-2 text-xs text-slate-400">No open findings for this agent.</p>
              ) : (
                <ul className="mt-2 space-y-2">
                  {agentFindings.map((f) => (
                    <li key={f.id} className="text-xs">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-medium text-white">{f.title}</span>
                        <FindingStatusLabel status={f.status} />
                      </div>
                      <p className="mt-0.5 text-[11px] text-slate-400">
                        Owner: {f.owner}
                        {f.jiraTicketKey ? ` · Jira: ${f.jiraTicketKey}` : ''}
                      </p>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
