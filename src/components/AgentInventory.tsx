import React, { useState } from 'react';
import { Plus, Search, X } from 'lucide-react';
import type { Agent, AgentType, DataSource, RiskLevel } from '../types/security';
import { filterAgents } from '../utils/riskEngine';
import { RiskLabel } from './RiskIndicator';

interface AgentInventoryProps {
  tenantId: string;
  totalTenantDiscoveredCount: number;
  agents: Agent[];
  dataSources: DataSource[];
  canManageAgents?: boolean;
  onCreateAgent?: (payload: {
    name: string;
    owner?: string;
    ownerTeam?: string;
    type?: AgentType;
    identity?: string;
    businessService?: string;
    tools?: string[];
    permissions?: string[];
    dataSources?: string[];
  }) => Promise<Agent | null>;
  onSelectAgent: (agentId: string) => void;
}

export const AgentInventory: React.FC<AgentInventoryProps> = ({
  tenantId,
  totalTenantDiscoveredCount,
  agents,
  dataSources,
  canManageAgents = true,
  onCreateAgent,
  onSelectAgent,
}) => {
  const [query, setQuery] = useState('');
  const [riskFilter, setRiskFilter] = useState<RiskLevel | 'all'>('all');
  const [typeFilter, setTypeFilter] = useState<AgentType | 'all'>('all');

  const [createOpen, setCreateOpen] = useState(false);
  const [newName, setNewName] = useState('');
  const [newOwner, setNewOwner] = useState('ai-platform@northwind.com');
  const [newTeam, setNewTeam] = useState('AI Platform');
  const [newType, setNewType] = useState<AgentType>('Internal agent');
  const [newService, setNewService] = useState('Enterprise Operations');
  const [newTools, setNewTools] = useState('read_records, send_email');
  const [newPerms, setNewPerms] = useState('workspace:read, crm:contacts.read');
  const [newDataSource, setNewDataSource] = useState(dataSources[0]?.id ?? 'ds_snowflake');
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState('');
  const [createNotice, setCreateNotice] = useState('');

  const filtered = filterAgents(agents, tenantId, {
    query,
    risk: riskFilter,
    type: typeFilter,
  });

  const resetFilters = () => {
    setQuery('');
    setRiskFilter('all');
    setTypeFilter('all');
  };

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!onCreateAgent) return;
    if (!newName.trim()) {
      setCreateError('Agent name is required.');
      return;
    }
    setCreateError('');
    setCreateNotice('');
    setCreating(true);
    try {
      const tools = newTools
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const permissions = newPerms
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const created = await onCreateAgent({
        name: newName.trim(),
        owner: newOwner.trim() || 'unassigned',
        ownerTeam: newTeam.trim() || 'Unassigned',
        type: newType,
        businessService: newService.trim() || 'Enterprise Operations',
        tools: tools.length ? tools : ['read_records'],
        permissions: permissions.length ? permissions : ['workspace:read'],
        dataSources: newDataSource ? [newDataSource] : undefined,
      });
      setNewName('');
      setCreateOpen(false);
      if (created) {
        setCreateNotice(
          `Registered "${created.name}" (${created.identity}) — 6-factor score ${created.riskScore} (${created.riskLevel}).`
        );
      }
    } catch (err) {
      setCreateError((err as Error).message || 'Unable to register agent.');
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-semibold tracking-tight text-white">
            AI Agent Inventory
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Showing {filtered.length} profiled agents out of {totalTenantDiscoveredCount} discovered
            across cloud and identity telemetry
          </p>
        </div>

        {onCreateAgent && (
          <button
            type="button"
            disabled={!canManageAgents}
            onClick={() => {
              setCreateError('');
              setCreateOpen((prev) => !prev);
            }}
            className="inline-flex items-center gap-2 rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50 whitespace-nowrap shrink-0"
          >
            {createOpen ? (
              <>
                <X className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Close form</span>
              </>
            ) : (
              <>
                <Plus className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Register agent</span>
              </>
            )}
          </button>
        )}
      </div>

      {createNotice && (
        <div
          role="status"
          className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-2.5 text-xs text-emerald-300"
        >
          {createNotice}
        </div>
      )}

      {createOpen && onCreateAgent && (
        <form
          onSubmit={handleCreateSubmit}
          className="rounded-xl border border-sky-500/30 bg-[#11151D] p-5 space-y-4"
        >
          <div className="flex items-center justify-between">
            <div>
              <h2 className="font-display text-base font-semibold text-white">
                Register AI agent into security graph
              </h2>
              <p className="text-xs text-slate-400">
                Creates agent entity, binds service identity and data access edges, and computes 6-factor risk posture
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
            <div>
              <label htmlFor="new-agent-name" className="block text-[11px] text-slate-400">
                Agent name
              </label>
              <input
                id="new-agent-name"
                type="text"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="Treasury Reconciliation Bot"
                className="mt-1 w-full rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 text-xs text-white placeholder:text-slate-500 focus:border-sky-500 focus:outline-none"
              />
            </div>
            <div>
              <label htmlFor="new-agent-owner" className="block text-[11px] text-slate-400">
                Owner email
              </label>
              <input
                id="new-agent-owner"
                type="text"
                value={newOwner}
                onChange={(e) => setNewOwner(e.target.value)}
                className="mt-1 w-full rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 text-xs text-white focus:border-sky-500 focus:outline-none"
              />
            </div>
            <div>
              <label htmlFor="new-agent-team" className="block text-[11px] text-slate-400">
                Owner team
              </label>
              <input
                id="new-agent-team"
                type="text"
                value={newTeam}
                onChange={(e) => setNewTeam(e.target.value)}
                className="mt-1 w-full rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 text-xs text-white focus:border-sky-500 focus:outline-none"
              />
            </div>
            <div>
              <label htmlFor="new-agent-type" className="block text-[11px] text-slate-400">
                Agent classification
              </label>
              <select
                id="new-agent-type"
                value={newType}
                onChange={(e) => setNewType(e.target.value as AgentType)}
                className="mt-1 w-full rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 text-xs text-white focus:border-sky-500 focus:outline-none"
              >
                <option value="Internal agent">Internal agent</option>
                <option value="Customer-facing">Customer-facing</option>
                <option value="Shadow AI">Shadow AI</option>
                <option value="Unowned">Unowned</option>
              </select>
            </div>

            <div>
              <label htmlFor="new-agent-service" className="block text-[11px] text-slate-400">
                Business service
              </label>
              <input
                id="new-agent-service"
                type="text"
                value={newService}
                onChange={(e) => setNewService(e.target.value)}
                className="mt-1 w-full rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 text-xs text-white focus:border-sky-500 focus:outline-none"
              />
            </div>
            <div>
              <label htmlFor="new-agent-ds" className="block text-[11px] text-slate-400">
                Reachable data store
              </label>
              <select
                id="new-agent-ds"
                value={newDataSource}
                onChange={(e) => setNewDataSource(e.target.value)}
                className="mt-1 w-full rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 text-xs text-white focus:border-sky-500 focus:outline-none"
              >
                {dataSources.map((ds) => (
                  <option key={ds.id} value={ds.id}>
                    {ds.name} ({ds.classification})
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label htmlFor="new-agent-tools" className="block text-[11px] text-slate-400">
                MCP tools (comma-separated)
              </label>
              <input
                id="new-agent-tools"
                type="text"
                value={newTools}
                onChange={(e) => setNewTools(e.target.value)}
                className="mt-1 w-full rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 font-mono text-xs text-white focus:border-sky-500 focus:outline-none"
              />
            </div>
            <div>
              <label htmlFor="new-agent-perms" className="block text-[11px] text-slate-400">
                IAM permissions
              </label>
              <input
                id="new-agent-perms"
                type="text"
                value={newPerms}
                onChange={(e) => setNewPerms(e.target.value)}
                className="mt-1 w-full rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 font-mono text-xs text-white focus:border-sky-500 focus:outline-none"
              />
            </div>
          </div>

          {createError && (
            <p role="alert" className="text-xs text-rose-400">
              {createError}
            </p>
          )}

          <div className="flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={() => setCreateOpen(false)}
              className="rounded-lg border border-white/15 px-3.5 py-2 text-xs font-medium text-slate-300 hover:text-white"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={creating}
              className="rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50"
            >
              {creating ? 'Registering...' : 'Register & score agent'}
            </button>
          </div>
        </form>
      )}

      {/* Filter Toolbar */}
      <div className="flex flex-wrap items-center gap-3 rounded-xl border border-white/[0.08] bg-[#11151D] p-4">
        <div className="relative flex-1 min-w-[220px]">
          <Search
            className="pointer-events-none absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-slate-400"
            aria-hidden="true"
          />
          <label htmlFor="agent-search-input" className="sr-only">
            Search agents by name, owner, tool, or data source
          </label>
          <input
            id="agent-search-input"
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search agents, owners, identities, tools, or data..."
            className="w-full rounded-lg border border-white/15 bg-[#090B10] py-2 pr-3 pl-9 text-xs text-white placeholder:text-slate-500 focus:border-sky-500 focus:outline-none"
          />
        </div>

        <div className="flex items-center gap-2">
          <label htmlFor="risk-filter-select" className="text-xs text-slate-400">
            Risk
          </label>
          <select
            id="risk-filter-select"
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value as RiskLevel | 'all')}
            className="rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 text-xs text-white focus:border-sky-500 focus:outline-none"
          >
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <div className="flex items-center gap-2">
          <label htmlFor="type-filter-select" className="text-xs text-slate-400">
            Type
          </label>
          <select
            id="type-filter-select"
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value as AgentType | 'all')}
            className="rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 text-xs text-white focus:border-sky-500 focus:outline-none"
          >
            <option value="all">All types</option>
            <option value="Internal agent">Internal agent</option>
            <option value="Customer-facing">Customer-facing</option>
            <option value="Shadow AI">Shadow AI</option>
            <option value="Unowned">Unowned</option>
          </select>
        </div>
      </div>

      {/* Inventory Table or Empty State */}
      {filtered.length === 0 ? (
        <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-12 text-center">
          <p className="font-display text-base font-semibold text-white">
            No AI agents match the current filters
          </p>
          <p className="mt-1 text-xs text-slate-400">
            Clear your search or severity filters to inspect all discovered agents.
          </p>
          <button
            type="button"
            onClick={resetFilters}
            className="mt-4 rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400"
          >
            Reset filters
          </button>
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl border border-white/[0.08] bg-[#11151D]">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-white/[0.08] bg-[#0D1017] text-slate-400">
                  <th className="px-4 py-3 font-medium">Agent</th>
                  <th className="px-4 py-3 font-medium">Owner</th>
                  <th className="px-4 py-3 font-medium">Type</th>
                  <th className="px-4 py-3 font-medium">Risk</th>
                  <th className="px-4 py-3 font-medium">Data access</th>
                  <th className="px-4 py-3 font-medium">Tools &amp; MCP</th>
                  <th className="px-4 py-3 text-right font-medium">Score</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.06]">
                {filtered.map((agent) => {
                  const dsLabels = dataSources
                    .filter((ds) => agent.dataSources.includes(ds.id))
                    .map((ds) => ds.name)
                    .join(', ');
                  return (
                    <tr
                      key={agent.id}
                      className="hover:bg-white/[0.03] transition-colors"
                    >
                      <td className="px-4 py-3.5">
                        <button
                          type="button"
                          onClick={() => onSelectAgent(agent.id)}
                          className="font-medium text-white hover:text-sky-400 text-left"
                        >
                          {agent.name}
                        </button>
                        <p className="mt-0.5 font-mono text-[11px] text-slate-400">
                          {agent.identity}
                        </p>
                      </td>
                      <td className="px-4 py-3.5 text-slate-300">
                        <div>{agent.ownerTeam}</div>
                        <div className="text-[11px] text-slate-400">{agent.owner}</div>
                      </td>
                      <td className="px-4 py-3.5 text-slate-300 whitespace-nowrap">
                        {agent.type}
                      </td>
                      <td className="px-4 py-3.5">
                        <RiskLabel level={agent.riskLevel} />
                      </td>
                      <td className="px-4 py-3.5 text-slate-300 max-w-[200px]">
                        {dsLabels || 'None'}
                      </td>
                      <td className="px-4 py-3.5 font-mono text-[11px] text-slate-300">
                        {agent.tools.join(', ')}
                      </td>
                      <td className="px-4 py-3.5 text-right font-mono font-semibold text-white tabular-nums">
                        {agent.riskScore}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
