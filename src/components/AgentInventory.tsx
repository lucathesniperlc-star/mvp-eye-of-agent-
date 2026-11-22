import React, { useState } from 'react';
import { Search } from 'lucide-react';
import type { Agent, AgentType, DataSource, RiskLevel } from '../types/security';
import { filterAgents } from '../utils/riskEngine';
import { RiskLabel } from './RiskIndicator';

interface AgentInventoryProps {
  tenantId: string;
  totalTenantDiscoveredCount: number;
  agents: Agent[];
  dataSources: DataSource[];
  onSelectAgent: (agentId: string) => void;
}

export const AgentInventory: React.FC<AgentInventoryProps> = ({
  tenantId,
  totalTenantDiscoveredCount,
  agents,
  dataSources,
  onSelectAgent,
}) => {
  const [query, setQuery] = useState('');
  const [riskFilter, setRiskFilter] = useState<RiskLevel | 'all'>('all');
  const [typeFilter, setTypeFilter] = useState<AgentType | 'all'>('all');

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
      </div>

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
