import React, { useState } from 'react';
import {
  Activity,
  Bot,
  Compass,
  FileCheck2,
  GitBranch,
  History,
  KeyRound,
  Layers,
  LayoutDashboard,
  Menu,
  Plug,
  ShieldAlert,
  SlidersHorizontal,
  UserCheck,
  X,
} from 'lucide-react';
import type { AuthSessionState, ScreenId, Tenant } from '../types/security';

interface DashboardShellProps {
  tenants: Tenant[];
  selectedTenantId: string;
  onSelectTenant: (tenantId: string) => void;
  activeScreen: ScreenId;
  onNavigate: (screen: ScreenId) => void;
  onExitToLanding: () => void;
  onStartTour: () => void;
  onOpenAuthModal: () => void;
  authSession: AuthSessionState | null;
  tourActive: boolean;
  breadcrumbDetail?: string;
  openFindingsCount: number;
  children: React.ReactNode;
}

const NAV_ITEMS: {
  id: ScreenId;
  label: string;
  icon: React.FC<{ className?: string }>;
  requiredPermission?: string;
}[] = [
  { id: 'overview', label: 'Risk Command Center', icon: LayoutDashboard },
  { id: 'all-in-one', label: 'All-in-One Hub', icon: Layers },
  { id: 'inventory', label: 'Agent Inventory', icon: Bot },
  { id: 'exposure', label: 'Exposure Paths', icon: GitBranch },
  { id: 'findings', label: 'Findings', icon: ShieldAlert },
  { id: 'compliance', label: 'Compliance', icon: FileCheck2, requiredPermission: 'compliance:read' },
  { id: 'policy', label: 'Policy', icon: SlidersHorizontal, requiredPermission: 'policies:read' },
  { id: 'connectors', label: 'Connectors', icon: Plug, requiredPermission: 'connectors:read' },
  { id: 'enterprise', label: 'SSO & Hardening', icon: KeyRound, requiredPermission: 'tenant:read' },
  { id: 'audit', label: 'Audit Log', icon: History, requiredPermission: 'audit:read' },
];

export const DashboardShell: React.FC<DashboardShellProps> = ({
  tenants,
  selectedTenantId,
  onSelectTenant,
  activeScreen,
  onNavigate,
  onExitToLanding,
  onStartTour,
  onOpenAuthModal,
  authSession,
  tourActive,
  breadcrumbDetail,
  openFindingsCount,
  children,
}) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const currentTenant = tenants.find((t) => t.id === selectedTenantId) ?? tenants[0];
  const allowedTenants = authSession?.memberships?.length
    ? tenants.filter((t) => authSession.memberships.some((m) => m.tenantId === t.id))
    : tenants;

  const visibleNavItems = NAV_ITEMS.filter(
    (item) =>
      !item.requiredPermission ||
      !authSession ||
      authSession.permissions.includes(item.requiredPermission)
  );

  const screenLabel =
    activeScreen === 'agent-detail'
      ? 'Agent Detail'
      : NAV_ITEMS.find((n) => n.id === activeScreen)?.label ?? 'Risk Command Center';

  const renderSidebarContent = () => (
    <div className="flex h-full flex-col justify-between bg-[#0B0E14] border-r border-white/[0.08] px-3 py-5">
      <div>
        <div className="px-3 pb-5 border-b border-white/[0.08]">
          <button
            type="button"
            onClick={onExitToLanding}
            className="text-left font-display text-base font-semibold tracking-tight text-white hover:text-sky-400 transition-colors"
          >
            Eyes of Agent
          </button>
          <p className="mt-1 text-[11px] text-slate-400">AI Risk Control Plane</p>
        </div>

        <div className="mt-4 px-2">
          <label
            htmlFor="tenant-switcher"
            className="block text-[11px] font-medium text-slate-400"
          >
            Tenant ({allowedTenants.length} authorized)
          </label>
          <select
            id="tenant-switcher"
            value={selectedTenantId}
            onChange={(e) => onSelectTenant(e.target.value)}
            className="mt-1.5 w-full rounded-lg border border-white/15 bg-[#11151D] px-2.5 py-2 text-xs font-medium text-white focus:border-sky-500 focus:outline-none"
          >
            {allowedTenants.map((tenant) => (
              <option key={tenant.id} value={tenant.id}>
                {tenant.name}
              </option>
            ))}
          </select>
        </div>

        <nav aria-label="Console navigation" className="mt-5 space-y-1">
          {visibleNavItems.map((item) => {
            const Icon = item.icon;
            const isActive =
              activeScreen === item.id ||
              (activeScreen === 'agent-detail' && item.id === 'inventory');
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => {
                  onNavigate(item.id);
                  setMobileMenuOpen(false);
                }}
                aria-current={isActive ? 'page' : undefined}
                className={`flex w-full items-center justify-between rounded-lg px-3 py-2.5 text-xs font-medium transition-colors ${
                  isActive
                    ? 'bg-sky-500/15 text-sky-300'
                    : 'text-slate-400 hover:bg-white/[0.04] hover:text-slate-200'
                }`}
              >
                <span className="flex items-center gap-2.5 truncate">
                  <Icon className="w-4 h-4 shrink-0" aria-hidden="true" />
                  <span className="truncate">{item.label}</span>
                </span>
                {item.id === 'findings' && openFindingsCount > 0 && (
                  <span className="font-mono text-[11px] text-rose-400 tabular-nums">
                    {openFindingsCount}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      <div className="space-y-2 border-t border-white/[0.08] pt-4 px-2">
        {authSession && (
          <div className="rounded-lg border border-white/[0.08] bg-[#11151D] p-3">
            <div className="flex items-center justify-between gap-2 text-xs font-medium text-white">
              <span className="flex items-center gap-1.5 truncate">
                <UserCheck className="w-3.5 h-3.5 text-sky-400 shrink-0" aria-hidden="true" />
                <span className="truncate">{authSession.user.email}</span>
              </span>
            </div>
            <p className="mt-1 font-mono text-[11px] text-slate-400">
              Role: {authSession.role} · {authSession.mfaVerified ? 'MFA verified' : 'Standard'}
            </p>
            <button
              type="button"
              onClick={onOpenAuthModal}
              className="mt-2.5 w-full rounded-md border border-white/15 bg-[#090B10] px-2.5 py-1.5 text-[11px] font-medium text-sky-300 hover:border-sky-500/50"
            >
              Switch SSO role / MFA
            </button>
          </div>
        )}

        <div className="rounded-lg border border-white/[0.08] bg-[#11151D] p-3">
          <div className="flex items-center gap-2 text-xs font-medium text-slate-200">
            <Activity className="w-3.5 h-3.5 text-emerald-400 shrink-0" aria-hidden="true" />
            <span>Zero prompt retention</span>
          </div>
          <p className="mt-1 text-[11px] text-slate-400">
            {currentTenant.domain} · Row-level isolated
          </p>
        </div>

        <button
          type="button"
          onClick={onExitToLanding}
          className="w-full rounded-lg border border-white/10 px-3 py-2 text-xs font-medium text-slate-300 hover:bg-white/[0.04] hover:text-white transition-colors"
        >
          Back to product overview
        </button>
      </div>
    </div>
  );

  return (
    <div className="flex min-h-screen bg-[#090B10] text-slate-100">
      {/* Desktop Sidebar */}
      <aside className="hidden w-64 shrink-0 lg:block">{renderSidebarContent()}</aside>

      {/* Mobile Sidebar Drawer */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 flex lg:hidden">
          <div
            className="fixed inset-0 bg-black/70"
            onClick={() => setMobileMenuOpen(false)}
            aria-hidden="true"
          />
          <div className="relative z-10 w-64 max-w-[80vw]">
            <button
              type="button"
              aria-label="Close navigation menu"
              onClick={() => setMobileMenuOpen(false)}
              className="absolute top-3 right-3 rounded-md p-1.5 text-slate-400 hover:text-white"
            >
              <X className="w-4 h-4" />
            </button>
            {renderSidebarContent()}
          </div>
        </div>
      )}

      {/* Main Content Area */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex items-center justify-between gap-4 border-b border-white/[0.08] bg-[#090B10]/95 px-5 py-3.5 backdrop-blur-md">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              aria-label="Open navigation menu"
              onClick={() => setMobileMenuOpen(true)}
              className="rounded-lg border border-white/10 p-2 text-slate-300 hover:text-white lg:hidden"
            >
              <Menu className="w-4 h-4" />
            </button>
            <nav aria-label="Breadcrumb" className="flex items-center gap-2 text-xs min-w-0">
              <span className="text-slate-400 truncate hidden sm:inline">
                {currentTenant.name}
              </span>
              <span className="text-slate-600 hidden sm:inline" aria-hidden="true">
                /
              </span>
              <span className="font-medium text-white truncate">{screenLabel}</span>
              {breadcrumbDetail && (
                <>
                  <span className="text-slate-600" aria-hidden="true">
                    /
                  </span>
                  <span className="font-medium text-sky-400 truncate">{breadcrumbDetail}</span>
                </>
              )}
            </nav>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={onOpenAuthModal}
              className="hidden sm:inline-flex items-center gap-1.5 rounded-lg border border-white/15 bg-[#11151D] px-3 py-2 text-xs font-medium text-slate-200 hover:border-white/30 whitespace-nowrap"
            >
              <UserCheck className="w-3.5 h-3.5 text-sky-400" aria-hidden="true" />
              <span>{authSession ? authSession.role : 'Sign in'}</span>
            </button>

            <button
              type="button"
              onClick={onStartTour}
              className={`inline-flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 ${
                tourActive
                  ? 'border border-sky-500/50 bg-sky-500/15 text-sky-300'
                  : 'bg-sky-500 text-slate-950 hover:bg-sky-400'
              }`}
            >
              <Compass className="w-3.5 h-3.5" aria-hidden="true" />
              <span>{tourActive ? 'Tour Active' : 'Start Guided Demo'}</span>
            </button>
          </div>
        </header>

        <main className="flex-1 p-5 lg:p-7">{children}</main>
      </div>
    </div>
  );
};
