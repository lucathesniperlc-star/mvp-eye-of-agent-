import React, { useState } from 'react';
import {
  ArrowRight,
  CheckCircle2,
  Database,
  Eye,
  KeyRound,
  Lock,
  Mail,
  Server,
  Shield,
  ShieldCheck,
  X,
} from 'lucide-react';

interface LandingPageProps {
  onLaunchDemo: (startTour?: boolean) => void;
}

const PREVIEW_NODES = [
  {
    id: 'agent',
    stage: 'AI Agent',
    title: 'Finance Copilot',
    detail: 'Owner: finance-ops@northwind.com · 4,820 calls/day',
    risk: 'Risk Score 82 · High',
    icon: Eye,
    accent: 'text-amber-400',
  },
  {
    id: 'identity',
    stage: 'Service Identity',
    title: 'svc-finance-copilot',
    detail: 'Entra ID Service Principal · AWS IAM Role',
    risk: 's3:GetObject · erp:PayrollExport',
    icon: KeyRound,
    accent: 'text-orange-400',
  },
  {
    id: 'mcp',
    stage: 'MCP Server',
    title: 'finance-mcp',
    detail: 'Tools: query_erp, export_payroll, file_search',
    risk: 'Unscoped bulk export enabled',
    icon: Server,
    accent: 'text-amber-400',
  },
  {
    id: 'data',
    stage: 'Sensitive Data',
    title: 'S3 payroll bucket',
    detail: '1.4M employee PII & compensation objects',
    risk: 'Restricted · Unmasked access',
    icon: Database,
    accent: 'text-rose-400',
  },
];

const INTEGRATIONS = [
  { name: 'Microsoft Entra ID', role: 'Agent identities & grants' },
  { name: 'Microsoft Azure', role: 'AI Foundry & managed identities' },
  { name: 'AWS', role: 'IAM roles, S3 & Bedrock' },
  { name: 'Google Cloud', role: 'Vertex AI & service accounts' },
  { name: 'GitHub', role: 'Repositories, apps & secrets' },
  { name: 'Slack', role: 'Bot permissions & channel scope' },
  { name: 'Jira', role: 'Automated security ticketing' },
  { name: 'ServiceNow', role: 'ITSM change & incident sync' },
];

export const LandingPage: React.FC<LandingPageProps> = ({ onLaunchDemo }) => {
  const [selectedPreviewNode, setSelectedPreviewNode] = useState<string>('agent');
  const [demoModalOpen, setDemoModalOpen] = useState(false);
  const [formName, setFormName] = useState('');
  const [formEmail, setFormEmail] = useState('');
  const [formCompany, setFormCompany] = useState('');
  const [formError, setFormError] = useState('');
  const [formSubmitting, setFormSubmitting] = useState(false);
  const [formSubmitted, setFormSubmitted] = useState(false);
  const [submittedRequestId, setSubmittedRequestId] = useState('');

  const activeNode =
    PREVIEW_NODES.find((n) => n.id === selectedPreviewNode) ?? PREVIEW_NODES[0];

  const handleRequestSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formName.trim() || !formCompany.trim()) {
      setFormError('Please enter your full name and organization.');
      return;
    }
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailPattern.test(formEmail.trim())) {
      setFormError('Please provide a valid work email address.');
      return;
    }
    setFormError('');
    setFormSubmitting(true);
    try {
      const res = await fetch('/api/demo-requests', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: formName.trim(),
          email: formEmail.trim(),
          company: formCompany.trim(),
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setFormError(data.error || 'Unable to submit demo request.');
        return;
      }
      setSubmittedRequestId(data.request?.id ?? '');
      setFormSubmitted(true);
    } catch {
      setFormError('Network error while submitting briefing request.');
    } finally {
      setFormSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#090B10] text-slate-100">
      {/* Top Bar Contract: 3 zones separated by gap-8 */}
      <header className="sticky top-0 z-40 border-b border-white/[0.08] bg-[#090B10]/95 backdrop-blur-md">
        <div className="mx-auto flex max-w-7xl items-center justify-between gap-8 px-6 py-3.5">
          <a
            href="#top"
            className="font-display text-lg font-semibold tracking-tight text-white whitespace-nowrap shrink-0"
          >
            Eyes of Agent
          </a>

          <nav
            aria-label="Primary navigation"
            className="hidden md:flex items-center gap-7 text-sm font-medium text-slate-400"
          >
            <a
              href="#problem"
              className="hover:text-white transition-colors whitespace-nowrap shrink-0"
            >
              Problem
            </a>
            <a
              href="#capabilities"
              className="hover:text-white transition-colors whitespace-nowrap shrink-0"
            >
              Capabilities
            </a>
            <a
              href="#how-it-works"
              className="hover:text-white transition-colors whitespace-nowrap shrink-0"
            >
              How it works
            </a>
            <a
              href="#use-cases"
              className="hover:text-white transition-colors whitespace-nowrap shrink-0"
            >
              Use cases
            </a>
          </nav>

          <div className="flex items-center shrink-0">
            <button
              type="button"
              onClick={() => onLaunchDemo(false)}
              className="rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400 transition-colors whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-sky-400"
            >
              View interactive demo
            </button>
          </div>
        </div>

        <div className="border-t border-white/[0.06] bg-[#0B0E15]/90">
          <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-x-6 gap-y-1 px-6 py-2 text-xs text-slate-400">
            <span className="hidden sm:inline">Security architecture &amp; onboarding help</span>
            <a
              href="mailto:lucathesniperlc@gmail.com"
              className="inline-flex items-center gap-1.5 font-medium text-sky-400 hover:text-sky-300 transition-colors whitespace-nowrap"
            >
              <Mail className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
              <span>Contact: lucathesniperlc@gmail.com</span>
            </a>
          </div>
        </div>
      </header>

      <main id="top">
        {/* 1. Hero */}
        <section className="mx-auto max-w-7xl px-6 pt-16 pb-20 lg:pt-20 lg:pb-24">
          <div className="grid grid-cols-1 gap-12 lg:grid-cols-12 lg:items-stretch">
            <div className="flex flex-col justify-center lg:col-span-6">
              <p className="text-sm font-medium text-sky-400">
                Enterprise AI Security Control Plane
              </p>
              <h1
                className="mt-4 font-display font-semibold tracking-tight text-white [text-wrap:balance]"
                style={{ fontSize: 'clamp(2.25rem, 4vw, 3.6rem)', lineHeight: 1.08 }}
              >
                See every agent. Understand every risk. Govern every action.
              </h1>
              <p className="mt-5 max-w-xl text-base leading-relaxed text-slate-300">
                Eyes of Agent is the control plane for AI-driven cyber risk. Connect your identity
                and cloud providers to discover shadow agents, map privilege paths to sensitive
                data, and enforce audit-ready policies in minutes.
              </p>

              <div className="mt-8 flex flex-wrap items-center gap-4">
                <button
                  type="button"
                  onClick={() => onLaunchDemo(false)}
                  className="inline-flex items-center gap-2 rounded-lg bg-sky-500 px-5 py-3 text-sm font-semibold text-slate-950 hover:bg-sky-400 transition-colors whitespace-nowrap shrink-0"
                >
                  <span>View interactive demo</span>
                  <ArrowRight className="w-4 h-4" aria-hidden="true" />
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setFormSubmitted(false);
                    setFormError('');
                    setDemoModalOpen(true);
                  }}
                  className="rounded-lg border border-white/15 bg-[#11151D] px-5 py-3 text-sm font-medium text-slate-200 hover:border-white/30 hover:text-white transition-colors whitespace-nowrap shrink-0"
                >
                  Request a demo
                </button>
              </div>

              <div className="mt-8 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-slate-400">
                <span>SOC 2-ready architecture</span>
                <span aria-hidden="true">·</span>
                <span>Privacy-first by design</span>
                <span aria-hidden="true">·</span>
                <span>No raw prompt retention</span>
              </div>
            </div>

            {/* Interactive Dashboard Preview */}
            <div className="lg:col-span-6">
              <div className="flex h-full flex-col justify-between rounded-xl border border-white/10 bg-[#11151D] p-6">
                <div>
                  <div className="flex items-center justify-between border-b border-white/[0.08] pb-4">
                    <div>
                      <p className="text-xs text-slate-400">
                        Northwind Financial · Live Exposure Preview
                      </p>
                      <h2 className="mt-1 font-display text-base font-semibold text-white">
                        Critical Path: Finance Copilot to S3 Payroll
                      </h2>
                    </div>
                    <span className="font-mono text-xs font-medium text-amber-400 tabular-nums">
                      Risk 82 / 100
                    </span>
                  </div>

                  {/* Summary metrics strip inside preview */}
                  <div className="mt-4 grid grid-cols-3 gap-4 border-b border-white/[0.08] pb-4">
                    <div>
                      <p className="text-xs text-slate-400">Discovered Agents</p>
                      <p className="mt-1 font-mono text-xl font-semibold text-white tabular-nums">
                        42
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-slate-400">Shadow AI</p>
                      <p className="mt-1 font-mono text-xl font-semibold text-amber-400 tabular-nums">
                        7
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-slate-400">Critical Paths</p>
                      <p className="mt-1 font-mono text-xl font-semibold text-rose-400 tabular-nums">
                        2
                      </p>
                    </div>
                  </div>

                  {/* Interactive 4-stage exposure path selector */}
                  <p className="mt-4 text-xs text-slate-400">
                    Select any node along the exposure chain to inspect permissions:
                  </p>
                  <div className="mt-3 grid grid-cols-2 gap-2.5 sm:grid-cols-4">
                    {PREVIEW_NODES.map((node, index) => {
                      const Icon = node.icon;
                      const isSelected = node.id === selectedPreviewNode;
                      return (
                        <button
                          key={node.id}
                          type="button"
                          onClick={() => setSelectedPreviewNode(node.id)}
                          className={`flex flex-col items-start rounded-lg border p-3 text-left transition-colors ${
                            isSelected
                              ? 'border-sky-500/60 bg-sky-500/10'
                              : 'border-white/[0.08] bg-[#0B0E14] hover:border-white/20'
                          }`}
                        >
                          <div className="flex w-full items-center justify-between">
                            <span className="font-mono text-[11px] text-slate-400 tabular-nums">
                              0{index + 1}
                            </span>
                            <Icon className={`w-3.5 h-3.5 ${node.accent}`} aria-hidden="true" />
                          </div>
                          <span className="mt-2 text-[11px] text-slate-400">{node.stage}</span>
                          <span className="mt-0.5 text-[11px] font-semibold text-white leading-snug break-words w-full">
                            {node.title}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Selected node detail readout */}
                <div className="mt-4 rounded-lg border border-white/[0.08] bg-[#090B10] p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-xs font-medium text-slate-400">
                      {activeNode.stage} · {activeNode.title}
                    </span>
                    <span className={`font-mono text-xs font-medium ${activeNode.accent}`}>
                      {activeNode.risk}
                    </span>
                  </div>
                  <p className="mt-1.5 font-mono text-xs text-slate-200">{activeNode.detail}</p>
                  <div className="mt-3 flex items-center justify-between border-t border-white/[0.06] pt-3">
                    <span className="text-xs text-slate-400">
                      Remediation: Scope IAM role &amp; enable observe-only DLP
                    </span>
                    <button
                      type="button"
                      onClick={() => onLaunchDemo(true)}
                      className="text-xs font-semibold text-sky-400 hover:text-sky-300 transition-colors whitespace-nowrap"
                    >
                      Run 8-step tour →
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* 2. Problem Section */}
        <section id="problem" className="border-t border-white/[0.08] bg-[#0C0F16] py-20">
          <div className="mx-auto max-w-7xl px-6">
            <div className="max-w-2xl">
              <p className="text-xs font-medium text-slate-400">The Visibility Gap</p>
              <h2 className="mt-2 font-display text-3xl font-semibold tracking-tight text-white [text-wrap:balance]">
                AI agents are appearing faster than security teams can govern them.
              </h2>
            </div>

            <div className="mt-12 grid grid-cols-1 gap-6 md:grid-cols-3">
              <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-6">
                <p className="font-mono text-xs text-amber-400">01 · Shadow AI</p>
                <h3 className="mt-3 font-display text-lg font-semibold text-white">
                  Unregistered agents &amp; personal tokens
                </h3>
                <p className="mt-2 text-sm leading-relaxed text-slate-400">
                  Teams connect copilots and MCP servers directly to customer warehouses and Slack
                  workspaces without security review or a named owner.
                </p>
              </div>

              <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-6">
                <p className="font-mono text-xs text-rose-400">02 · Over-privileged agents</p>
                <h3 className="mt-3 font-display text-lg font-semibold text-white">
                  Excessive IAM &amp; data permissions
                </h3>
                <p className="mt-2 text-sm leading-relaxed text-slate-400">
                  Non-human service accounts inherit tenant-wide SharePoint, CRM, or S3 payroll
                  access that a single prompt injection or tool call can expose.
                </p>
              </div>

              <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-6">
                <p className="font-mono text-xs text-sky-400">03 · Unprovable compliance</p>
                <h3 className="mt-3 font-display text-lg font-semibold text-white">
                  No audit trail for SOC 2 &amp; ISO 27001
                </h3>
                <p className="mt-2 text-sm leading-relaxed text-slate-400">
                  Auditors ask which agents touch regulated PII, what controls enforce least
                  privilege, and where runtime policy evidence lives.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* 3. Product Pillars */}
        <section id="capabilities" className="border-t border-white/[0.08] py-20">
          <div className="mx-auto max-w-7xl px-6">
            <div className="max-w-2xl">
              <p className="text-xs font-medium text-sky-400">Platform Architecture</p>
              <h2 className="mt-2 font-display text-3xl font-semibold tracking-tight text-white [text-wrap:balance]">
                One control plane from discovery to audit evidence.
              </h2>
            </div>

            <div className="mt-12 grid grid-cols-1 gap-6 lg:grid-cols-12">
              <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-7 lg:col-span-5">
                <span className="font-mono text-xs text-sky-400">Pillar 01 · Discover</span>
                <h3 className="mt-3 font-display text-xl font-semibold text-white">
                  AI agents, MCP servers, models, and tools
                </h3>
                <p className="mt-3 text-sm leading-relaxed text-slate-400">
                  Continuously inventory sanctioned and shadow agents across Entra ID, AWS, Azure,
                  GCP, GitHub, and Slack. Catalog every connected MCP server, tool definition, and
                  foundation model endpoint.
                </p>
                <div className="mt-6 border-t border-white/[0.08] pt-4 text-xs text-slate-300 font-mono">
                  42 agents · 5 MCP servers · 4 model providers
                </div>
              </div>

              <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-7 lg:col-span-7">
                <span className="font-mono text-xs text-orange-400">Pillar 02 · Understand</span>
                <h3 className="mt-3 font-display text-xl font-semibold text-white">
                  Identity, permissions, data access, and exposure paths
                </h3>
                <p className="mt-3 text-sm leading-relaxed text-slate-400">
                  Correlate each agent to its underlying service principal or IAM role, trace tool
                  permissions through MCP servers, and expose exact reachability to Restricted data
                  stores like S3 payroll buckets, Snowflake, and SharePoint.
                </p>
                <div className="mt-6 grid grid-cols-2 gap-4 border-t border-white/[0.08] pt-4 sm:grid-cols-4 text-xs">
                  <div>
                    <span className="text-slate-400">Hop 1</span>
                    <p className="mt-0.5 font-medium text-white">Agent</p>
                  </div>
                  <div>
                    <span className="text-slate-400">Hop 2</span>
                    <p className="mt-0.5 font-medium text-white">Service Identity</p>
                  </div>
                  <div>
                    <span className="text-slate-400">Hop 3</span>
                    <p className="mt-0.5 font-medium text-white">MCP &amp; Tools</p>
                  </div>
                  <div>
                    <span className="text-slate-400">Hop 4</span>
                    <p className="mt-0.5 font-medium text-rose-400">Sensitive Data</p>
                  </div>
                </div>
              </div>

              <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-7 lg:col-span-12">
                <div className="grid grid-cols-1 gap-6 lg:grid-cols-12 lg:items-center">
                  <div className="lg:col-span-7">
                    <span className="font-mono text-xs text-emerald-400">Pillar 03 · Govern</span>
                    <h3 className="mt-3 font-display text-xl font-semibold text-white">
                      Policy, remediation, enforcement, and audit evidence
                    </h3>
                    <p className="mt-2 text-sm leading-relaxed text-slate-400">
                      Roll out observe-only guardrails first to see exactly what tool calls would be
                      redacted or blocked, dispatch remediation tickets to Jira or ServiceNow, and
                      export cryptographically hashed SOC 2 and ISO 27001 evidence packs.
                    </p>
                  </div>
                  <div className="grid grid-cols-3 gap-4 border-t border-white/[0.08] pt-4 lg:col-span-5 lg:border-t-0 lg:border-l lg:pl-6 lg:pt-0">
                    <div>
                      <p className="text-xs text-slate-400">Policy Mode</p>
                      <p className="mt-1 font-mono text-sm font-medium text-white">
                        Observe / Enforce
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-slate-400">Ticketing</p>
                      <p className="mt-1 font-mono text-sm font-medium text-white">
                        Jira · ServiceNow
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-slate-400">Frameworks</p>
                      <p className="mt-1 font-mono text-sm font-medium text-white">
                        SOC 2 · ISO 27001
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* 4. How It Works */}
        <section id="how-it-works" className="border-t border-white/[0.08] bg-[#0C0F16] py-20">
          <div className="mx-auto max-w-7xl px-6">
            <div className="max-w-2xl">
              <p className="text-xs font-medium text-slate-400">Deployment Flow</p>
              <h2 className="mt-2 font-display text-3xl font-semibold tracking-tight text-white">
                From read-only connection to provable governance.
              </h2>
            </div>

            <div className="mt-10 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
              {[
                {
                  step: '01',
                  title: 'Connect',
                  desc: 'Authorize read-only Entra ID, AWS, GCP, Azure, and GitHub connectors.',
                },
                {
                  step: '02',
                  title: 'Discover',
                  desc: 'Identify every sanctioned, unowned, and shadow AI agent plus MCP servers.',
                },
                {
                  step: '03',
                  title: 'Map risk',
                  desc: 'Compute exposure paths from service identities to PII and financial buckets.',
                },
                {
                  step: '04',
                  title: 'Remediate',
                  desc: 'Route scoped least-privilege fixes directly to Jira and Cloud Security.',
                },
                {
                  step: '05',
                  title: 'Prove',
                  desc: 'Simulate observe-only blocks and export SOC 2 & ISO 27001 evidence.',
                },
              ].map((item) => (
                <div
                  key={item.step}
                  className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5"
                >
                  <span className="font-mono text-xs font-medium text-sky-400">{item.step}</span>
                  <h3 className="mt-2 font-display text-base font-semibold text-white">
                    {item.title}
                  </h3>
                  <p className="mt-2 text-xs leading-relaxed text-slate-400">{item.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* 5. Key Use Cases */}
        <section id="use-cases" className="border-t border-white/[0.08] py-20">
          <div className="mx-auto max-w-7xl px-6">
            <div className="max-w-2xl">
              <p className="text-xs font-medium text-sky-400">Built for Security &amp; Risk Leaders</p>
              <h2 className="mt-2 font-display text-3xl font-semibold tracking-tight text-white">
                Four workflows your security team runs every week.
              </h2>
            </div>

            <div className="mt-10 grid grid-cols-1 gap-6 md:grid-cols-2">
              {[
                {
                  title: 'CISO risk review',
                  detail:
                    'Present an executive risk posture score, shadow AI trend, and top critical exposure paths impacting Payroll, CRM, and Core SDLC.',
                },
                {
                  title: 'AI governance',
                  detail:
                    'Require every agent to carry an accountable owner, approved foundation model provider, and least-privilege MCP tool policy.',
                },
                {
                  title: 'Compliance readiness',
                  detail:
                    'Map technical controls and live policy decisions directly to SOC 2 CC6/CC7 and ISO 27001 Annex A with one-click evidence export.',
                },
                {
                  title: 'Incident response',
                  detail:
                    'Trace anomalous tool invocations back to service credentials, inspect reachable data stores, and switch observe-only rules to block.',
                },
              ].map((uc) => (
                <div
                  key={uc.title}
                  className="rounded-xl border border-white/[0.08] bg-[#11151D] p-6"
                >
                  <h3 className="font-display text-lg font-semibold text-white">{uc.title}</h3>
                  <p className="mt-2 text-sm leading-relaxed text-slate-400">{uc.detail}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* 6. Social Proof / Trust & Integrations */}
        <section className="border-t border-white/[0.08] bg-[#0C0F16] py-20">
          <div className="mx-auto max-w-7xl px-6">
            <div className="grid grid-cols-1 gap-10 lg:grid-cols-12 lg:items-start">
              <div className="lg:col-span-5">
                <p className="text-xs font-medium text-slate-400">Trust &amp; Privacy</p>
                <h2 className="mt-2 font-display text-2xl font-semibold tracking-tight text-white">
                  Built for regulated financial and enterprise environments.
                </h2>
                <div className="mt-6 space-y-4">
                  <div className="flex items-start gap-3">
                    <ShieldCheck className="mt-0.5 h-4 w-4 text-emerald-400 shrink-0" aria-hidden="true" />
                    <div>
                      <p className="text-sm font-medium text-white">SOC 2-ready architecture</p>
                      <p className="text-xs text-slate-400">
                        Tenant-isolated metadata store with immutable audit logging.
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <Lock className="mt-0.5 h-4 w-4 text-sky-400 shrink-0" aria-hidden="true" />
                    <div>
                      <p className="text-sm font-medium text-white">Privacy-first by design</p>
                      <p className="text-xs text-slate-400">
                        Metadata-only discovery using read-only IAM and identity scopes.
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <Shield className="mt-0.5 h-4 w-4 text-slate-300 shrink-0" aria-hidden="true" />
                    <div>
                      <p className="text-sm font-medium text-white">No raw prompt retention</p>
                      <p className="text-xs text-slate-400">
                        Policy inspection evaluates patterns in memory without storing customer
                        prompts.
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              <div className="lg:col-span-7">
                <p className="text-xs font-medium text-slate-400">
                  Native Control Plane Integrations
                </p>
                <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
                  {INTEGRATIONS.map((item) => (
                    <div
                      key={item.name}
                      className="rounded-lg border border-white/[0.08] bg-[#11151D] p-4"
                    >
                      <p className="text-xs font-semibold text-white">{item.name}</p>
                      <p className="mt-1 text-[11px] text-slate-400">{item.role}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* 6b. 6 Core Questions, Ecosystem Coverage & Commercial Tiers */}
        <section className="border-t border-white/[0.08] py-20">
          <div className="mx-auto max-w-7xl px-6 space-y-16">
            {/* 6 Core Questions */}
            <div>
              <p className="text-xs font-medium text-sky-400">Platform Mandate</p>
              <h2 className="mt-2 font-display text-2xl font-semibold tracking-tight text-white">
                Six questions every security, AI, and compliance leader must answer.
              </h2>
              <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {[
                  { q: '01 · What AI agents exist?', a: 'Auto-discover sanctioned, unowned, and shadow AI across Entra ID, AWS, Azure, GCP, GitHub, and MCP.' },
                  { q: '02 · What cyber risks do they create?', a: 'Score blast radius using our explainable 6-factor model across privilege, autonomy, and governance.' },
                  { q: '03 · What sensitive data can they reach?', a: 'Traverse identity → permission → MCP tool → PII/PHI/PCI store → external egress in one graph.' },
                  { q: '04 · What are they doing right now?', a: 'Inspect inline PEP/PDP telemetry across 11 model providers with zero raw prompt retention.' },
                  { q: '05 · Who must fix a risk?', a: 'Assign accountable owners, enforce SLAs, route Jira/ServiceNow tickets, and verify on next sync.' },
                  { q: '06 · Are we compliant?', a: 'Map controls and SHA-256 hash-chained evidence to SOC 2, ISO 27001/42001, GDPR, and EU AI Act.' },
                ].map((item) => (
                  <div
                    key={item.q}
                    className="rounded-xl border border-white/[0.08] bg-[#11151D] p-4"
                  >
                    <p className="font-mono text-xs font-semibold text-sky-400">{item.q}</p>
                    <p className="mt-1.5 text-xs leading-relaxed text-slate-300">{item.a}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* 11 AI Providers & 8 Agent Frameworks + Vertical Policy Packs */}
            <div className="grid grid-cols-1 gap-8 lg:grid-cols-12">
              <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-6 lg:col-span-7 space-y-5">
                <div>
                  <p className="text-xs font-medium text-sky-400">Universal AI Runtime Coverage</p>
                  <h3 className="mt-1 font-display text-lg font-semibold text-white">
                    11 AI Providers &amp; 8 Agent Frameworks Supported
                  </h3>
                </div>
                <div>
                  <p className="text-[11px] font-medium uppercase tracking-wider text-slate-400">
                    Model &amp; Cloud AI Providers (11)
                  </p>
                  <p className="mt-2 font-mono text-xs leading-relaxed text-slate-200">
                    OpenAI · Anthropic · Google Gemini / Vertex AI · Azure OpenAI · AWS Bedrock · Cohere · Mistral · Groq · Together AI · Hugging Face · Ollama / Self-Hosted
                  </p>
                </div>
                <div className="border-t border-white/[0.08] pt-4">
                  <p className="text-[11px] font-medium uppercase tracking-wider text-slate-400">
                    Discovered Agent Frameworks &amp; Runtimes (8)
                  </p>
                  <p className="mt-2 font-mono text-xs leading-relaxed text-slate-200">
                    LangGraph · CrewAI · AutoGen · OpenAI Agents SDK · Microsoft Copilot Studio · AWS Bedrock Agents · Google Vertex AI Agent Builder · Custom MCP Runtime
                  </p>
                </div>
              </div>

              <div className="rounded-xl border border-white/[0.08] bg-[#11151D] p-6 lg:col-span-5 space-y-4">
                <div>
                  <p className="text-xs font-medium text-emerald-400">10 Industry Vertical Policy Packs</p>
                  <h3 className="mt-1 font-display text-lg font-semibold text-white">
                    One-click domain guardrails
                  </h3>
                </div>
                <p className="text-xs leading-relaxed text-slate-400">
                  Pre-built YAML enforcement rules and framework mappings tailored for regulated workloads:
                </p>
                <div className="grid grid-cols-2 gap-2 font-mono text-[11px] text-slate-200">
                  {[
                    'FinTech & Payments',
                    'SaaS & Tech',
                    'Healthcare (HIPAA)',
                    'Insurance',
                    'Legal & Audit',
                    'Manufacturing',
                    'Energy & Utilities',
                    'Government / GovCloud',
                    'Retail & Commerce',
                    'Higher Education',
                  ].map((v) => (
                    <div
                      key={v}
                      className="rounded border border-white/[0.08] bg-[#090B10] px-2.5 py-1.5 truncate"
                    >
                      {v}
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* 4 Commercial Packaging Tiers */}
            <div>
              <p className="text-xs font-medium text-slate-400">Commercial Packaging</p>
              <h2 className="mt-2 font-display text-2xl font-semibold tracking-tight text-white">
                Built to start in 15 minutes and scale across global enterprises.
              </h2>
              <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
                {[
                  {
                    tier: 'Starter',
                    audience: 'AI-first teams & startups',
                    price: 'Up to 25 agents',
                    features: 'Read-only Entra/AWS/GitHub discovery, exposure graph, 6-factor risk scoring, SOC 2 starter mapping.',
                  },
                  {
                    tier: 'Growth',
                    audience: 'Mid-market security & AI teams',
                    price: 'Up to 250 agents',
                    features: 'Jira/ServiceNow routing, approval-gated remediation, observe-only PEP/PDP gateway, ISO 27001/42001.',
                  },
                  {
                    tier: 'Enterprise',
                    audience: 'Regulated enterprises & CISOs',
                    price: 'Unlimited agents',
                    features: 'Enforced PEP/PDP (8 actions), SOAR playbooks, SAML 2.0 + SCIM, vertical packs, auditor-scoped packs.',
                  },
                  {
                    tier: 'MSSP',
                    audience: 'Managed security & advisory partners',
                    price: 'Multi-tenant console',
                    features: 'Cross-tenant posture fleet view, delegated RBAC, white-labeled executive audit exports & SLAs.',
                  },
                ].map((pkg) => (
                  <div
                    key={pkg.tier}
                    className="rounded-xl border border-white/[0.08] bg-[#11151D] p-5 flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-center justify-between gap-2">
                        <h3 className="font-display text-base font-semibold text-white">
                          {pkg.tier}
                        </h3>
                        <span className="font-mono text-[11px] text-sky-400">{pkg.price}</span>
                      </div>
                      <p className="mt-1 text-[11px] text-slate-400">{pkg.audience}</p>
                      <p className="mt-3 text-xs leading-relaxed text-slate-300">{pkg.features}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* 7. Final CTA */}
        <section className="border-t border-white/[0.08] py-20">
          <div className="mx-auto max-w-4xl px-6 text-center">
            <h2 className="font-display text-3xl font-semibold tracking-tight text-white [text-wrap:balance]">
              See your AI agent risk in 15 minutes.
            </h2>
            <p className="mt-4 text-base text-slate-400">
              Explore the full Northwind Financial control plane right now with realistic enterprise
              data, or schedule a guided session with our security engineering team.
            </p>
            <div className="mt-8 flex flex-wrap items-center justify-center gap-4">
              <button
                type="button"
                onClick={() => onLaunchDemo(true)}
                className="inline-flex items-center gap-2 rounded-lg bg-sky-500 px-6 py-3 text-sm font-semibold text-slate-950 hover:bg-sky-400 transition-colors"
              >
                <span>View interactive demo</span>
                <ArrowRight className="w-4 h-4" aria-hidden="true" />
              </button>
              <button
                type="button"
                onClick={() => {
                  setFormSubmitted(false);
                  setFormError('');
                  setDemoModalOpen(true);
                }}
                className="rounded-lg border border-white/15 bg-[#11151D] px-6 py-3 text-sm font-medium text-slate-200 hover:border-white/30 hover:text-white transition-colors"
              >
                Request a demo
              </button>
            </div>
          </div>
        </section>
      </main>

      {/* Quiet Footer */}
      <footer className="border-t border-white/[0.08] py-8">
        <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-4 px-6 text-xs text-slate-500 sm:flex-row">
          <span>Eyes of Agent · AI Risk &amp; Governance Control Plane</span>
          <div className="flex flex-wrap items-center justify-center gap-6">
            <span>SOC 2-ready architecture</span>
            <span>No raw prompt retention</span>
            <a
              href="mailto:lucathesniperlc@gmail.com"
              className="text-sky-400 hover:text-sky-300 transition-colors"
            >
              Contact: lucathesniperlc@gmail.com
            </a>
          </div>
        </div>
      </footer>

      {/* Request Demo Modal */}
      {demoModalOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="demo-modal-title"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm"
        >
          <div className="w-full max-w-md rounded-xl border border-white/15 bg-[#11151D] p-6">
            <div className="flex items-start justify-between gap-4">
              <div>
                <h2 id="demo-modal-title" className="font-display text-lg font-semibold text-white">
                  Request a security architecture briefing
                </h2>
                <p className="mt-1 text-xs text-slate-400">
                  15-minute read-only assessment of your Entra ID, AWS, and MCP surface. Direct contact:{' '}
                  <a
                    href="mailto:lucathesniperlc@gmail.com"
                    className="text-sky-400 hover:text-sky-300 underline-offset-2 hover:underline"
                  >
                    lucathesniperlc@gmail.com
                  </a>
                </p>
              </div>
              <button
                type="button"
                aria-label="Close request demo modal"
                onClick={() => setDemoModalOpen(false)}
                className="rounded-md p-1.5 text-slate-400 hover:bg-white/10 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {formSubmitted ? (
              <div className="mt-6 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-4">
                <div className="flex items-center gap-2 text-sm font-semibold text-emerald-300">
                  <CheckCircle2 className="w-4 h-4 shrink-0" aria-hidden="true" />
                  <span>Briefing request received</span>
                </div>
                <p className="mt-2 text-xs leading-relaxed text-slate-300">
                  We have reserved a sandbox briefing for <span className="font-medium text-white">{formCompany}</span> ({formEmail}). You can explore the live Northwind Financial prototype immediately.
                </p>
                {submittedRequestId && (
                  <p className="mt-2 font-mono text-[11px] text-emerald-300">
                    Reference ID: {submittedRequestId} · Logged in control plane audit trail
                  </p>
                )}
                <div className="mt-4 flex items-center justify-end gap-3">
                  <button
                    type="button"
                    onClick={() => {
                      setDemoModalOpen(false);
                      onLaunchDemo(true);
                    }}
                    className="rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400"
                  >
                    Open interactive demo
                  </button>
                </div>
              </div>
            ) : (
              <form onSubmit={handleRequestSubmit} className="mt-5 space-y-4" noValidate>
                <div>
                  <label htmlFor="demo-name" className="block text-xs font-medium text-slate-300">
                    Full name
                  </label>
                  <input
                    id="demo-name"
                    type="text"
                    value={formName}
                    onChange={(e) => setFormName(e.target.value)}
                    placeholder="Jordan Vance"
                    className="mt-1.5 w-full rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 text-sm text-white placeholder:text-slate-500 focus:border-sky-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label htmlFor="demo-email" className="block text-xs font-medium text-slate-300">
                    Work email
                  </label>
                  <input
                    id="demo-email"
                    type="email"
                    value={formEmail}
                    onChange={(e) => setFormEmail(e.target.value)}
                    placeholder="security@company.com"
                    className="mt-1.5 w-full rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 text-sm text-white placeholder:text-slate-500 focus:border-sky-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label htmlFor="demo-company" className="block text-xs font-medium text-slate-300">
                    Organization
                  </label>
                  <input
                    id="demo-company"
                    type="text"
                    value={formCompany}
                    onChange={(e) => setFormCompany(e.target.value)}
                    placeholder="Northwind Financial"
                    className="mt-1.5 w-full rounded-lg border border-white/15 bg-[#090B10] px-3 py-2 text-sm text-white placeholder:text-slate-500 focus:border-sky-500 focus:outline-none"
                  />
                </div>

                {formError && (
                  <p role="alert" className="text-xs text-rose-400">
                    {formError}
                  </p>
                )}

                <div className="flex items-center justify-end gap-3 pt-2">
                  <button
                    type="button"
                    onClick={() => setDemoModalOpen(false)}
                    className="rounded-lg border border-white/10 px-4 py-2 text-xs font-medium text-slate-300 hover:bg-white/5"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={formSubmitting}
                    className="rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50"
                  >
                    {formSubmitting ? 'Submitting...' : 'Submit request'}
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
