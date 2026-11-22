import React from 'react';
import { ChevronLeft, ChevronRight, X } from 'lucide-react';
import type { ScreenId } from '../types/security';

export interface TourStep {
  step: number;
  title: string;
  narrative: string;
  screen: ScreenId;
  agentId?: string;
}

export const DEMO_TOUR_STEPS: TourStep[] = [
  {
    step: 1,
    title: 'Connect Entra ID & AWS',
    narrative:
      'Northwind Financial authorized read-only Entra ID, AWS IAM, Azure, GCP, and GitHub connectors in under 15 minutes.',
    screen: 'connectors',
  },
  {
    step: 2,
    title: 'Discover 42 AI agents (7 shadow)',
    narrative:
      'Inventory telemetry uncovered 42 active AI agents, including 7 unregistered Shadow AI bots and 5 unowned service principals.',
    screen: 'inventory',
  },
  {
    step: 3,
    title: 'Identify Finance Copilot',
    narrative:
      'Finance Copilot carries a 92 Critical risk score because svc-finance-copilot holds direct payroll export permissions.',
    screen: 'agent-detail',
    agentId: 'agent_finance_copilot',
  },
  {
    step: 4,
    title: 'Trace the exposure path',
    narrative:
      'In under 10 seconds, trace the blast radius: Finance Copilot → svc-finance-copilot → finance-mcp → S3 payroll bucket (1.4M objects).',
    screen: 'exposure',
    agentId: 'agent_finance_copilot',
  },
  {
    step: 5,
    title: 'Review critical finding & impact',
    narrative:
      'Eyes of Agent generated Finding 001 with business impact on 1.4M employee tax records and exact IAM least-privilege steps.',
    screen: 'findings',
  },
  {
    step: 6,
    title: 'Create Jira ticket for Cloud Security',
    narrative:
      'Click "Create Jira ticket" right inside Findings to assign remediation to Cloud Security with SLA tracking.',
    screen: 'findings',
  },
  {
    step: 7,
    title: 'Verify SOC 2 & ISO 27001 evidence',
    narrative:
      'Controls CC6.1, CC6.3, and ISO A.8.2 map directly to cryptographically hashed metadata evidence—ready for audit export.',
    screen: 'compliance',
  },
  {
    step: 8,
    title: 'Enable observe-only policy mode',
    narrative:
      'Preview exactly which bulk payroll exports and SSN egress calls would be blocked or redacted before turning on enforcement.',
    screen: 'policy',
  },
];

interface GuidedTourOverlayProps {
  currentStepIndex: number;
  onSelectStep: (index: number) => void;
  onClose: () => void;
}

export const GuidedTourOverlay: React.FC<GuidedTourOverlayProps> = ({
  currentStepIndex,
  onSelectStep,
  onClose,
}) => {
  const current = DEMO_TOUR_STEPS[currentStepIndex] ?? DEMO_TOUR_STEPS[0];
  const isFirst = currentStepIndex === 0;
  const isLast = currentStepIndex === DEMO_TOUR_STEPS.length - 1;

  return (
    <aside
      aria-label="Guided product tour"
      className="fixed right-5 bottom-5 z-40 w-[calc(100%-2.5rem)] max-w-md rounded-xl border border-sky-500/40 bg-[#11151D] p-5 shadow-2xl"
    >
      <div className="flex items-center justify-between gap-3">
        <span className="font-mono text-xs font-medium text-sky-400 tabular-nums">
          Guided Demo · Step {current.step} of {DEMO_TOUR_STEPS.length}
        </span>
        <button
          type="button"
          aria-label="Close guided tour"
          onClick={onClose}
          className="rounded-md p-1 text-slate-400 hover:bg-white/10 hover:text-white"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <h3 className="mt-2 font-display text-base font-semibold text-white">{current.title}</h3>
      <p className="mt-1.5 text-xs leading-relaxed text-slate-300">{current.narrative}</p>

      <div className="mt-4 flex items-center justify-between border-t border-white/[0.08] pt-3">
        <button
          type="button"
          disabled={isFirst}
          onClick={() => onSelectStep(currentStepIndex - 1)}
          className="inline-flex items-center gap-1 rounded-lg border border-white/10 px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white disabled:opacity-40"
        >
          <ChevronLeft className="w-3.5 h-3.5" aria-hidden="true" />
          <span>Previous</span>
        </button>

        {isLast ? (
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg bg-emerald-500 px-3.5 py-1.5 text-xs font-semibold text-slate-950 hover:bg-emerald-400"
          >
            Finish tour
          </button>
        ) : (
          <button
            type="button"
            onClick={() => onSelectStep(currentStepIndex + 1)}
            className="inline-flex items-center gap-1 rounded-lg bg-sky-500 px-3.5 py-1.5 text-xs font-semibold text-slate-950 hover:bg-sky-400"
          >
            <span>Next step</span>
            <ChevronRight className="w-3.5 h-3.5" aria-hidden="true" />
          </button>
        )}
      </div>
    </aside>
  );
};
