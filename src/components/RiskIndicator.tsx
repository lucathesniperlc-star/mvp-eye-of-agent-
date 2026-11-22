import { AlertTriangle, CheckCircle2, Clock, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { FindingStatus, GatewayDecision, PolicyAction, RiskLevel } from '../types/security';

export function RiskLabel({ level }: { level: RiskLevel | 'nominal' }) {
  const styles: Record<RiskLevel | 'nominal', { text: string; label: string }> = {
    critical: { text: 'text-rose-400', label: 'Critical' },
    high: { text: 'text-orange-400', label: 'High' },
    medium: { text: 'text-amber-400', label: 'Medium' },
    low: { text: 'text-sky-400', label: 'Low' },
    informational: { text: 'text-slate-400', label: 'Informational' },
    nominal: { text: 'text-emerald-400', label: 'Nominal' },
  };
  const cfg = styles[level];
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-medium whitespace-nowrap ${cfg.text}`}>
      {level === 'critical' || level === 'high' ? (
        <ShieldAlert className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
      ) : level === 'nominal' ? (
        <ShieldCheck className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
      ) : (
        <AlertTriangle className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
      )}
      <span>{cfg.label}</span>
    </span>
  );
}

export function FindingStatusLabel({ status }: { status: FindingStatus }) {
  if (status === 'remediated') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-400 whitespace-nowrap">
        <CheckCircle2 className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
        <span>Remediated</span>
      </span>
    );
  }
  if (status === 'in_progress') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-sky-400 whitespace-nowrap">
        <Clock className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
        <span>In progress</span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-rose-400 whitespace-nowrap">
      <AlertTriangle className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
      <span>Open</span>
    </span>
  );
}

export function PolicyActionLabel({ action }: { action: PolicyAction }) {
  if (action === 'block') {
    return <span className="text-xs font-mono font-medium text-rose-400 uppercase tracking-wider">Block</span>;
  }
  if (action === 'redact') {
    return <span className="text-xs font-mono font-medium text-amber-400 uppercase tracking-wider">Redact</span>;
  }
  return <span className="text-xs font-mono font-medium text-emerald-400 uppercase tracking-wider">Allow</span>;
}

export function GatewayDecisionLabel({ decision }: { decision: GatewayDecision }) {
  const normalized = decision.replace(/^would_/, '');
  if (normalized === 'block' || normalized === 'quarantine_agent') {
    return (
      <span className="text-xs font-mono font-medium text-rose-400">
        {decision}
      </span>
    );
  }
  if (normalized === 'escalate') {
    return (
      <span className="text-xs font-mono font-medium text-orange-400">
        {decision}
      </span>
    );
  }
  if (
    normalized === 'redact' ||
    normalized === 'approve' ||
    normalized === 'step_up_authenticate' ||
    normalized === 'downgrade'
  ) {
    return (
      <span className="text-xs font-mono font-medium text-amber-400">
        {decision}
      </span>
    );
  }
  return (
    <span className="text-xs font-mono font-medium text-emerald-400">
      {decision}
    </span>
  );
}
