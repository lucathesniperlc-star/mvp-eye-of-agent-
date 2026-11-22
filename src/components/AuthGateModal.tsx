import React, { useEffect, useState } from 'react';
import { KeyRound, ShieldCheck, X } from 'lucide-react';
import type { AuthSessionState, RbacRole } from '../types/security';

interface PersonaItem {
  user: {
    id: string;
    email: string;
    displayName: string;
    idp: string;
    mfaEnabled: boolean;
    interactiveAllowed: boolean;
  };
  memberships: Array<{ tenantId: string; tenantName: string; role: RbacRole }>;
}

interface AuthGateModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAuthenticated: (session: AuthSessionState) => void;
}

export const AuthGateModal: React.FC<AuthGateModalProps> = ({
  isOpen,
  onClose,
  onAuthenticated,
}) => {
  const [personas, setPersonas] = useState<PersonaItem[]>([]);
  const [selectedEmail, setSelectedEmail] = useState('ciso@northwind.com');
  const [totpCode, setTotpCode] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!isOpen) return;
    fetch('/api/auth/personas')
      .then((r) => r.json())
      .then((data: { personas?: PersonaItem[] }) => {
        if (data.personas) setPersonas(data.personas);
      })
      .catch(() => {
        setErrorMsg('Unable to load identity provider directory.');
      });
  }, [isOpen]);

  if (!isOpen) return null;

  const activePersona = personas.find((p) => p.user.email === selectedEmail);
  const needsMfa = Boolean(activePersona?.user.mfaEnabled);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg('');
    setLoading(true);
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: selectedEmail,
          totpCode: totpCode.trim(),
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data.error || 'Authentication failed');
        return;
      }
      onAuthenticated(data as AuthSessionState);
      setTotpCode('');
      onClose();
    } catch {
      setErrorMsg('Network error reaching authentication service.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="sso-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm"
    >
      <div className="w-full max-w-lg rounded-xl border border-white/15 bg-[#11151D] p-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-medium text-sky-400">
              <ShieldCheck className="w-4 h-4" aria-hidden="true" />
              <span>Enterprise SSO · OIDC / SAML 2.0 + MFA</span>
            </div>
            <h2 id="sso-modal-title" className="mt-1 font-display text-lg font-semibold text-white">
              Sign in or switch RBAC role
            </h2>
            <p className="mt-1 text-xs text-slate-400">
              Sessions use HttpOnly signed cookies with zero browser localStorage token persistence.
            </p>
          </div>
          <button
            type="button"
            aria-label="Close sign in dialog"
            onClick={onClose}
            className="rounded-md p-1.5 text-slate-400 hover:bg-white/10 hover:text-white"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="mt-5 space-y-4">
          <div>
            <label htmlFor="sso-persona-select" className="block text-xs font-medium text-slate-300">
              Identity principal
            </label>
            <select
              id="sso-persona-select"
              value={selectedEmail}
              onChange={(e) => {
                setSelectedEmail(e.target.value);
                setErrorMsg('');
              }}
              className="mt-1.5 w-full rounded-lg border border-white/15 bg-[#090B10] px-3 py-2.5 text-xs text-white focus:border-sky-500 focus:outline-none"
            >
              {personas.map((p) => {
                const rolesLabel = p.memberships
                  .map((m) => `${m.tenantName}: ${m.role}`)
                  .join(' · ');
                return (
                  <option key={p.user.id} value={p.user.email}>
                    {p.user.displayName} ({rolesLabel})
                  </option>
                );
              })}
            </select>
          </div>

          {activePersona && (
            <div className="rounded-lg border border-white/[0.08] bg-[#090B10] p-3 text-xs space-y-1">
              <div className="flex items-center justify-between text-slate-300">
                <span>Provider: <span className="font-mono text-white">{activePersona.user.idp}</span></span>
                <span>
                  MFA:{' '}
                  <span className="font-mono text-white">
                    {activePersona.user.mfaEnabled ? 'Required (TOTP)' : 'Optional'}
                  </span>
                </span>
              </div>
              {!activePersona.user.interactiveAllowed && (
                <p className="text-amber-400">
                  Service accounts do not permit interactive browser login (will reject with 403).
                </p>
              )}
            </div>
          )}

          <div>
            <label htmlFor="sso-totp-input" className="block text-xs font-medium text-slate-300">
              {needsMfa ? '6-digit MFA authenticator code (required)' : 'MFA code (optional)'}
            </label>
            <div className="relative mt-1.5">
              <KeyRound
                className="pointer-events-none absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-slate-500"
                aria-hidden="true"
              />
              <input
                id="sso-totp-input"
                type="text"
                inputMode="numeric"
                maxLength={6}
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value)}
                placeholder="Enter 6-digit TOTP (e.g. 123456)"
                className="w-full rounded-lg border border-white/15 bg-[#090B10] py-2 pr-3 pl-9 font-mono text-xs text-white placeholder:text-slate-500 focus:border-sky-500 focus:outline-none"
              />
            </div>
          </div>

          {errorMsg && (
            <p role="alert" className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-300">
              {errorMsg}
            </p>
          )}

          <div className="flex items-center justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-white/10 px-4 py-2 text-xs font-medium text-slate-300 hover:bg-white/5"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50"
            >
              {loading ? 'Verifying...' : 'Authenticate session'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
