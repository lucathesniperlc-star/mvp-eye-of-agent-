import crypto from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import type { Permission, Role, SessionRecord, UserRecord } from './types.ts';
import { store } from './store.ts';

const SESSION_COOKIE_NAME = 'eoa_session';
const SESSION_SIGNING_SECRET =
  process.env.EOA_SESSION_SECRET ||
  'eyes-of-agent-session-hmac-secret-dev-only';

export const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  owner: [
    'tenant:read',
    'tenant:admin',
    'agents:read',
    'agents:remediate_owned',
    'findings:read',
    'findings:manage',
    'connectors:read',
    'connectors:manage',
    'policies:read',
    'policies:manage',
    'compliance:read',
    'compliance:export',
    'audit:read',
    'graph:read',
  ],
  admin: [
    'tenant:read',
    'tenant:admin',
    'agents:read',
    'agents:remediate_owned',
    'findings:read',
    'findings:manage',
    'connectors:read',
    'connectors:manage',
    'policies:read',
    'policies:manage',
    'compliance:read',
    'compliance:export',
    'audit:read',
    'graph:read',
  ],
  security_analyst: [
    'tenant:read',
    'agents:read',
    'findings:read',
    'findings:manage',
    'connectors:read',
    'policies:read',
    'compliance:read',
    'audit:read',
    'graph:read',
  ],
  compliance_manager: [
    'tenant:read',
    'agents:read',
    'findings:read',
    'compliance:read',
    'compliance:export',
    'audit:read',
    'policies:read',
    'graph:read',
  ],
  agent_owner: [
    'tenant:read',
    'agents:read',
    'agents:remediate_owned',
    'findings:read',
    'graph:read',
  ],
  auditor: [
    'tenant:read',
    'agents:read',
    'findings:read',
    'compliance:read',
    'audit:read',
    'policies:read',
    'graph:read',
  ],
  service_account: [
    'tenant:read',
    'agents:read',
    'findings:read',
    'graph:read',
  ],
};

export function hasPermission(role: Role, permission: Permission): boolean {
  return ROLE_PERMISSIONS[role]?.includes(permission) ?? false;
}

export function signSessionCookieValue(sessionId: string): string {
  const sig = crypto
    .createHmac('sha256', SESSION_SIGNING_SECRET)
    .update(sessionId)
    .digest('base64url');
  return `${sessionId}.${sig}`;
}

export function verifySessionCookieValue(rawCookie: string | undefined): string | null {
  if (!rawCookie) return null;
  const parts = rawCookie.split('.');
  if (parts.length !== 2) return null;
  const [sessionId, sig] = parts;
  const expected = crypto
    .createHmac('sha256', SESSION_SIGNING_SECRET)
    .update(sessionId)
    .digest('base64url');
  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expected);
  if (sigBuf.length !== expBuf.length) return null;
  if (!crypto.timingSafeEqual(sigBuf, expBuf)) return null;
  return sessionId;
}

export function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!cookieHeader) return out;
  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const val = decodeURIComponent(part.slice(idx + 1).trim());
    out[key] = val;
  }
  return out;
}

export function setSessionCookie(res: Response, sessionId: string) {
  const value = signSessionCookieValue(sessionId);
  res.cookie(SESSION_COOKIE_NAME, value, {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 1000 * 60 * 60 * 8,
  });
}

export function clearSessionCookie(res: Response) {
  res.clearCookie(SESSION_COOKIE_NAME, { path: '/' });
}

export interface AuthenticatedRequest extends Request {
  auth?: {
    session: SessionRecord;
    user: UserRecord;
    tenantId: string;
    role: Role;
  };
}

/**
 * Request -> verify cookie session -> resolve user -> resolve tenant membership
 * -> reject forged client tenant overrides -> enforce tenant_id
 */
export function requireAuth(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) {
  const cookies = parseCookies(req.headers.cookie);
  const sessionId = verifySessionCookieValue(cookies[SESSION_COOKIE_NAME]);
  if (!sessionId) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const session = store.getSession(sessionId);
  if (!session) {
    return res.status(401).json({ error: 'Session expired or invalid' });
  }

  const user = store.findUserById(session.userId);
  if (!user) {
    return res.status(401).json({ error: 'Authenticated user not found' });
  }

  // Enforce MFA for Owner/Admin roles
  const membership = store.getMembership(session.activeTenantId, user.id);
  if (!membership) {
    store.recordAuditEvent({
      tenantId: session.activeTenantId,
      actorId: user.id,
      actorEmail: user.email,
      actorRole: 'anonymous',
      action: 'auth.membership_denied',
      resourceType: 'tenant',
      resourceId: session.activeTenantId,
      outcome: 'denied',
      before: null,
      after: { reason: 'No active tenant membership' },
    });
    return res.status(403).json({ error: 'Forbidden: No active membership in resolved tenant' });
  }

  if ((membership.role === 'owner' || membership.role === 'admin') && !session.mfaVerified) {
    return res.status(403).json({ error: 'MFA verification required for privileged role' });
  }

  // Zero-trust rule: Never trust a client-supplied tenant ID header or query param if it differs from session
  const clientHeaderTenant = req.headers['x-tenant-id'];
  if (
    typeof clientHeaderTenant === 'string' &&
    clientHeaderTenant.length > 0 &&
    clientHeaderTenant !== session.activeTenantId
  ) {
    store.recordAuditEvent({
      tenantId: session.activeTenantId,
      actorId: user.id,
      actorEmail: user.email,
      actorRole: membership.role,
      action: 'security.cross_tenant_attempt_blocked',
      resourceType: 'tenant',
      resourceId: clientHeaderTenant,
      outcome: 'denied',
      before: { sessionTenantId: session.activeTenantId },
      after: { attemptedTenantId: clientHeaderTenant, path: req.path },
    });
    return res.status(403).json({
      error: 'Forbidden: Cross-tenant access denied and logged',
    });
  }

  req.auth = {
    session,
    user,
    tenantId: session.activeTenantId,
    role: membership.role,
  };
  next();
}

export function requirePermission(permission: Permission) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const ctx = req.auth;
    if (!ctx) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    if (!hasPermission(ctx.role, permission)) {
      store.recordAuditEvent({
        tenantId: ctx.tenantId,
        actorId: ctx.user.id,
        actorEmail: ctx.user.email,
        actorRole: ctx.role,
        action: 'rbac.permission_denied',
        resourceType: 'endpoint',
        resourceId: `${req.method} ${req.path}`,
        outcome: 'denied',
        before: null,
        after: { requiredPermission: permission, actorRole: ctx.role },
      });
      return res.status(403).json({
        error: `Forbidden: Role '${ctx.role}' lacks permission '${permission}'`,
      });
    }
    next();
  };
}
