import express from 'express';
import {
  clearSessionCookie,
  hasPermission,
  parseCookies,
  requireAuth,
  requirePermission,
  ROLE_PERMISSIONS,
  setSessionCookie,
  verifySessionCookieValue,
  type AuthenticatedRequest,
} from './auth.ts';
import {
  AWS_READ_ONLY_POLICY_DOCUMENT,
  AZURE_SECURITY_READER_ACTIONS,
} from './connectorRegistry.ts';
import { redactSensitiveFields } from './cryptoVault.ts';
import { store } from './store.ts';
import type {
  AgentStatus,
  AgentType,
  ComplianceFramework,
  EnforcementAction,
  PlaybookId,
  RiskFactorInputs,
  RolloutStage,
} from '../src/types/security.ts';

export function createApiRouter() {
  const router = express.Router();
  router.use(express.json());

  router.get('/health', (_req, res) => {
    const persistence = store.getPersistenceInfo();
    res.json({
      ok: true,
      persistenceEnabled: persistence.enabled,
      uptimeSeconds: Math.round(process.uptime()),
    });
  });

  // Public inbound demo / briefing request persistence
  router.post('/demo-requests', (req, res) => {
    const body = (req.body ?? {}) as {
      name?: string;
      email?: string;
      company?: string;
    };
    try {
      const request = store.submitDemoRequest({
        name: body.name ?? '',
        email: body.email ?? '',
        company: body.company ?? '',
      });
      res.status(201).json({ request });
    } catch (err) {
      res.status(400).json({ error: (err as Error).message });
    }
  });

  router.get(
    '/demo-requests',
    requireAuth,
    requirePermission('tenant:read'),
    (_req, res) => {
      res.json({ requests: store.listDemoRequests() });
    }
  );

  // Public list of sandbox enterprise SSO personas for demo sign-in
  router.get('/auth/personas', (_req, res) => {
    res.json({ personas: store.listUsersForDemoSignIn() });
  });

  // Non-throwing session status check for SPA boot (avoids noisy 401 before demo login)
  router.get('/auth/session', (req, res) => {
    const cookies = parseCookies(req.headers.cookie);
    const sessionId = verifySessionCookieValue(cookies.eoa_session);
    const session = sessionId ? store.getSession(sessionId) : null;
    const user = session ? store.findUserById(session.userId) : null;
    const membership =
      session && user ? store.getMembership(session.activeTenantId, user.id) : null;
    if (!session || !user || !membership) {
      return res.json({ authenticated: false });
    }
    const memberships = store.getMembershipsForUser(user.id).map((m) => ({
      tenantId: m.tenantId,
      tenantName: store.getTenant(m.tenantId).name,
      role: m.role,
    }));
    return res.json({
      authenticated: true,
      user,
      activeTenantId: session.activeTenantId,
      role: membership.role,
      permissions: ROLE_PERMISSIONS[membership.role],
      mfaVerified: session.mfaVerified,
      memberships,
    });
  });

  // Current authenticated session context (resolved strictly server-side)
  router.get('/auth/me', requireAuth, (req: AuthenticatedRequest, res) => {
    const auth = req.auth!;
    const memberships = store.getMembershipsForUser(auth.user.id).map((m) => ({
      tenantId: m.tenantId,
      tenantName: store.getTenant(m.tenantId).name,
      role: m.role,
    }));
    res.json({
      user: auth.user,
      activeTenantId: auth.tenantId,
      role: auth.role,
      permissions: ROLE_PERMISSIONS[auth.role],
      mfaVerified: auth.session.mfaVerified,
      memberships,
    });
  });

  // Enterprise SSO + MFA login endpoint (issues HttpOnly signed cookie; no tokens in localStorage)
  router.post('/auth/login', (req, res) => {
    const { email, totpCode, tenantId } = req.body as {
      email?: string;
      totpCode?: string;
      tenantId?: string;
    };

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const user = store.findUserByEmail(email);
    if (!user) {
      return res.status(401).json({ error: 'Unknown identity provider principal' });
    }

    if (!user.interactiveAllowed) {
      const memberships = store.getMembershipsForUser(user.id);
      if (memberships[0]) {
        store.recordAuditEvent({
          tenantId: memberships[0].tenantId,
          actorId: user.id,
          actorEmail: user.email,
          actorRole: 'service_account',
          action: 'auth.interactive_login_blocked',
          resourceType: 'session',
          resourceId: user.id,
          outcome: 'denied',
          before: null,
          after: { reason: 'Service accounts cannot perform interactive login' },
        });
      }
      return res.status(403).json({
        error: 'Service accounts are restricted to scoped API access and cannot sign in interactively.',
      });
    }

    const memberships = store.getMembershipsForUser(user.id);
    if (memberships.length === 0) {
      return res.status(403).json({ error: 'User has no active tenant membership' });
    }

    const chosenMembership = tenantId
      ? memberships.find((m) => m.tenantId === tenantId)
      : memberships[0];

    if (!chosenMembership) {
      store.recordAuditEvent({
        tenantId: memberships[0].tenantId,
        actorId: user.id,
        actorEmail: user.email,
        actorRole: memberships[0].role,
        action: 'auth.cross_tenant_login_blocked',
        resourceType: 'tenant',
        resourceId: tenantId ?? 'unknown',
        outcome: 'denied',
        before: null,
        after: { attemptedTenantId: tenantId },
      });
      return res.status(403).json({ error: 'Forbidden: User is not a member of requested tenant' });
    }

    const needsMfa =
      chosenMembership.role === 'owner' || chosenMembership.role === 'admin' || user.mfaEnabled;

    if (needsMfa && (!totpCode || !/^\d{6}$/.test(totpCode.trim()))) {
      return res.status(401).json({
        error: 'MFA verification required. Enter a 6-digit TOTP authenticator code.',
        mfaRequired: true,
      });
    }

    const session = store.createSession(
      user.id,
      chosenMembership.tenantId,
      needsMfa ? true : false
    );
    setSessionCookie(res, session.sessionId);

    store.recordAuditEvent({
      tenantId: chosenMembership.tenantId,
      actorId: user.id,
      actorEmail: user.email,
      actorRole: chosenMembership.role,
      action: 'auth.sso_login_succeeded',
      resourceType: 'session',
      resourceId: session.sessionId,
      outcome: 'allowed',
      before: null,
      after: { idp: user.idp, mfaVerified: session.mfaVerified, role: chosenMembership.role },
    });

    res.json({
      user,
      activeTenantId: chosenMembership.tenantId,
      role: chosenMembership.role,
      permissions: ROLE_PERMISSIONS[chosenMembership.role],
      mfaVerified: session.mfaVerified,
      memberships: memberships.map((m) => ({
        tenantId: m.tenantId,
        tenantName: store.getTenant(m.tenantId).name,
        role: m.role,
      })),
    });
  });

  // Rotate session cookie (refresh token rotation pattern)
  router.post('/auth/rotate', requireAuth, (req: AuthenticatedRequest, res) => {
    const auth = req.auth!;
    const rotated = store.rotateSession(auth.session.sessionId);
    if (!rotated) {
      return res.status(401).json({ error: 'Unable to rotate session' });
    }
    setSessionCookie(res, rotated.sessionId);
    res.json({ rotated: true, expiresAt: rotated.expiresAt });
  });

  // Switch active tenant ONLY among verified memberships of the authenticated user
  router.post('/auth/switch-tenant', requireAuth, (req: AuthenticatedRequest, res) => {
    const auth = req.auth!;
    const { tenantId } = req.body as { tenantId?: string };
    if (!tenantId) {
      return res.status(400).json({ error: 'tenantId is required' });
    }

    const switched = store.switchSessionTenant(auth.session.sessionId, tenantId);
    if (!switched) {
      store.recordAuditEvent({
        tenantId: auth.tenantId,
        actorId: auth.user.id,
        actorEmail: auth.user.email,
        actorRole: auth.role,
        action: 'security.unauthorized_tenant_switch_blocked',
        resourceType: 'tenant',
        resourceId: tenantId,
        outcome: 'denied',
        before: { activeTenantId: auth.tenantId },
        after: { requestedTenantId: tenantId },
      });
      return res.status(403).json({
        error: 'Forbidden: Your account does not hold membership in the requested tenant.',
      });
    }

    const nextMembership = store.getMembership(tenantId, auth.user.id)!;
    store.recordAuditEvent({
      tenantId,
      actorId: auth.user.id,
      actorEmail: auth.user.email,
      actorRole: nextMembership.role,
      action: 'tenant.context_switched',
      resourceType: 'tenant',
      resourceId: tenantId,
      outcome: 'allowed',
      before: { tenantId: auth.tenantId },
      after: { tenantId, role: nextMembership.role },
    });

    res.json({
      activeTenantId: tenantId,
      role: nextMembership.role,
      permissions: ROLE_PERMISSIONS[nextMembership.role],
    });
  });

  router.post('/auth/logout', requireAuth, (req: AuthenticatedRequest, res) => {
    const auth = req.auth!;
    store.recordAuditEvent({
      tenantId: auth.tenantId,
      actorId: auth.user.id,
      actorEmail: auth.user.email,
      actorRole: auth.role,
      action: 'auth.logout',
      resourceType: 'session',
      resourceId: auth.session.sessionId,
      outcome: 'allowed',
      before: null,
      after: null,
    });
    store.deleteSession(auth.session.sessionId);
    clearSessionCookie(res);
    res.json({ ok: true });
  });

  // Tenant-scoped workspace bundle
  router.get(
    '/workspace',
    requireAuth,
    requirePermission('tenant:read'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const bundle = store.getSharedWorkspaceBundle(
        auth.tenantId,
        auth.role,
        auth.user.email
      );
      const graph = store.getExposurePaths(auth.tenantId);
      const policy = store.getPolicyState(auth.tenantId);
      const auditEvents = hasPermission(auth.role, 'audit:read')
        ? store.getAuditEvents(auth.tenantId)
        : [];
      const enterprise = store.getEnterpriseState(auth.tenantId);
      const tenants = store.listAuthorizedTenantsForUser(auth.user.id);

      res.json({
        ...bundle,
        tenants,
        graph,
        policy,
        auditEvents,
        enterprise,
      });
    }
  );

  // Graph exposure traversal query
  router.get(
    '/graph/exposure-paths',
    requireAuth,
    requirePermission('graph:read'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const agentId = typeof req.query.agentId === 'string' ? req.query.agentId : undefined;
      const result = store.getExposurePaths(auth.tenantId, agentId);
      res.json(result);
    }
  );

  // Detection rules catalog
  router.get(
    '/detection-rules',
    requireAuth,
    requirePermission('findings:read'),
    (_req, res) => {
      res.json({ rules: store.getDetectionRules() });
    }
  );

  // Findings management: Ticket routing (Jira / ServiceNow) + Approval-gated remediation + Sync verification
  router.post(
    '/findings/ticket-all',
    requireAuth,
    requirePermission('findings:manage'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const { provider, assignee, notifyChannels } = (req.body ?? {}) as {
        provider?: 'jira' | 'servicenow';
        assignee?: string;
        notifyChannels?: string[];
      };
      const result = store.createTicketsForAllOpenFindings(
        auth.tenantId,
        {
          provider: provider === 'servicenow' ? 'servicenow' : 'jira',
          assignee: assignee || 'Cloud Security',
          notifyChannels,
        },
        { id: auth.user.id, email: auth.user.email, role: auth.role }
      );
      res.json(result);
    }
  );

  router.post(
    '/findings/:findingId/jira',
    requireAuth,
    requirePermission('findings:manage'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const { assignee } = req.body as { assignee?: string };
      try {
        const updated = store.createJiraTicket(
          auth.tenantId,
          req.params.findingId,
          assignee || 'Cloud Security',
          { id: auth.user.id, email: auth.user.email, role: auth.role }
        );
        res.json({ finding: updated });
      } catch (err) {
        res.status(404).json({ error: (err as Error).message });
      }
    }
  );

  router.post(
    '/findings/:findingId/ticket',
    requireAuth,
    requirePermission('findings:manage'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const { provider, assignee, notifyChannels } = req.body as {
        provider?: 'jira' | 'servicenow';
        assignee?: string;
        notifyChannels?: string[];
      };
      try {
        const updated = store.createRemediationTicket(
          auth.tenantId,
          req.params.findingId,
          {
            provider: provider === 'servicenow' ? 'servicenow' : 'jira',
            assignee: assignee || 'Cloud Security',
            notifyChannels,
          },
          { id: auth.user.id, email: auth.user.email, role: auth.role }
        );
        res.json({ finding: updated });
      } catch (err) {
        res.status(404).json({ error: (err as Error).message });
      }
    }
  );

  router.post(
    '/findings/:findingId/dry-run',
    requireAuth,
    requirePermission('findings:manage'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      try {
        const updated = store.runFindingDryRun(auth.tenantId, req.params.findingId, {
          id: auth.user.id,
          email: auth.user.email,
          role: auth.role,
        });
        res.json({ finding: updated });
      } catch (err) {
        res.status(404).json({ error: (err as Error).message });
      }
    }
  );

  router.post(
    '/findings/:findingId/approve',
    requireAuth,
    requirePermission('findings:manage'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const breakGlassDualApproval = Boolean(req.body?.breakGlassDualApproval);
      try {
        const updated = store.approveFindingRemediation(
          auth.tenantId,
          req.params.findingId,
          { breakGlassDualApproval },
          { id: auth.user.id, email: auth.user.email, role: auth.role }
        );
        res.json({ finding: updated });
      } catch (err) {
        res.status(404).json({ error: (err as Error).message });
      }
    }
  );

  router.post(
    '/findings/:findingId/apply-remediation',
    requireAuth,
    requirePermission('findings:manage'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      try {
        const updated = store.applyApprovedRemediation(auth.tenantId, req.params.findingId, {
          id: auth.user.id,
          email: auth.user.email,
          role: auth.role,
        });
        res.json({ finding: updated });
      } catch (err) {
        const msg = (err as Error).message;
        const status = msg.includes('Approval required') ? 409 : 404;
        res.status(status).json({ error: msg });
      }
    }
  );

  router.post(
    '/findings/:findingId/rollback',
    requireAuth,
    requirePermission('findings:manage'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      try {
        const updated = store.rollbackFindingRemediation(auth.tenantId, req.params.findingId, {
          id: auth.user.id,
          email: auth.user.email,
          role: auth.role,
        });
        res.json({ finding: updated });
      } catch (err) {
        res.status(404).json({ error: (err as Error).message });
      }
    }
  );

  router.post(
    '/findings/:findingId/verify-closure',
    requireAuth,
    requirePermission('findings:manage'),
    async (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      try {
        const result = await store.verifyAndCloseFinding(auth.tenantId, req.params.findingId, {
          id: auth.user.id,
          email: auth.user.email,
          role: auth.role,
        });
        if (!result.closed) {
          return res.status(409).json({
            closed: false,
            error: result.finding.verification?.message || 'Exposure path still present in graph.',
            finding: result.finding,
          });
        }
        return res.json({ closed: true, finding: result.finding });
      } catch (err) {
        return res.status(404).json({ error: (err as Error).message });
      }
    }
  );

  router.post(
    '/findings/:findingId/remediate',
    requireAuth,
    requirePermission('findings:manage'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      try {
        const updated = store.markFindingRemediated(auth.tenantId, req.params.findingId, {
          id: auth.user.id,
          email: auth.user.email,
          role: auth.role,
        });
        res.json({ finding: updated });
      } catch (err) {
        const msg = (err as Error).message;
        const status = msg.includes('Cannot close finding') ? 409 : 404;
        res.status(status).json({ error: msg });
      }
    }
  );

  // Policy administration
  router.post(
    '/policy/mode',
    requireAuth,
    requirePermission('policies:manage'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const { mode } = req.body as { mode?: 'observe' | 'enforce' };
      if (mode !== 'observe' && mode !== 'enforce') {
        return res.status(400).json({ error: 'Invalid policy mode' });
      }
      const next = store.setPolicyMode(auth.tenantId, mode, {
        id: auth.user.id,
        email: auth.user.email,
        role: auth.role,
      });
      res.json({ mode: next });
    }
  );

  router.post(
    '/policy/rules/:ruleId/toggle',
    requireAuth,
    requirePermission('policies:manage'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      try {
        const rule = store.togglePolicyRule(auth.tenantId, req.params.ruleId, {
          id: auth.user.id,
          email: auth.user.email,
          role: auth.role,
        });
        res.json({ rule });
      } catch (err) {
        res.status(404).json({ error: (err as Error).message });
      }
    }
  );

  router.post(
    '/policy/rules',
    requireAuth,
    requirePermission('policies:manage'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const body = (req.body ?? {}) as {
        name?: string;
        scope?: string;
        action?: 'allow' | 'redact' | 'block';
        condition?: string;
      };
      const action =
        body.action === 'allow' || body.action === 'redact' || body.action === 'block'
          ? body.action
          : 'block';
      try {
        const rule = store.createPolicyRule(
          auth.tenantId,
          {
            name: body.name ?? '',
            scope: body.scope ?? '',
            action,
            condition: body.condition ?? '',
          },
          { id: auth.user.id, email: auth.user.email, role: auth.role }
        );
        res.status(201).json({ rule });
      } catch (err) {
        res.status(400).json({ error: (err as Error).message });
      }
    }
  );

  router.post(
    '/enterprise/policies',
    requireAuth,
    requirePermission('policies:manage'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const body = (req.body ?? {}) as {
        name?: string;
        agents?: string[];
        tools?: string[];
        dataClassification?: string[];
        decision?: EnforcementAction;
        strategy?: 'tokenization' | 'masking' | 'strict_block' | 'step_up_mfa' | 'downgrade_readonly';
      };
      try {
        const policy = store.createGatewayPolicy(
          auth.tenantId,
          {
            name: body.name ?? '',
            agents: Array.isArray(body.agents) && body.agents.length > 0 ? body.agents : ['*'],
            tools: Array.isArray(body.tools) && body.tools.length > 0 ? body.tools : ['*'],
            dataClassification:
              Array.isArray(body.dataClassification) && body.dataClassification.length > 0
                ? body.dataClassification
                : ['pii'],
            decision: body.decision ?? 'block',
            strategy: body.strategy,
          },
          { id: auth.user.id, email: auth.user.email, role: auth.role }
        );
        res.status(201).json({ policy });
      } catch (err) {
        res.status(400).json({ error: (err as Error).message });
      }
    }
  );

  // Agent Registration & Governance Updates (Owner assignment, Quarantine/Restrict, Risk Recalculation)
  router.post(
    '/agents',
    requireAuth,
    requirePermission('findings:manage'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const body = (req.body ?? {}) as {
        name?: string;
        owner?: string;
        ownerTeam?: string;
        type?: AgentType;
        identity?: string;
        businessService?: string;
        tools?: string[];
        permissions?: string[];
        dataSources?: string[];
      };
      try {
        const agent = store.createAgent(
          auth.tenantId,
          {
            name: body.name ?? '',
            owner: body.owner,
            ownerTeam: body.ownerTeam,
            type: body.type,
            identity: body.identity,
            businessService: body.businessService,
            tools: body.tools,
            permissions: body.permissions,
            dataSources: body.dataSources,
          },
          { id: auth.user.id, email: auth.user.email, role: auth.role }
        );
        res.status(201).json({ agent });
      } catch (err) {
        res.status(400).json({ error: (err as Error).message });
      }
    }
  );

  router.patch(
    '/agents/:agentId',
    requireAuth,
    requirePermission('findings:manage'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const body = (req.body ?? {}) as {
        owner?: string;
        ownerTeam?: string;
        status?: AgentStatus;
        businessService?: string;
        permissions?: string[];
      };
      try {
        const agent = store.updateAgentGovernance(
          auth.tenantId,
          req.params.agentId,
          body,
          { id: auth.user.id, email: auth.user.email, role: auth.role }
        );
        res.json({ agent });
      } catch (err) {
        res.status(404).json({ error: (err as Error).message });
      }
    }
  );

  // Dynamic 6-factor risk recalculation when agent permissions, ownership, or activity change
  router.post(
    '/agents/:agentId/risk-signals',
    requireAuth,
    requirePermission('findings:manage'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const body = req.body as {
        owner?: string;
        permissions?: string[];
        dailyCalls?: number;
        overrides?: Partial<RiskFactorInputs>;
      };
      try {
        const agent = store.updateAgentRiskSignals(
          auth.tenantId,
          req.params.agentId,
          {
            owner: body.owner,
            permissions: body.permissions,
            dailyCalls: body.dailyCalls,
            overrides: body.overrides,
          },
          { id: auth.user.id, email: auth.user.email, role: auth.role }
        );
        res.json({ agent });
      } catch (err) {
        res.status(404).json({ error: (err as Error).message });
      }
    }
  );

  // Runtime AI & MCP Gateway inspection (observe mode forwards all traffic without blocking)
  router.post(
    '/gateway/inspect',
    requireAuth,
    requirePermission('policies:read'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const body = req.body as {
        agentId?: string;
        provider?: string;
        model?: string;
        tool?: string;
        mcpServer?: string;
        promptText?: string;
        responseText?: string;
        targetResource?: string;
      };
      if (!body.agentId || !body.tool) {
        return res.status(400).json({ error: 'agentId and tool are required' });
      }
      try {
        const result = store.inspectGatewayTraffic(
          auth.tenantId,
          {
            agentId: body.agentId,
            provider: body.provider,
            model: body.model,
            tool: body.tool,
            mcpServer: body.mcpServer,
            promptText: body.promptText,
            responseText: body.responseText,
            targetResource: body.targetResource,
          },
          { id: auth.user.id, email: auth.user.email, role: auth.role }
        );
        res.json(result);
      } catch (err) {
        res.status(404).json({ error: (err as Error).message });
      }
    }
  );

  // Privacy-first customer-controlled redacted excerpt retention toggle
  router.post(
    '/gateway/retention',
    requireAuth,
    requirePermission('policies:manage'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const retentionConfig = store.setRetentionOptIn(
        auth.tenantId,
        Boolean(req.body?.redactedExcerptOptIn),
        { id: auth.user.id, email: auth.user.email, role: auth.role }
      );
      res.json({ retentionConfig });
    }
  );

  // Read-only cloud connector policy templates & onboarding
  router.get(
    '/connectors/templates',
    requireAuth,
    requirePermission('connectors:read'),
    (_req, res) => {
      res.json({
        awsReadOnlyPolicy: AWS_READ_ONLY_POLICY_DOCUMENT,
        azureSecurityReaderActions: AZURE_SECURITY_READER_ACTIONS,
        entraReadOnlyScopes: store.registry.get('entra_id').requiredReadOnlyScopes,
      });
    }
  );

  router.post(
    '/connectors/onboard',
    requireAuth,
    requirePermission('connectors:manage'),
    async (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const { provider, config } = req.body as {
        provider?: 'entra_id' | 'aws' | 'azure';
        config?: Record<string, string>;
      };
      if (provider !== 'entra_id' && provider !== 'aws' && provider !== 'azure') {
        return res.status(400).json({ error: 'Provider must be entra_id, aws, or azure.' });
      }
      try {
        const result = await store.connectCloudProvider(
          auth.tenantId,
          provider,
          config ?? {},
          { id: auth.user.id, email: auth.user.email, role: auth.role }
        );
        res.json(result);
      } catch (err) {
        res.status(400).json({ error: (err as Error).message });
      }
    }
  );

  router.post(
    '/connectors/onboard-all',
    requireAuth,
    requirePermission('connectors:manage'),
    async (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      try {
        const result = await store.connectAllCloudProviders(auth.tenantId, {
          id: auth.user.id,
          email: auth.user.email,
          role: auth.role,
        });
        res.json(result);
      } catch (err) {
        res.status(400).json({ error: (err as Error).message });
      }
    }
  );

  // Pluggable Connector OAuth PKCE, KMS Token Rotation, Discovery Sync & Revocation
  router.get(
    '/connectors',
    requireAuth,
    requirePermission('connectors:read'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const items = store.getConnectors(auth.tenantId).map((c) =>
        redactSensitiveFields({
          ...c,
          credentialMeta: store.getCredentialMetadata(auth.tenantId, c.id),
        })
      );
      res.json({ connectors: items });
    }
  );

  router.post(
    '/connectors/:connectorId/oauth/start',
    requireAuth,
    requirePermission('connectors:manage'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      try {
        const pkce = store.startPkceAuthorization(auth.tenantId, req.params.connectorId);
        res.json(pkce);
      } catch (err) {
        res.status(404).json({ error: (err as Error).message });
      }
    }
  );

  router.post(
    '/connectors/:connectorId/oauth/callback',
    requireAuth,
    requirePermission('connectors:manage'),
    async (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const { authSessionId, codeVerifier } = req.body as {
        authSessionId?: string;
        codeVerifier?: string;
      };
      if (!authSessionId || !codeVerifier) {
        return res.status(400).json({ error: 'authSessionId and codeVerifier are required' });
      }
      try {
        const connector = await store.completePkceAuthorization(
          auth.tenantId,
          req.params.connectorId,
          authSessionId,
          codeVerifier,
          { id: auth.user.id, email: auth.user.email, role: auth.role }
        );
        res.json({ connector: redactSensitiveFields(connector as unknown as Record<string, unknown>) });
      } catch (err) {
        res.status(400).json({ error: (err as Error).message });
      }
    }
  );

  router.post(
    '/connectors/:connectorId/rotate-token',
    requireAuth,
    requirePermission('connectors:manage'),
    async (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      try {
        const result = await store.rotateConnectorToken(auth.tenantId, req.params.connectorId, {
          id: auth.user.id,
          email: auth.user.email,
          role: auth.role,
        });
        res.json(result);
      } catch (err) {
        res.status(400).json({ error: (err as Error).message });
      }
    }
  );

  router.post(
    '/connectors/:connectorId/sync',
    requireAuth,
    requirePermission('connectors:manage'),
    async (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const simulateFailure = Boolean(req.body?.simulateFailure);
      try {
        const result = await store.syncConnector(
          auth.tenantId,
          req.params.connectorId,
          { id: auth.user.id, email: auth.user.email, role: auth.role },
          { simulateFailure }
        );
        res.json(result);
      } catch (err) {
        res.status(502).json({ error: (err as Error).message });
      }
    }
  );

  router.post(
    '/connectors/:connectorId/disconnect',
    requireAuth,
    requirePermission('connectors:manage'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      try {
        const connector = store.revokeConnector(auth.tenantId, req.params.connectorId, {
          id: auth.user.id,
          email: auth.user.email,
          role: auth.role,
        });
        res.json({ connector });
      } catch (err) {
        res.status(404).json({ error: (err as Error).message });
      }
    }
  );

  // Immutable hash-chained audit trail + integrity + export + retention
  router.get(
    '/audit-events',
    requireAuth,
    requirePermission('audit:read'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const search = typeof req.query.search === 'string' ? req.query.search : undefined;
      const outcomeRaw = typeof req.query.outcome === 'string' ? req.query.outcome : 'all';
      const outcome =
        outcomeRaw === 'allowed' || outcomeRaw === 'denied' ? outcomeRaw : 'all';
      res.json({
        events: store.getAuditEvents(auth.tenantId, { search, outcome }),
        integrity: store.getAuditIntegrity(auth.tenantId),
        retentionDays: store.getEnterpriseState(auth.tenantId).auditRetentionDays,
      });
    }
  );

  router.post(
    '/audit-events/export',
    requireAuth,
    requirePermission('audit:read'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const fromDate = typeof req.body?.fromDate === 'string' ? req.body.fromDate : undefined;
      const toDate = typeof req.body?.toDate === 'string' ? req.body.toDate : undefined;
      const pkg = store.exportAuditLedger(
        auth.tenantId,
        { fromDate, toDate },
        { id: auth.user.id, email: auth.user.email, role: auth.role }
      );
      res.json(pkg);
    }
  );

  router.post(
    '/enterprise/audit/retention',
    requireAuth,
    requirePermission('tenant:admin'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const days = Number(req.body?.retentionDays);
      try {
        const updated = store.setAuditRetentionDays(auth.tenantId, days, {
          id: auth.user.id,
          email: auth.user.email,
          role: auth.role,
        });
        res.json({ retentionDays: updated });
      } catch (err) {
        res.status(400).json({ error: (err as Error).message });
      }
    }
  );

  // Enterprise Control Plane: PEP/PDP, Progressive Rollout, SOAR Playbooks, SSO/SCIM & Release Gates
  router.get(
    '/enterprise/state',
    requireAuth,
    requirePermission('tenant:read'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      res.json(store.getEnterpriseState(auth.tenantId));
    }
  );

  router.post(
    '/enterprise/rollout-stage',
    requireAuth,
    requirePermission('policies:manage'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const stage = req.body?.stage as RolloutStage | undefined;
      const allowed: RolloutStage[] = [
        'observe',
        'advisory',
        'selective_enforcement',
        'approval_gated_response',
        'full_enforcement',
      ];
      if (!stage || !allowed.includes(stage)) {
        return res.status(400).json({ error: 'Invalid rollout stage' });
      }
      const result = store.setRolloutStage(auth.tenantId, stage, {
        id: auth.user.id,
        email: auth.user.email,
        role: auth.role,
      });
      res.json(result);
    }
  );

  router.post(
    '/enterprise/pep/evaluate',
    requireAuth,
    requirePermission('policies:read'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const body = req.body as {
        agentId?: string;
        provider?: string;
        model?: string;
        tool?: string;
        mcpServer?: string;
        promptText?: string;
        targetResource?: string;
        requestedActionOverride?: EnforcementAction;
        mfaVerified?: boolean;
        replayNonce?: string;
      };
      if (!body.agentId || !body.tool) {
        return res.status(400).json({ error: 'agentId and tool are required' });
      }
      try {
        const result = store.evaluatePepRequest(
          auth.tenantId,
          {
            agentId: body.agentId,
            provider: body.provider,
            model: body.model,
            tool: body.tool,
            mcpServer: body.mcpServer,
            promptText: body.promptText,
            targetResource: body.targetResource,
            requestedActionOverride: body.requestedActionOverride,
            mfaVerified: body.mfaVerified,
            replayNonce: body.replayNonce,
          },
          { id: auth.user.id, email: auth.user.email, role: auth.role }
        );
        res.json(result);
      } catch (err) {
        const msg = (err as Error).message;
        res.status(msg.includes('Replay protection') ? 409 : 400).json({ error: msg });
      }
    }
  );

  router.post(
    '/enterprise/kill-switch',
    requireAuth,
    requirePermission('policies:manage'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const paused = Boolean(req.body?.paused);
      const reason = typeof req.body?.reason === 'string' ? req.body.reason : '';
      const killSwitch = store.setKillSwitch(auth.tenantId, paused, reason, {
        id: auth.user.id,
        email: auth.user.email,
        role: auth.role,
      });
      res.json({ killSwitch });
    }
  );

  router.post(
    '/enterprise/playbooks/:playbookId/dry-run',
    requireAuth,
    requirePermission('policies:read'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const agentId = typeof req.body?.agentId === 'string' ? req.body.agentId : 'agent_finance_copilot';
      try {
        const execution = store.dryRunPlaybook(
          auth.tenantId,
          req.params.playbookId as PlaybookId,
          agentId,
          { id: auth.user.id, email: auth.user.email, role: auth.role }
        );
        res.json({ execution });
      } catch (err) {
        res.status(404).json({ error: (err as Error).message });
      }
    }
  );

  router.post(
    '/enterprise/playbooks/:playbookId/run',
    requireAuth,
    requirePermission('policies:manage'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const agentId = typeof req.body?.agentId === 'string' ? req.body.agentId : 'agent_finance_copilot';
      const triggerSignal = typeof req.body?.triggerSignal === 'string' ? req.body.triggerSignal : undefined;
      try {
        const execution = store.executePlaybook(
          auth.tenantId,
          req.params.playbookId as PlaybookId,
          agentId,
          { id: auth.user.id, email: auth.user.email, role: auth.role },
          triggerSignal
        );
        res.json({ execution });
      } catch (err) {
        const msg = (err as Error).message;
        const status = msg.includes('Kill switch') || msg.includes('Rate limit') ? 429 : 404;
        res.status(status).json({ error: msg });
      }
    }
  );

  router.post(
    '/enterprise/responses/:executionId/approve',
    requireAuth,
    requirePermission('policies:manage'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      try {
        const execution = store.approvePlaybookExecution(auth.tenantId, req.params.executionId, {
          id: auth.user.id,
          email: auth.user.email,
          role: auth.role,
        });
        res.json({ execution });
      } catch (err) {
        res.status(404).json({ error: (err as Error).message });
      }
    }
  );

  router.post(
    '/enterprise/responses/:executionId/rollback',
    requireAuth,
    requirePermission('policies:manage'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      try {
        const execution = store.rollbackPlaybookExecution(auth.tenantId, req.params.executionId, {
          id: auth.user.id,
          email: auth.user.email,
          role: auth.role,
        });
        res.json({ execution });
      } catch (err) {
        res.status(404).json({ error: (err as Error).message });
      }
    }
  );

  router.post(
    '/enterprise/sso/config',
    requireAuth,
    requirePermission('tenant:admin'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const body = req.body as {
        protocol?: 'saml_2_0' | 'oidc';
        ssoEnforced?: boolean;
        localPasswordFallbackDisabled?: boolean;
        mfaRequiredForAdmins?: boolean;
        scimEnabled?: boolean;
        rotateCertificate?: boolean;
      };
      const ssoConfig = store.updateSsoConfig(auth.tenantId, body, {
        id: auth.user.id,
        email: auth.user.email,
        role: auth.role,
      });
      res.json({ ssoConfig });
    }
  );

  router.post('/enterprise/sso/jit-login', (req, res) => {
    const body = req.body as {
      tenantId?: string;
      email?: string;
      displayName?: string;
      idpGroups?: string[];
      mfaMethod?: 'totp' | 'webauthn';
      totpCode?: string;
    };
    if (!body.email || !Array.isArray(body.idpGroups) || body.idpGroups.length === 0) {
      return res.status(400).json({ error: 'email and idpGroups are required for SSO JIT login' });
    }
    try {
      const result = store.jitSsoLogin(body.tenantId || 'tenant_northwind', {
        email: body.email,
        displayName: body.displayName,
        idpGroups: body.idpGroups,
        mfaMethod: body.mfaMethod,
        totpCode: body.totpCode,
      });
      setSessionCookie(res, result.session.sessionId);
      const memberships = store.getMembershipsForUser(result.user.id).map((m) => ({
        tenantId: m.tenantId,
        tenantName: store.getTenant(m.tenantId).name,
        role: m.role,
      }));
      res.json({
        user: result.user,
        activeTenantId: result.session.activeTenantId,
        role: result.role,
        permissions: ROLE_PERMISSIONS[result.role],
        mfaVerified: result.session.mfaVerified,
        memberships,
        ssoConfig: result.ssoConfig,
      });
    } catch (err) {
      res.status(401).json({ error: (err as Error).message, mfaRequired: true });
    }
  });

  router.post(
    '/enterprise/scim/provision',
    requireAuth,
    requirePermission('tenant:admin'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const body = req.body as {
        email?: string;
        displayName?: string;
        idpGroups?: string[];
        mfaEnrolled?: boolean;
      };
      if (!body.email || !Array.isArray(body.idpGroups) || body.idpGroups.length === 0) {
        return res.status(400).json({ error: 'email and idpGroups are required' });
      }
      const user = store.provisionScimUser(
        auth.tenantId,
        {
          email: body.email,
          displayName: body.displayName || body.email.split('@')[0],
          idpGroups: body.idpGroups,
          mfaEnrolled: body.mfaEnrolled,
        },
        { id: auth.user.id, email: auth.user.email, role: auth.role }
      );
      res.json({ user });
    }
  );

  router.post(
    '/enterprise/scim/deprovision',
    requireAuth,
    requirePermission('tenant:admin'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const target = typeof req.body?.email === 'string' ? req.body.email : req.body?.userId;
      if (!target) {
        return res.status(400).json({ error: 'email or userId is required' });
      }
      try {
        const result = store.deprovisionScimUser(auth.tenantId, target, {
          id: auth.user.id,
          email: auth.user.email,
          role: auth.role,
        });
        res.json(result);
      } catch (err) {
        res.status(404).json({ error: (err as Error).message });
      }
    }
  );

  router.post(
    '/enterprise/release-gates/verify',
    requireAuth,
    requirePermission('tenant:read'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const result = store.verifyReleaseGates(auth.tenantId, {
        id: auth.user.id,
        email: auth.user.email,
        role: auth.role,
      });
      res.json(result);
    }
  );

  router.post(
    '/enterprise/all-in-one/run',
    requireAuth,
    requirePermission('policies:manage'),
    async (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const body = (req.body ?? {}) as {
        ticketProvider?: 'jira' | 'servicenow';
        assignee?: string;
      };
      try {
        const result = await store.runAllInOneControlLoop(
          auth.tenantId,
          {
            ticketProvider: body.ticketProvider === 'servicenow' ? 'servicenow' : 'jira',
            assignee: body.assignee,
          },
          { id: auth.user.id, email: auth.user.email, role: auth.role }
        );
        res.json(result);
      } catch (err) {
        res.status(500).json({ error: (err as Error).message });
      }
    }
  );

  // Auditor-scoped, time-bounded compliance audit export
  router.post(
    '/compliance/export',
    requireAuth,
    requirePermission('compliance:export'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const framework = (
        typeof req.body?.framework === 'string' ? req.body.framework : 'all'
      ) as ComplianceFramework | 'all';
      const fromDate = typeof req.body?.fromDate === 'string' ? req.body.fromDate : undefined;
      const toDate = typeof req.body?.toDate === 'string' ? req.body.toDate : undefined;

      const pkg = store.exportComplianceAuditPackage(
        auth.tenantId,
        { framework, fromDate, toDate },
        { id: auth.user.id, email: auth.user.email, role: auth.role }
      );
      res.json({ exported: true, ...pkg });
    }
  );

  router.post(
    '/compliance/controls/:controlId/attest',
    requireAuth,
    requirePermission('compliance:export'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      const body = (req.body ?? {}) as {
        title?: string;
        summary?: string;
        source?: string;
      };
      try {
        const result = store.attestComplianceControl(
          auth.tenantId,
          req.params.controlId,
          {
            title: body.title,
            summary: body.summary ?? '',
            source: body.source,
          },
          { id: auth.user.id, email: auth.user.email, role: auth.role }
        );
        res.status(201).json(result);
      } catch (err) {
        res.status(400).json({ error: (err as Error).message });
      }
    }
  );

  router.post(
    '/system/reset-demo',
    requireAuth,
    requirePermission('tenant:admin'),
    (req: AuthenticatedRequest, res) => {
      const auth = req.auth!;
      store.resetToSeedState(
        { id: auth.user.id, email: auth.user.email, role: auth.role },
        auth.tenantId
      );
      res.json({ reset: true });
    }
  );

  return router;
}
