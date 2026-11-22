import crypto from 'node:crypto';
import type {
  Agent,
  AuditChainIntegrity,
  DlpClassification,
  EnforcementAction,
  GatewayPolicyDefinition,
  PlatformHardeningItem,
  PlaybookDefinition,
  PlaybookId,
  RolloutStage,
} from '../src/types/security.ts';
import type { AuditEvent, Role } from './types.ts';
import { classifyContent } from './governanceEngine.ts';

export const IDP_GROUP_ROLE_MAP: Record<string, Role> = {
  'EyesOfAgent-Owners': 'owner',
  'EyesOfAgent-SecurityAdmins': 'admin',
  'EyesOfAgent-Analysts': 'security_analyst',
  'EyesOfAgent-Compliance': 'compliance_manager',
  'EyesOfAgent-Auditors': 'auditor',
  'EyesOfAgent-AgentOwners': 'agent_owner',
};

const ROLE_PRIORITY: Role[] = [
  'owner',
  'admin',
  'security_analyst',
  'compliance_manager',
  'agent_owner',
  'auditor',
  'service_account',
];

export function mapIdpGroupsToRole(groups: string[]): Role {
  const mapped = groups
    .map((g) => IDP_GROUP_ROLE_MAP[g])
    .filter((r): r is Role => Boolean(r));
  if (mapped.length === 0) return 'auditor';
  mapped.sort((a, b) => ROLE_PRIORITY.indexOf(a) - ROLE_PRIORITY.indexOf(b));
  return mapped[0];
}

export const ENTERPRISE_YAML_POLICIES: GatewayPolicyDefinition[] = [
  {
    id: 'prevent_payroll_exfiltration',
    name: 'Prevent payroll export to external models',
    scope: {
      agents: ['agent_finance_copilot', 'finance-copilot'],
      tools: ['export_payroll'],
      data_classification: ['pii_financial', 'pii', 'financial'],
    },
    decision: 'block',
    mode: 'observe',
    severity: 'critical',
    actions: ['create_critical_finding', 'notify_security', 'preserve_evidence'],
    enabled: true,
    observeHits24h: 14,
    lastTriggered: '2m ago',
    yaml: `policy:
  id: prevent_payroll_exfiltration
  name: Prevent payroll export to external models
  scope:
    agents: [finance-copilot]
    tools: [export_payroll]
    data_classification: [pii_financial]
  decision: block
  actions:
    - create_critical_finding
    - notify_security
    - preserve_evidence`,
  },
  {
    id: 'redact_customer_pii',
    name: 'Redact customer PII in prompts',
    scope: {
      agents: ['*'],
      tools: ['*'],
      data_classification: ['pii'],
    },
    decision: 'redact',
    mode: 'observe',
    severity: 'high',
    actions: ['log_decision', 'attach_evidence'],
    enabled: true,
    observeHits24h: 312,
    lastTriggered: '8m ago',
    yaml: `policy:
  id: redact_customer_pii
  name: Redact customer PII in prompts
  scope:
    data_classification: [pii]
  decision: redact
  redaction:
    strategy: tokenization
  actions:
    - log_decision
    - attach_evidence`,
  },
];

export const RESPONSE_PLAYBOOKS: PlaybookDefinition[] = [
  {
    id: 'pb_sensitive_exfiltration',
    name: 'Sensitive-data exfiltration',
    trigger: 'PII/PHI/PCI sent to external model',
    severity: 'critical',
    automatedAction: 'Block request, quarantine tool, create critical finding',
    humanApprovalRequiredFor: 'Permanent IAM change',
    responderIdentity: 'svc-soar-responder (least-privilege containment)',
    rateLimitPerMinute: 5,
  },
  {
    id: 'pb_prompt_injection',
    name: 'Prompt injection',
    trigger: 'Suspicious instruction or tool-abuse pattern',
    severity: 'critical',
    automatedAction: 'Block tool call, preserve evidence, notify owner',
    humanApprovalRequiredFor: 'Agent disablement',
    responderIdentity: 'svc-soar-responder (least-privilege containment)',
    rateLimitPerMinute: 5,
  },
  {
    id: 'pb_compromised_identity',
    name: 'Compromised service identity',
    trigger: 'Anomalous credential use',
    severity: 'critical',
    automatedAction: 'Revoke session, flag credential rotation candidate, restrict scope',
    humanApprovalRequiredFor: 'Credential rotation',
    responderIdentity: 'svc-soar-responder (least-privilege containment)',
    rateLimitPerMinute: 5,
  },
  {
    id: 'pb_shadow_ai',
    name: 'Shadow AI detected',
    trigger: 'Unapproved AI app or MCP server',
    severity: 'high',
    automatedAction: 'Create finding, notify owner, add to review queue',
    humanApprovalRequiredFor: 'Blocking',
    responderIdentity: 'svc-soar-responder (least-privilege containment)',
    rateLimitPerMinute: 5,
  },
  {
    id: 'pb_overprivileged_agent',
    name: 'Over-privileged agent',
    trigger: 'Broad IAM permission or sensitive-data access',
    severity: 'high',
    automatedAction: 'Create finding and ticket',
    humanApprovalRequiredFor: 'Permission removal',
    responderIdentity: 'svc-soar-responder (least-privilege containment)',
    rateLimitPerMinute: 5,
  },
  {
    id: 'pb_data_loss',
    name: 'Data-loss event',
    trigger: 'Sensitive file sent externally',
    severity: 'critical',
    automatedAction: 'Block future similar calls, notify DPO/security',
    humanApprovalRequiredFor: 'Deletion or account suspension',
    responderIdentity: 'svc-soar-responder (least-privilege containment)',
    rateLimitPerMinute: 5,
  },
];

export const PLATFORM_HARDENING_MATRIX: PlatformHardeningItem[] = [
  {
    area: 'Tenant isolation',
    control: 'Enforced at API, database, cache, queue, storage, and graph layers',
    status: 'enforced',
  },
  {
    area: 'Secrets',
    control: 'KMS/Vault-backed AES-256-GCM encryption, rotation, no secrets in logs',
    status: 'enforced',
  },
  {
    area: 'Connector access',
    control: 'Read-only by default, scoped PKCE OAuth, ExternalId for AWS AssumeRole',
    status: 'enforced',
  },
  {
    area: 'Gateway',
    control: 'mTLS boundary, signed requests, replay nonce protection, sliding rate limits',
    status: 'enforced',
  },
  {
    area: 'Automation',
    control: 'Approval gates, dry-run diff, rollback snapshots, break-glass & kill switch',
    status: 'enforced',
  },
  {
    area: 'Infrastructure',
    control: 'IaC templates, least-privilege responder identity, network segmentation',
    status: 'verified',
  },
  {
    area: 'Supply chain',
    control: 'Signed builds, SBOM attestation, dependency scanning, provenance',
    status: 'verified',
  },
  {
    area: 'Incident response',
    control: 'SOAR playbooks, forensic hash preservation, DPO/security notification',
    status: 'enforced',
  },
];

export function detectPromptInjection(text: string): { detected: boolean; matchedPattern?: string } {
  const patterns: Array<[RegExp, string]> = [
    [/ignore\s+(all\s+)?previous\s+instructions/i, 'PROMPT_OVERRIDE_INSTRUCTION'],
    [/reveal\s+(your\s+)?system\s+prompt/i, 'SYSTEM_PROMPT_EXTRACTION'],
    [/bypass\s+(security|policy|guardrail|dlp)/i, 'POLICY_BYPASS_ATTEMPT'],
    [/curl\s+.*\|\s*(sh|bash)/i, 'SHELL_TOOL_ABUSE'],
    [/exfiltrate|dump\s+all\s+ssn|steal\s+credentials/i, 'EXFILTRATION_COMMAND'],
  ];
  for (const [regex, label] of patterns) {
    if (regex.test(text)) {
      return { detected: true, matchedPattern: label };
    }
  }
  return { detected: false };
}

export function tokenizeSensitiveContent(text: string): string {
  if (!text) return '';
  return text
    .replace(/\b\d{3}-\d{2}-\d{4}\b/g, 'tok_ssn_9f4a21')
    .replace(/\b(?:\d{4}[- ]?){3}\d{4}\b/g, 'tok_pan_4c18b0')
    .replace(/\b(?:DE|GB|FR|CH)\d{2}[A-Z0-9]{10,28}\b/g, 'tok_iban_7d20e3')
    .replace(/\b(sk-[a-zA-Z0-9]{6,}|AKIA[0-9A-Z]{12,}|ghp_[a-zA-Z0-9]{6,})\b/g, 'tok_secret_3a91c8')
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, 'tok_email_6e11d4');
}

export interface PdpEvaluationInput {
  agent: Agent;
  tool: string;
  model: string;
  promptText?: string;
  targetResource?: string;
  rolloutStage: RolloutStage;
  killSwitchPaused: boolean;
  requestedActionOverride?: EnforcementAction;
  mfaVerified?: boolean;
}

export interface PdpEvaluationResult {
  decision: EnforcementAction;
  reason: string;
  policyRule: string;
  classification: DlpClassification;
  promptInjectionDetected: boolean;
  promptInjectionSignal?: string;
  tokenizedPreview?: string;
  effectiveIdentity: string;
  effectiveModel: string;
  matchedPlaybookId?: PlaybookId;
  requiresApproval: boolean;
}

/**
 * Policy Decision Point (PDP): evaluates policy, DLP, injection signals, and rollout context
 * independently of the Gateway Policy Enforcement Point (PEP).
 */
export function evaluatePolicyDecisionPoint(input: PdpEvaluationInput): PdpEvaluationResult {
  const classification = classifyContent({
    promptText: input.promptText,
    tool: input.tool,
    targetResource: input.targetResource,
  });
  const injection = detectPromptInjection(input.promptText ?? '');

  let decision: EnforcementAction = 'allow';
  let reason = 'Request within baseline agent permissions and data classification policy.';
  let policyRule = 'default_zero_trust_baseline';
  let matchedPlaybookId: PlaybookId | undefined;
  let effectiveIdentity = input.agent.identity;
  let effectiveModel = input.model;
  let tokenizedPreview: string | undefined;

  if (input.requestedActionOverride) {
    decision = input.requestedActionOverride;
    policyRule = `pdp_policy_${input.requestedActionOverride}`;
    reason = `PDP evaluated enforcement policy action '${input.requestedActionOverride}' for ${input.agent.name}.`;
  } else if (injection.detected) {
    decision = 'block';
    policyRule = 'prompt_injection_guard';
    reason = `Prompt injection pattern (${injection.matchedPattern}) blocked at PDP boundary.`;
    matchedPlaybookId = 'pb_prompt_injection';
  } else if (
    input.tool === 'export_payroll' &&
    (classification.pii || classification.financial)
  ) {
    decision = 'block';
    policyRule = 'prevent_payroll_exfiltration';
    reason = 'Payroll PII/financial export to external model violates prevent_payroll_exfiltration.';
    matchedPlaybookId = 'pb_sensitive_exfiltration';
  } else if (classification.secrets) {
    decision = 'quarantine_agent';
    policyRule = 'compromised_credential_guard';
    reason = 'Raw credential or API secret detected; quarantining agent tool token.';
    matchedPlaybookId = 'pb_compromised_identity';
  } else if (input.agent.type === 'Shadow AI' && input.tool === 'url_fetch') {
    decision = 'escalate';
    policyRule = 'shadow_ai_egress_escalation';
    reason = 'Unapproved Shadow AI agent attempted outbound fetch; escalating incident.';
    matchedPlaybookId = 'pb_shadow_ai';
  } else if (classification.pii || classification.pci) {
    decision = 'redact';
    policyRule = 'redact_customer_pii';
    reason = 'PII/PCI fields tokenized before forwarding to upstream provider.';
    tokenizedPreview = tokenizeSensitiveContent(input.promptText ?? '');
  } else if (input.agent.riskScore >= 85 && !input.mfaVerified) {
    decision = 'step_up_authenticate';
    policyRule = 'high_risk_step_up_mfa';
    reason = 'High-risk agent action requires MFA / WebAuthn step-up verification.';
  } else if (input.tool === 'write_records' || input.tool === 'delete_records') {
    decision = 'approve';
    policyRule = 'human_approval_write_gate';
    reason = 'Mutating tool call paused pending explicit human owner approval.';
  } else if (input.agent.permissions.some((p) => p.includes('*')) && input.model === 'gpt-4.1') {
    decision = 'downgrade';
    policyRule = 'least_privilege_identity_downgrade';
    effectiveIdentity = `${input.agent.identity}-readonly`;
    effectiveModel = 'azure-openai-restricted';
    reason = 'Over-privileged identity downgraded to scoped read-only identity and restricted model.';
    matchedPlaybookId = 'pb_overprivileged_agent';
  }

  if (decision === 'redact' && !tokenizedPreview) {
    tokenizedPreview = tokenizeSensitiveContent(input.promptText ?? '[no prompt payload]');
  }
  if (decision === 'downgrade' && effectiveIdentity === input.agent.identity) {
    effectiveIdentity = `${input.agent.identity}-readonly`;
    effectiveModel = 'azure-openai-restricted';
  }

  return {
    decision,
    reason,
    policyRule,
    classification,
    promptInjectionDetected: injection.detected,
    promptInjectionSignal: injection.matchedPattern,
    tokenizedPreview,
    effectiveIdentity,
    effectiveModel,
    matchedPlaybookId,
    requiresApproval: decision === 'approve' || decision === 'step_up_authenticate',
  };
}

export function isDecisionEnforcedAtStage(
  stage: RolloutStage,
  decision: EnforcementAction
): boolean {
  if (stage === 'observe' || stage === 'advisory') return false;
  if (stage === 'selective_enforcement') {
    return decision === 'redact' || decision === 'block' || decision === 'downgrade';
  }
  // approval_gated_response & full_enforcement enforce all decisions
  return true;
}

export function buildCanonicalAuditPayload(ev: {
  id: string;
  tenantId: string;
  actorId: string;
  action: string;
  resourceType: string;
  resourceId: string;
  outcome: string;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
  occurredAt: string;
}): Record<string, unknown> {
  return {
    id: ev.id,
    tenantId: ev.tenantId,
    actorId: ev.actorId,
    action: ev.action,
    resourceType: ev.resourceType,
    resourceId: ev.resourceId,
    outcome: ev.outcome,
    before: ev.before,
    after: ev.after,
    occurredAt: ev.occurredAt,
  };
}

export function computeAuditEventHash(
  payload: Record<string, unknown>,
  prevHash: string
): string {
  const canonical = JSON.stringify({ prevHash, payload });
  return `sha256:${crypto.createHash('sha256').update(canonical).digest('hex')}`;
}

export function verifyAuditHashChain(
  events: AuditEvent[],
  retentionDays: number
): AuditChainIntegrity {
  if (events.length === 0) {
    return {
      valid: true,
      verifiedCount: 0,
      headHash: 'sha256:audit_genesis',
      tamperAlerts: [],
      retentionDays,
    };
  }
  // Events are stored newest-first; sort chronologically (and preserve insertion order for equal ms)
  const chronological = [...events].reverse();
  const tamperAlerts: string[] = [];
  for (let i = 0; i < chronological.length; i++) {
    const ev = chronological[i];
    if (!ev.event_hash || !ev.event_hash.startsWith('sha256:')) {
      tamperAlerts.push(`Event ${ev.id} missing SHA-256 event_hash`);
      continue;
    }
    const expectedPrev =
      i === 0 ? 'sha256:audit_genesis' : (chronological[i - 1].event_hash ?? 'sha256:audit_genesis');
    if (ev.prev_hash !== expectedPrev) {
      tamperAlerts.push(`Hash chain break detected at ${ev.id} (${ev.action})`);
    }
    const expectedDigest = computeAuditEventHash(
      buildCanonicalAuditPayload(ev),
      ev.prev_hash ?? expectedPrev
    );
    if (ev.event_hash !== expectedDigest) {
      tamperAlerts.push(`Payload tamper detected at ${ev.id} (${ev.action})`);
    }
  }
  return {
    valid: tamperAlerts.length === 0,
    verifiedCount: chronological.length,
    headHash: chronological[chronological.length - 1].event_hash ?? 'sha256:audit_genesis',
    tamperAlerts,
    retentionDays,
  };
}
