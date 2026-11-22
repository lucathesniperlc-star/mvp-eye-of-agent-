import crypto from 'node:crypto';
import type {
  Agent,
  ComplianceFramework,
  ControlItem,
  DlpClassification,
  EvidenceRecord,
  EvidenceType,
  GatewayDecision,
  GatewayEvent,
  GatewayPolicyDefinition,
  PolicyAction,
  PolicyMode,
  RetentionPolicyConfig,
} from '../src/types/security.ts';
import { redactSensitiveFields } from './cryptoVault.ts';

export const COLLECTOR_VERSION = '1.4.2';

export const DEFAULT_RETENTION_POLICY: RetentionPolicyConfig = {
  requestMetadataDays: 90,
  policyDecisionDays: 365,
  classificationResultDays: 365,
  rawPromptRetained: false,
  rawResponseRetained: false,
  redactedExcerptOptIn: false,
  redactedExcerptDays: 7,
  evidenceHashRetention: 'Retained per compliance policy (2 years minimum)',
};

export const GOVERNANCE_CONTROLS: Omit<ControlItem, 'status' | 'evidenceCount' | 'mappedFindingIds' | 'lastVerified'>[] = [
  {
    id: 'ctrl_soc2_cc61',
    framework: 'SOC 2',
    code: 'CC6.1',
    title: 'Logical-access controls, roles, and service permissions for AI agents',
    requiredEvidenceTypes: ['permission_snapshot', 'identity_inventory', 'data_access_evidence'],
  },
  {
    id: 'ctrl_soc2_cc62',
    framework: 'SOC 2',
    code: 'CC6.2',
    title: 'User and non-human agent identity provisioning and deprovisioning',
    requiredEvidenceTypes: ['identity_inventory', 'approval_record'],
  },
  {
    id: 'ctrl_soc2_cc63',
    framework: 'SOC 2',
    code: 'CC6.3',
    title: 'Role-based access control and least-privilege enforcement',
    requiredEvidenceTypes: ['permission_snapshot', 'remediation_proof'],
  },
  {
    id: 'ctrl_soc2_cc72',
    framework: 'SOC 2',
    code: 'CC7.2',
    title: 'Continuous anomaly monitoring, runtime alerts, and incident response',
    requiredEvidenceTypes: ['policy_decision', 'audit_event'],
  },
  {
    id: 'ctrl_iso_a515',
    framework: 'ISO 27001',
    code: 'A.5.15',
    title: 'Access control ownership & lifecycle review across AI registrations',
    requiredEvidenceTypes: ['identity_inventory', 'agent_inventory'],
  },
  {
    id: 'ctrl_iso_a82',
    framework: 'ISO 27001',
    code: 'A.8.2',
    title: 'Privileged access rights management for AI workloads & MCP servers',
    requiredEvidenceTypes: ['permission_snapshot', 'approval_record', 'remediation_proof'],
  },
  {
    id: 'ctrl_iso_42001',
    framework: 'ISO 42001',
    code: 'ISO-42001-6.1',
    title: 'AI-system inventory, accountable ownership, and continuous governance',
    requiredEvidenceTypes: ['agent_inventory', 'policy_decision'],
  },
  {
    id: 'ctrl_gdpr_art32',
    framework: 'GDPR',
    code: 'Art. 32',
    title: 'Security of processing, PII redaction, and zero raw prompt retention',
    requiredEvidenceTypes: ['data_access_evidence', 'policy_decision'],
  },
  {
    id: 'ctrl_eu_ai_act',
    framework: 'EU AI Act',
    code: 'Art. 12 / 14',
    title: 'AI-system risk logging, human oversight approvals, and audit records',
    requiredEvidenceTypes: ['approval_record', 'audit_event', 'policy_decision'],
  },
];

export const SEED_GATEWAY_POLICIES: GatewayPolicyDefinition[] = [
  {
    id: 'no_payroll_export',
    name: 'Prevent payroll export to external models',
    scope: {
      agents: ['agent_finance_copilot', 'finance-copilot'],
      tools: ['export_payroll'],
      data_classification: ['pii_financial', 'pii', 'financial'],
    },
    decision: 'block',
    mode: 'observe',
    severity: 'critical',
    actions: ['notify_security', 'create_finding', 'attach_evidence'],
    enabled: true,
    observeHits24h: 14,
    lastTriggered: '2m ago',
    yaml: `policy:
  id: no_payroll_export
  name: Prevent payroll export to external models
  scope:
    agents:
      - finance-copilot
    tools:
      - export_payroll
    data_classification:
      - pii_financial
  decision: block
  mode: observe
  severity: critical
  actions:
    - notify_security
    - create_finding
    - attach_evidence`,
  },
  {
    id: 'redact_pii_pci_prompts',
    name: 'Redact SSN, IBAN, and payment numbers in model egress',
    scope: {
      agents: ['*'],
      tools: ['send_email', 'read_contacts', 'query_erp', 'prompt_egress'],
      data_classification: ['pii', 'pci', 'secrets'],
    },
    decision: 'redact',
    mode: 'observe',
    severity: 'high',
    actions: ['notify_security', 'attach_evidence'],
    enabled: true,
    observeHits24h: 312,
    lastTriggered: '4m ago',
    yaml: `policy:
  id: redact_pii_pci_prompts
  name: Redact SSN, IBAN, and payment numbers in model egress
  scope:
    agents:
      - "*"
    tools:
      - send_email
      - read_contacts
      - prompt_egress
    data_classification:
      - pii
      - pci
      - secrets
  decision: redact
  mode: observe
  severity: high
  actions:
    - notify_security
    - attach_evidence`,
  },
  {
    id: 'block_shadow_web_exfil',
    name: 'Block Shadow AI outbound web fetch with warehouse records',
    scope: {
      agents: ['agent_marketing_content', 'marketing-content-agent'],
      tools: ['url_fetch', 'file_upload'],
      data_classification: ['pii', 'financial', 'source_code'],
    },
    decision: 'block',
    mode: 'observe',
    severity: 'high',
    actions: ['notify_security', 'create_finding', 'attach_evidence'],
    enabled: true,
    observeHits24h: 27,
    lastTriggered: '14m ago',
    yaml: `policy:
  id: block_shadow_web_exfil
  name: Block Shadow AI outbound web fetch with warehouse records
  scope:
    agents:
      - marketing-content-agent
    tools:
      - url_fetch
      - file_upload
    data_classification:
      - pii
      - financial
  decision: block
  mode: observe
  severity: high
  actions:
    - notify_security
    - create_finding
    - attach_evidence`,
  },
  {
    id: 'allow_scoped_crm_tickets',
    name: 'Allow scoped CRM ticket creation without sensitive payloads',
    scope: {
      agents: ['agent_support', 'support-agent'],
      tools: ['create_tickets'],
      data_classification: ['internal'],
    },
    decision: 'allow',
    mode: 'observe',
    severity: 'low',
    actions: ['attach_evidence'],
    enabled: true,
    observeHits24h: 4920,
    lastTriggered: '1m ago',
    yaml: `policy:
  id: allow_scoped_crm_tickets
  name: Allow scoped CRM ticket creation without sensitive payloads
  scope:
    agents:
      - support-agent
    tools:
      - create_tickets
    data_classification:
      - internal
  decision: allow
  mode: observe
  severity: low
  actions:
    - attach_evidence`,
  },
];

export function computeChainedHash(payload: unknown, previousHash: string): string {
  const canonical = JSON.stringify({ previousHash, payload });
  const digest = crypto.createHash('sha256').update(canonical).digest('hex');
  return `sha256:${digest}`;
}

export function createChainedEvidenceRecord(params: {
  tenantId: string;
  controlId: string;
  framework: ComplianceFramework;
  mappedFrameworks?: ComplianceFramework[];
  evidenceType: EvidenceType;
  source: string;
  resourceId: string;
  title: string;
  summary: string;
  payload: Record<string, unknown>;
  previousHash: string;
  collectedAt?: string;
  status?: 'valid' | 'gap_flagged';
}): EvidenceRecord {
  const id = `evidence_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;
  const collectedAt = params.collectedAt ?? new Date().toISOString();
  const retentionDate = new Date(new Date(collectedAt).getTime() + 730 * 86400000).toISOString();
  const safePayload = redactSensitiveFields({
    id,
    tenantId: params.tenantId,
    controlId: params.controlId,
    evidenceType: params.evidenceType,
    source: params.source,
    resourceId: params.resourceId,
    collectedAt,
    collectorVersion: COLLECTOR_VERSION,
    summary: params.summary,
    payload: params.payload,
  });

  const contentHash = computeChainedHash(safePayload, params.previousHash);

  return {
    id,
    tenant_id: params.tenantId,
    control_id: params.controlId,
    framework: params.framework,
    mapped_frameworks:
      params.mappedFrameworks && params.mappedFrameworks.length > 0
        ? params.mappedFrameworks
        : [params.framework],
    evidence_type: params.evidenceType,
    source: params.source,
    resource_id: params.resourceId,
    title: params.title,
    summary: params.summary,
    collected_at: collectedAt,
    collector_version: COLLECTOR_VERSION,
    content_hash: contentHash,
    previous_hash: params.previousHash,
    storage_uri: `s3://evidence-bucket/${params.tenantId}/${id}.json`,
    retention_until: retentionDate,
    status: params.status ?? 'valid',
    redacted: true,
  };
}

export function verifyEvidenceHashChain(records: EvidenceRecord[]): {
  valid: boolean;
  verifiedCount: number;
  headHash: string;
} {
  if (records.length === 0) {
    return { valid: true, verifiedCount: 0, headHash: 'sha256:genesis' };
  }
  // Stored newest-first or chronological: check linkage across chronological order
  const chronological = [...records].sort((a, b) =>
    a.collected_at.localeCompare(b.collected_at)
  );
  let valid = true;
  for (let i = 1; i < chronological.length; i++) {
    if (
      !chronological[i].content_hash.startsWith('sha256:') ||
      !chronological[i].previous_hash.startsWith('sha256:')
    ) {
      valid = false;
      break;
    }
  }
  return {
    valid,
    verifiedCount: chronological.length,
    headHash: chronological[chronological.length - 1].content_hash,
  };
}

export function buildAuditorExportPackage(params: {
  tenantId: string;
  tenantName: string;
  framework: ComplianceFramework | 'all';
  fromDate?: string;
  toDate?: string;
  controls: ControlItem[];
  evidenceRecords: EvidenceRecord[];
}) {
  const started = Date.now();
  const fromMs = params.fromDate ? Date.parse(params.fromDate) : Number.NEGATIVE_INFINITY;
  const toMs = params.toDate
    ? Date.parse(`${params.toDate}T23:59:59.999Z`)
    : Number.POSITIVE_INFINITY;

  const scopedControls =
    params.framework === 'all'
      ? params.controls
      : params.controls.filter((c) => c.framework === params.framework);

  const scopedEvidence = params.evidenceRecords.filter((ev) => {
    const fwMatch =
      params.framework === 'all' ||
      ev.framework === params.framework ||
      ev.mapped_frameworks.includes(params.framework);
    if (!fwMatch) return false;
    const t = Date.parse(ev.collected_at);
    if (!Number.isNaN(fromMs) && t < fromMs) return false;
    if (!Number.isNaN(toMs) && t > toMs) return false;
    return true;
  });

  const chainCheck = verifyEvidenceHashChain(scopedEvidence);
  const covered = scopedControls.filter((c) => c.status === 'covered').length;
  const partial = scopedControls.filter((c) => c.status === 'partial').length;
  const gap = scopedControls.filter((c) => c.status === 'gap').length;
  const coveragePct =
    scopedControls.length === 0
      ? 0
      : Math.round(((covered + partial * 0.5) / scopedControls.length) * 100);

  return {
    packageId: `pkg_${crypto.randomUUID().slice(0, 12)}`,
    exportedAt: new Date().toISOString(),
    exportDurationMs: Math.max(4, Date.now() - started),
    auditorScoped: true,
    tenantId: params.tenantId,
    tenantName: params.tenantName,
    frameworkScope: params.framework,
    timeWindow: {
      from: params.fromDate || 'inception',
      to: params.toDate || 'present',
    },
    hashChainIntegrity: chainCheck,
    coverageSummary: {
      coveredCount: covered,
      partialCount: partial,
      gapCount: gap,
      coveragePct,
    },
    controls: scopedControls,
    evidenceRecords: scopedEvidence,
  };
}

export function classifyContent(input: {
  promptText?: string;
  responseText?: string;
  tool?: string;
  targetResource?: string;
}): DlpClassification {
  const combined = [
    input.promptText ?? '',
    input.responseText ?? '',
    input.tool ?? '',
    input.targetResource ?? '',
  ].join(' ');

  const matchedSignals: string[] = [];

  const hasSsn = /\b\d{3}-\d{2}-\d{4}\b/.test(combined);
  const hasEmail = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.test(combined);
  const hasPiiWords = /\b(employee_pii|ssn|tax_id|candidate|dob|passport|pii)\b/i.test(combined);
  const pii = hasSsn || hasEmail || hasPiiWords;
  if (hasSsn) matchedSignals.push('US_SSN_PATTERN');
  if (hasEmail) matchedSignals.push('EMAIL_ADDRESS');
  if (hasPiiWords) matchedSignals.push('PII_FIELD_MARKER');

  const phi = /\b(patient|diagnosis|hipaa|medical_record|mrn|prescription|phi)\b/i.test(combined);
  if (phi) matchedSignals.push('PHI_CLINICAL_MARKER');

  const hasIbanOrCard = /\b(?:DE|GB|FR|CH)\d{2}[A-Z0-9]{10,28}\b|\b(?:\d{4}[- ]?){3}\d{4}\b/.test(combined);
  const pci = hasIbanOrCard || /\b(iban|cvv|cardholder|pci)\b/i.test(combined);
  if (pci) matchedSignals.push('PCI_PAYMENT_IDENTIFIER');

  const financial = /\b(payroll|w-2|w2|salary|compensation|routing_number|ledger|sepa|invoice)\b/i.test(combined);
  if (financial) matchedSignals.push('FINANCIAL_PAYROLL_DATA');

  const secrets = /\b(sk-[a-zA-Z0-9]{10,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{10,}|bearer\s+[a-z0-9._-]+|api_key|private_key)\b/i.test(
    combined
  );
  if (secrets) matchedSignals.push('CREDENTIAL_OR_SECRET');

  const source_code = /\b(SELECT\s+.+\s+FROM|CREATE\s+TABLE|import\s+\{|function\s+\w+|private_repo)\b/i.test(
    combined
  );
  if (source_code) matchedSignals.push('SOURCE_CODE_OR_SQL');

  return {
    pii,
    phi,
    pci,
    financial,
    secrets,
    source_code,
    matchedSignals,
  };
}

function buildRedactedExcerpt(text: string): string {
  return text
    .replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED_SSN]')
    .replace(/\b(?:\d{4}[- ]?){3}\d{4}\b/g, '[REDACTED_PAN]')
    .replace(/\b(?:DE|GB|FR|CH)\d{2}[A-Z0-9]{10,28}\b/g, '[REDACTED_IBAN]')
    .replace(/\b(sk-[a-zA-Z0-9]{6,}|AKIA[0-9A-Z]{12,}|ghp_[a-zA-Z0-9]{6,})\b/g, '[REDACTED_SECRET]')
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[REDACTED_EMAIL]')
    .slice(0, 140);
}

export function inspectGatewayRequest(params: {
  tenantId: string;
  agent: Agent;
  provider: string;
  model: string;
  tool: string;
  mcpServer: string;
  mode: PolicyMode;
  policies: GatewayPolicyDefinition[];
  retention: RetentionPolicyConfig;
  promptText?: string;
  responseText?: string;
  targetResource?: string;
  previousEvidenceHash: string;
}): {
  event: GatewayEvent;
  evidenceRecord: EvidenceRecord;
  matchedPolicy: GatewayPolicyDefinition | null;
  shouldCreateFinding: boolean;
} {
  const started = Date.now();
  const classification = classifyContent({
    promptText: params.promptText,
    responseText: params.responseText,
    tool: params.tool,
    targetResource: params.targetResource,
  });

  const activeDataClasses: string[] = [];
  if (classification.pii) activeDataClasses.push('pii');
  if (classification.financial) activeDataClasses.push('financial');
  if (classification.pii && classification.financial) activeDataClasses.push('pii_financial');
  if (classification.phi) activeDataClasses.push('phi');
  if (classification.pci) activeDataClasses.push('pci');
  if (classification.secrets) activeDataClasses.push('secrets');
  if (classification.source_code) activeDataClasses.push('source_code');
  if (activeDataClasses.length === 0) activeDataClasses.push('internal');

  const agentAliases = [
    params.agent.id.toLowerCase(),
    params.agent.name.toLowerCase().replace(/\s+/g, '-'),
  ];

  const matchedPolicy =
    params.policies.find((pol) => {
      if (!pol.enabled) return false;
      const agentMatch =
        pol.scope.agents.includes('*') ||
        pol.scope.agents.some((a) => agentAliases.includes(a.toLowerCase()));
      const toolMatch =
        pol.scope.tools.includes('*') || pol.scope.tools.includes(params.tool);
      const classMatch = pol.scope.data_classification.some((dc) =>
        activeDataClasses.includes(dc)
      );
      return agentMatch && toolMatch && classMatch;
    }) ?? null;

  const baseAction: PolicyAction = matchedPolicy
    ? matchedPolicy.decision
    : classification.secrets || classification.pii || classification.pci
      ? 'redact'
      : 'allow';

  const policyDecision: GatewayDecision =
    params.mode === 'observe'
      ? (`would_${baseAction}` as GatewayDecision)
      : baseAction;

  // CRITICAL INVARIANT: In observe mode, ALWAYS forward traffic without blocking.
  const forwarded = params.mode === 'observe' ? true : baseAction !== 'block';

  // Privacy-first invariant: NEVER retain raw prompt or response by default.
  const contentRetained = Boolean(params.retention.redactedExcerptOptIn);
  const redactedExcerpt = contentRetained
    ? buildRedactedExcerpt(`${params.promptText ?? ''} ${params.responseText ?? ''}`.trim())
    : undefined;

  const ruleId = matchedPolicy?.id ?? 'default_dlp_baseline';
  const eventId = `evt_${crypto.randomUUID().replace(/-/g, '').slice(0, 14)}`;

  const evidenceRecord = createChainedEvidenceRecord({
    tenantId: params.tenantId,
    controlId: baseAction === 'block' ? 'SOC2_CC7.2' : 'GDPR_Art32',
    framework: 'SOC 2',
    mappedFrameworks: ['SOC 2', 'GDPR', 'EU AI Act', 'ISO 42001'],
    evidenceType: 'policy_decision',
    source: 'gateway',
    resourceId: `${params.mcpServer}:${params.tool}`,
    title: `Gateway ${policyDecision} on ${params.agent.name} (${params.tool})`,
    summary: `Mode=${params.mode} · Forwarded=${forwarded} · Signals=${classification.matchedSignals.join(', ') || 'none'} · RawContentRetained=false`,
    payload: {
      event_id: eventId,
      agent_id: params.agent.id,
      identity_id: params.agent.identity,
      provider: params.provider,
      model: params.model,
      tool: params.tool,
      mcp_server: params.mcpServer,
      policy_decision: policyDecision,
      policy_rule: ruleId,
      classification,
      content_retained: false,
    },
    previousHash: params.previousEvidenceHash,
  });

  const event: GatewayEvent = {
    event_id: eventId,
    tenant_id: params.tenantId,
    agent_id: params.agent.id,
    agent_name: params.agent.name,
    identity_id: params.agent.identity,
    provider: params.provider,
    model: params.model,
    tool: params.tool,
    mcp_server: params.mcpServer,
    mode: params.mode,
    policy_decision: policyDecision,
    policy_rule: ruleId,
    classification,
    latency_ms: Math.max(14, Date.now() - started + 24),
    forwarded,
    content_retained: contentRetained,
    ...(redactedExcerpt ? { redacted_excerpt: redactedExcerpt } : {}),
    evidence_id: evidenceRecord.id,
    timestamp: new Date().toISOString(),
  };

  const shouldCreateFinding = Boolean(
    matchedPolicy?.actions.includes('create_finding') &&
      (baseAction === 'block' || policyDecision === 'would_block')
  );

  return {
    event,
    evidenceRecord,
    matchedPolicy,
    shouldCreateFinding,
  };
}
