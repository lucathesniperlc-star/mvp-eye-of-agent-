import crypto from 'node:crypto';
import type {
  Agent,
  AgentFramework,
  AiProviderAdapterMeta,
  AuditChainIntegrity,
  ContainmentActionCatalogItem,
  DlpClassification,
  EnforcementAction,
  GatewayPolicyDefinition,
  McpApprovalStatus,
  ModelApprovalStatus,
  PlatformHardeningItem,
  PlaybookDefinition,
  PlaybookId,
  PolicyException,
  RolloutStage,
  VerticalPolicyPack,
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

export const VERTICAL_POLICY_PACKS: VerticalPolicyPack[] = [
  {
    id: 'fintech',
    name: 'Financial Services & Fintech Pack',
    priority: 'P0',
    frameworks: ['SOC 2', 'PCI-DSS', 'SOX', 'FFIEC'],
    summary: 'Prevents payroll, IBAN/PAN, and ledger exfiltration across treasury copilots and external LLMs.',
    keyRisks: ['Sensitive financial data exposure', 'Autonomous transaction tool calls', 'Fraud & auditability'],
    defaultRules: [
      { name: 'Block unredacted IBAN & SWIFT routing egress', scope: 'Treasury & Finance Copilots', condition: 'data_class in [iban, pci] && destination == external', action: 'block' },
      { name: 'Require dual approval on payment or ledger write tools', scope: 'ERP & Core Banking MCP', condition: 'tool in [export_payroll, execute_wire]', action: 'block' },
    ],
    gatewayYamlTemplate: `policy:\n  id: fintech_pack_guard\n  name: Fintech IBAN/PAN & Payroll Guard\n  scope:\n    agents: ['*']\n    tools: [export_payroll, execute_wire]\n    data_classification: [pci, pii_financial]\n  decision: block\n  actions: [create_critical_finding, notify_security, preserve_evidence]`,
  },
  {
    id: 'saas_tech',
    name: 'SaaS & Technology Pack',
    priority: 'P0',
    frameworks: ['SOC 2', 'ISO 27001', 'ISO 42001'],
    summary: 'Protects proprietary source code, CI/CD credentials, and unapproved MCP servers in engineering workflows.',
    keyRisks: ['Source code & secret leakage', 'Shadow coding assistants', 'Over-privileged GitHub bots'],
    defaultRules: [
      { name: 'Tokenize API keys & secrets before LLM inference', scope: 'Engineering & Code Agents', condition: 'classification.secrets == true', action: 'redact' },
      { name: 'Block unapproved OSS MCP web-fetch egress', scope: 'Shadow AI & Dev Agents', condition: 'mcp_approval == unapproved', action: 'block' },
    ],
    gatewayYamlTemplate: `policy:\n  id: saas_source_secret_guard\n  name: SaaS Source Code & Secret Guard\n  scope:\n    agents: ['*']\n    tools: [read_repos, url_fetch]\n    data_classification: [secrets, source_code]\n  decision: redact\n  actions: [log_decision, attach_evidence]`,
  },
  {
    id: 'healthcare',
    name: 'Healthcare & Life Sciences Pack',
    priority: 'P0',
    frameworks: ['HIPAA', 'HITECH', 'GDPR'],
    summary: 'Enforces PHI tokenization, EHR least-privilege access, and BAA-verified model routing.',
    keyRisks: ['PHI leakage to non-BAA models', 'Clinical copilot over-permissioning'],
    defaultRules: [
      { name: 'Redact patient MRN and clinical PHI fields', scope: 'Clinical & Triage Agents', condition: 'classification.phi == true', action: 'redact' },
    ],
    gatewayYamlTemplate: `policy:\n  id: healthcare_phi_guard\n  name: Healthcare HIPAA PHI Guard\n  scope:\n    agents: ['*']\n    tools: ['*']\n    data_classification: [phi, pii]\n  decision: redact\n  actions: [log_decision, attach_evidence]`,
  },
  {
    id: 'insurance',
    name: 'Insurance Underwriting & Claims Pack',
    priority: 'P1',
    frameworks: ['SOC 2', 'NAIC AI', 'EU AI Act'],
    summary: 'Enforces EU AI Act high-risk underwriting explainability and claims PII protection.',
    keyRisks: ['Claims fraud & PII leak', 'Opaque underwriting decisions'],
    defaultRules: [
      { name: 'Capture decision trace for high-risk claims scoring', scope: 'Claims & Underwriting Agents', condition: 'risk_level in [critical, high]', action: 'redact' },
    ],
    gatewayYamlTemplate: `policy:\n  id: insurance_eu_ai_act_pack\n  name: Insurance Claims Explainability & PII Guard\n  scope:\n    agents: ['*']\n    tools: [write_records]\n    data_classification: [pii, financial]\n  decision: redact\n  actions: [log_decision, attach_evidence]`,
  },
  {
    id: 'legal',
    name: 'Legal & Professional Services Pack',
    priority: 'P1',
    frameworks: ['ISO 27001', 'GDPR', 'SOC 2'],
    summary: 'Prevents cross-matter client confidentiality leaks and enforces zero-retention model endpoints.',
    keyRisks: ['Client matter bleed', 'Privileged contract upload to non-DPA models'],
    defaultRules: [
      { name: 'Block client M&A contracts on unverified models', scope: 'Procurement & Legal Agents', condition: 'model_retention == Unverified local', action: 'block' },
    ],
    gatewayYamlTemplate: `policy:\n  id: legal_privilege_guard\n  name: Legal Privilege & Zero-Retention Guard\n  scope:\n    agents: ['*']\n    tools: [extract_contracts]\n    data_classification: [restricted, pii]\n  decision: block\n  actions: [log_decision, preserve_evidence]`,
  },
  {
    id: 'manufacturing',
    name: 'Manufacturing & Supply Chain Pack',
    priority: 'P1',
    frameworks: ['ISO 27001', 'IEC 62443'],
    summary: 'Protects CAD/IP trade secrets and isolates OT/ERP agent service accounts.',
    keyRisks: ['Trade secret IP exfiltration', 'Supplier portal prompt injection'],
    defaultRules: [
      { name: 'Block external webhook transfer of BOM/IP files', scope: 'Supply Chain Agents', condition: 'tool == file_upload', action: 'block' },
    ],
    gatewayYamlTemplate: `policy:\n  id: manufacturing_ip_guard\n  name: Manufacturing IP & OT Isolation\n  scope:\n    agents: ['*']\n    tools: [file_upload]\n    data_classification: [restricted]\n  decision: block\n  actions: [log_decision]`,
  },
  {
    id: 'energy',
    name: 'Energy & Critical Utilities Pack',
    priority: 'P2',
    frameworks: ['NERC CIP', 'NIS2', 'ISO 27001'],
    summary: 'Enforces fail-closed policy enforcement on grid telemetry and operator assistants.',
    keyRisks: ['Telemetry manipulation', 'Unapproved external tool chaining'],
    defaultRules: [
      { name: 'Fail-closed on SCADA / grid telemetry agent calls', scope: 'Grid Operations Copilots', condition: 'environment == production', action: 'block' },
    ],
    gatewayYamlTemplate: `policy:\n  id: energy_nis2_guard\n  name: Energy NERC CIP Fail-Closed Guard\n  scope:\n    agents: ['*']\n    tools: [write_records]\n    data_classification: [restricted]\n  decision: block\n  actions: [notify_security]`,
  },
  {
    id: 'government',
    name: 'Public Sector & Government Pack',
    priority: 'P2',
    frameworks: ['FedRAMP', 'NIST AI RMF', 'EO 14110'],
    summary: 'Restricts model routing to FedRAMP/sovereign regions and preserves 365+ day forensic evidence.',
    keyRisks: ['Cross-border model egress', 'Unattributed autonomous actions'],
    defaultRules: [
      { name: 'Enforce sovereign cloud model routing only', scope: 'Citizen & Agency Agents', condition: 'model_region not in sovereign', action: 'block' },
    ],
    gatewayYamlTemplate: `policy:\n  id: gov_fedramp_sovereign\n  name: Public Sector Sovereign Routing\n  scope:\n    agents: ['*']\n    tools: ['*']\n    data_classification: [pii, restricted]\n  decision: block\n  actions: [preserve_evidence]`,
  },
  {
    id: 'retail',
    name: 'Retail & E-Commerce Pack',
    priority: 'P2',
    frameworks: ['PCI-DSS', 'GDPR', 'CCPA'],
    summary: 'Protects shopper payment PANs and customer support bots from indirect prompt injection.',
    keyRisks: ['Customer PAN leakage', 'Support bot refund manipulation'],
    defaultRules: [
      { name: 'Tokenize shopper email & cardholder data', scope: 'Customer Support Agents', condition: 'classification.pci == true || classification.pii == true', action: 'redact' },
    ],
    gatewayYamlTemplate: `policy:\n  id: retail_pci_guard\n  name: Retail PCI & Prompt Injection Guard\n  scope:\n    agents: ['*']\n    tools: [send_email]\n    data_classification: [pci, pii]\n  decision: redact\n  actions: [log_decision]`,
  },
  {
    id: 'education',
    name: 'Higher Education & Research Pack',
    priority: 'P2',
    frameworks: ['FERPA', 'GDPR', 'ISO 27001'],
    summary: 'Safeguards student records and research grants across campus copilots and local lab models.',
    keyRisks: ['Student FERPA exposure', 'Unverified local Ollama deployments'],
    defaultRules: [
      { name: 'Flag unverified local research models handling FERPA PII', scope: 'Research & Advising Bots', condition: 'model_approval == unapproved', action: 'redact' },
    ],
    gatewayYamlTemplate: `policy:\n  id: edu_ferpa_guard\n  name: Education FERPA & Lab Model Guard\n  scope:\n    agents: ['*']\n    tools: ['*']\n    data_classification: [pii]\n  decision: redact\n  actions: [log_decision]`,
  },
];

export const AI_PROVIDER_ADAPTERS: AiProviderAdapterMeta[] = [
  { id: 'openai', name: 'OpenAI', priority: 'P0', integrationCapabilities: 'Gateway inspection, token/model metadata, usage & retention policy', protocol: 'REST / SSE' },
  { id: 'anthropic', name: 'Anthropic', priority: 'P0', integrationCapabilities: 'Gateway inspection, enterprise DPA verification, safety & usage metadata', protocol: 'REST / SSE' },
  { id: 'azure-openai', name: 'Azure OpenAI', priority: 'P0', integrationCapabilities: 'Tenant deployment inventory, Entra managed identity permissions, logs', protocol: 'Managed Identity' },
  { id: 'vertex-gemini', name: 'Google Vertex AI', priority: 'P0', integrationCapabilities: 'Model endpoints, IAM service accounts, prompt/response metadata logging', protocol: 'Cloud IAM / API' },
  { id: 'aws-bedrock', name: 'AWS Bedrock', priority: 'P0', integrationCapabilities: 'Model access permissions, IAM role bindings, CloudWatch invocation logs', protocol: 'Cloud IAM / API' },
  { id: 'huggingface', name: 'Hugging Face', priority: 'P1', integrationCapabilities: 'Hosted inference endpoints, workspace token inventory, model provenance', protocol: 'REST / SSE' },
  { id: 'cohere', name: 'Cohere', priority: 'P1', integrationCapabilities: 'Enterprise embed/chat gateway interception & zero-retention checks', protocol: 'REST / SSE' },
  { id: 'mistral', name: 'Mistral', priority: 'P1', integrationCapabilities: 'EU-sovereign API routing, policy inspection & key telemetry', protocol: 'OpenAI-Compatible' },
  { id: 'meta-llama', name: 'Meta Llama', priority: 'P1', integrationCapabilities: 'Self-hosted & cloud MaaS endpoint discovery and guardrail wrapping', protocol: 'OpenAI-Compatible' },
  { id: 'local-models', name: 'Local Models (Ollama / LM Studio / vLLM)', priority: 'P1', integrationCapabilities: 'Shadow local endpoint detection, model inventory & egress tagging', protocol: 'Local Socket / HTTP' },
  { id: 'custom-models', name: 'Custom Models', priority: 'P2', integrationCapabilities: 'Generic OpenAI-compatible HTTP proxy & custom JSON-schema telemetry', protocol: 'OpenAI-Compatible' },
];

export const AGENT_FRAMEWORKS: AgentFramework[] = [
  'LangChain',
  'LangGraph',
  'CrewAI',
  'AutoGen',
  'Copilot Studio',
  'MCP',
  'OpenAI Assistants',
  'Custom',
];

export const CONTAINMENT_ACTION_CATALOG: ContainmentActionCatalogItem[] = [
  { id: 'revoke_oauth_grant', label: 'Revoke OAuth Grant', targetType: 'identity', requiresApproval: true, reversible: true, description: 'Revokes delegated OAuth2 permission grants on the agent enterprise app.' },
  { id: 'disable_api_key', label: 'Disable API Key', targetType: 'credential', requiresApproval: true, reversible: true, description: 'Disables compromised or unapproved provider API keys bound to the agent.' },
  { id: 'rotate_client_secret', label: 'Rotate Client Secret', targetType: 'credential', requiresApproval: true, reversible: true, description: 'Rotates Entra/AWS static client secrets and invalidates old tokens.' },
  { id: 'remove_privileged_group', label: 'Remove from Privileged Group', targetType: 'identity', requiresApproval: true, reversible: true, description: 'Strips wildcard admin or privileged directory group memberships.' },
  { id: 'remove_unapproved_model', label: 'Remove Access to Unapproved Model', targetType: 'model', requiresApproval: false, reversible: true, description: 'Detaches shadow or unapproved LLM endpoints from agent runtime routing.' },
  { id: 'disable_unapproved_mcp', label: 'Disable Unapproved MCP Server', targetType: 'mcp', requiresApproval: false, reversible: true, description: 'Disables unmanaged MCP server bridge at the gateway enforcement layer.' },
  { id: 'restrict_data_access', label: 'Restrict Data-Source Access', targetType: 'data', requiresApproval: true, reversible: true, description: 'Removes sensitive restricted datastore bindings and scopes agent to read-only.' },
  { id: 'quarantine_agent', label: 'Quarantine Agent', targetType: 'agent', requiresApproval: true, reversible: true, description: 'Places agent into full quarantine, blocking all runtime tool invocations.' },
];

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
  modelApprovalStatus?: ModelApprovalStatus;
  mcpApprovalStatus?: McpApprovalStatus;
  activeException?: PolicyException;
  pdpUnavailable?: boolean;
  failoverMode?: 'fail_open' | 'fail_closed';
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

  if (input.pdpUnavailable) {
    const mode = input.failoverMode ?? 'fail_closed';
    const failDecision: EnforcementAction = mode === 'fail_closed' ? 'block' : 'allow';
    return {
      decision: failDecision,
      reason: `PDP engine unreachable — gateway executed configured ${mode} failover (${failDecision}).`,
      policyRule: 'gateway_failover_mode',
      classification,
      promptInjectionDetected: injection.detected,
      promptInjectionSignal: injection.matchedPattern,
      effectiveIdentity: input.agent.identity,
      effectiveModel: input.model,
      requiresApproval: false,
    };
  }

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
  } else if (
    input.activeException &&
    input.activeException.status === 'active' &&
    Date.parse(input.activeException.expiresAt) > Date.now()
  ) {
    decision = 'allow';
    policyRule = 'approved_policy_exception';
    reason = `Time-bound exception ${input.activeException.id} (${input.activeException.justification}) permitted request until ${input.activeException.expiresAt.slice(0, 10)}.`;
  } else if (injection.detected) {
    decision = 'block';
    policyRule = 'prompt_injection_guard';
    reason = `Prompt injection pattern (${injection.matchedPattern}) blocked at PDP boundary.`;
    matchedPlaybookId = 'pb_prompt_injection';
  } else if (
    input.mcpApprovalStatus === 'disabled' ||
    input.mcpApprovalStatus === 'unapproved' ||
    input.modelApprovalStatus === 'unapproved'
  ) {
    decision = 'block';
    policyRule = 'approved_ai_registry_guard';
    reason = `Blocked invocation targeting unapproved/disabled model (${input.model}) or MCP server (${input.mcpApprovalStatus ?? 'unapproved'}).`;
    matchedPlaybookId = 'pb_shadow_ai';
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
