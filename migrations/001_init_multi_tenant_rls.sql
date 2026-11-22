-- Eyes of Agent: Multi-Tenant PostgreSQL Schema, RLS Policies & Recursive Graph Traversal
-- Target: PostgreSQL 15+ (Shared database, row-level isolation via app.current_tenant_id)

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

-- Least-privileged runtime role (no SUPERUSER, no BYPASSRLS)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'eoa_app_runtime') THEN
    CREATE ROLE eoa_app_runtime NOLOGIN NOBYPASSRLS;
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS tenants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  slug text NOT NULL UNIQUE,
  plan text NOT NULL DEFAULT 'enterprise',
  status text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email citext NOT NULL UNIQUE,
  external_id text NOT NULL,
  idp text NOT NULL DEFAULT 'oidc',
  mfa_enabled boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tenant_memberships (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (
    role IN ('owner', 'admin', 'security_analyst', 'compliance_manager', 'agent_owner', 'auditor', 'service_account')
  ),
  status text NOT NULL DEFAULT 'active',
  PRIMARY KEY (tenant_id, user_id)
);

CREATE TABLE IF NOT EXISTS connectors (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  provider text NOT NULL,
  status text NOT NULL DEFAULT 'healthy',
  last_sync_at timestamptz,
  config jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  connector_id uuid NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
  ciphertext bytea NOT NULL,
  key_id text NOT NULL,
  expires_at timestamptz
);

CREATE TABLE IF NOT EXISTS agents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  external_key text NOT NULL,
  name text NOT NULL,
  owner_email text NOT NULL,
  agent_type text NOT NULL,
  status text NOT NULL DEFAULT 'active',
  risk_score integer NOT NULL DEFAULT 0,
  risk_level text NOT NULL DEFAULT 'medium',
  identity_name text NOT NULL,
  business_service text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, external_key)
);

CREATE TABLE IF NOT EXISTS graph_nodes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  node_type text NOT NULL,
  external_key text NOT NULL,
  label text NOT NULL,
  sensitivity text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  UNIQUE (tenant_id, external_key)
);

CREATE TABLE IF NOT EXISTS graph_edges (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  source_node_id uuid NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
  target_node_id uuid NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
  edge_type text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  UNIQUE (tenant_id, source_node_id, target_node_id, edge_type)
);

CREATE TABLE IF NOT EXISTS findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  agent_id uuid REFERENCES agents(id) ON DELETE SET NULL,
  title text NOT NULL,
  severity text NOT NULL,
  owner_team text NOT NULL,
  status text NOT NULL DEFAULT 'open',
  jira_ticket_key text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  actor_id uuid,
  action text NOT NULL,
  resource_type text NOT NULL,
  resource_id text NOT NULL,
  before jsonb,
  after jsonb,
  occurred_at timestamptz NOT NULL DEFAULT now()
);

-- Enable Row-Level Security on all tenant-scoped tables
ALTER TABLE tenant_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE connectors ENABLE ROW LEVEL SECURITY;
ALTER TABLE credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE graph_nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE graph_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_memberships ON tenant_memberships
  FOR ALL USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
CREATE POLICY tenant_isolation_connectors ON connectors
  FOR ALL USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
CREATE POLICY tenant_isolation_credentials ON credentials
  FOR ALL USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
CREATE POLICY tenant_isolation_agents ON agents
  FOR ALL USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
CREATE POLICY tenant_isolation_graph_nodes ON graph_nodes
  FOR ALL USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
CREATE POLICY tenant_isolation_graph_edges ON graph_edges
  FOR ALL USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
CREATE POLICY tenant_isolation_findings ON findings
  FOR ALL USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
CREATE POLICY tenant_isolation_audit_events ON audit_events
  FOR ALL USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- Example Recursive CTE: Agent-to-Sensitive-Data Exposure Path Traversal
-- Usage after: SET LOCAL app.current_tenant_id = '<tenant_uuid>';
-- WITH RECURSIVE exposure_walk AS (
--   SELECT n.id AS start_agent_id, n.id AS current_node_id,
--          ARRAY[n.id] AS node_path, ARRAY[]::text[] AS edge_path, 0 AS depth
--   FROM graph_nodes n
--   WHERE n.node_type = 'AI agent' AND n.tenant_id = current_setting('app.current_tenant_id')::uuid
--   UNION ALL
--   SELECT ew.start_agent_id, e.target_node_id,
--          ew.node_path || e.target_node_id, ew.edge_path || e.edge_type, ew.depth + 1
--   FROM exposure_walk ew
--   JOIN graph_edges e ON e.source_node_id = ew.current_node_id
--   WHERE ew.depth < 7
--     AND NOT (e.target_node_id = ANY(ew.node_path))
-- )
-- SELECT ew.*, target.label, target.sensitivity
-- FROM exposure_walk ew
-- JOIN graph_nodes target ON target.id = ew.current_node_id
-- WHERE target.node_type = 'Data object'
--   AND target.sensitivity IN ('pii', 'phi', 'pci', 'restricted');
