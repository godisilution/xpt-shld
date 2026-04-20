/*
  # Create Xpecto Shield Tables

  1. New Tables
    - `shield_incidents` - Records of detected security threats
      - `id` (uuid, primary key)
      - `created_at` (timestamptz, auto)
      - `timestamp` (timestamptz) - when the incident was detected
      - `source_ip` (text) - attacker IP address
      - `request_path` (text) - URL path of the request
      - `request_method` (text) - HTTP method (GET, POST, etc.)
      - `attack_category` (text) - type of attack (sqli, xss, lfi, ssrf, path-traversal)
      - `matched_payload` (text) - the payload pattern that matched
      - `confidence` (float8) - detection confidence score 0-1
      - `raw_input` (text) - original input before decoding
      - `action` (text) - action taken (blocked, logged)
      - `user_agent` (text) - client user-agent header
      - `geo_location` (text, nullable) - geographic location if available

    - `shield_blocked_ips` - IP addresses that have been blocked
      - `id` (uuid, primary key)
      - `created_at` (timestamptz, auto)
      - `ip_address` (text) - the blocked IP
      - `reason` (text) - reason for block (auto, manual)
      - `strike_count` (integer) - number of detected attacks
      - `blocked_at` (timestamptz) - when the block started
      - `expires_at` (timestamptz, nullable) - when the block expires
      - `last_attack_category` (text) - most recent attack type
      - `is_active` (boolean) - whether block is currently active

    - `shield_ai_reports` - AI-generated analytics reports
      - `id` (uuid, primary key)
      - `created_at` (timestamptz, auto)
      - `date_range_start` (text) - analysis period start
      - `date_range_end` (text) - analysis period end
      - `incident_count` (integer) - number of incidents analyzed
      - `executive_summary` (text) - AI summary
      - `pattern_analysis` (text) - JSON pattern insights
      - `trend_analysis` (text) - JSON trend data
      - `risk_assessment` (text) - JSON risk scores
      - `recommendations` (text) - JSON recommendations
      - `threat_level` (text) - overall threat level
      - `model_used` (text) - which AI model produced this

    - `shield_settings` - Key-value configuration store
      - `id` (uuid, primary key)
      - `created_at` (timestamptz, auto)
      - `key` (text, unique) - setting name
      - `value` (text) - setting value

  2. Indexes
    - shield_incidents: timestamp (DESC), source_ip, attack_category
    - shield_blocked_ips: ip_address, is_active

  3. Security
    - RLS enabled on all tables
    - Policies allow anon users full access for demo purposes
      (this is a security testing demo app, not a production system)
*/

-- ─── shield_incidents ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS shield_incidents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at timestamptz DEFAULT now(),
  timestamp timestamptz NOT NULL,
  source_ip text NOT NULL,
  request_path text NOT NULL,
  request_method text NOT NULL DEFAULT 'GET',
  attack_category text NOT NULL,
  matched_payload text NOT NULL DEFAULT '',
  confidence float8 NOT NULL DEFAULT 0,
  raw_input text NOT NULL DEFAULT '',
  action text NOT NULL DEFAULT 'blocked',
  user_agent text NOT NULL DEFAULT '',
  geo_location text
);

CREATE INDEX IF NOT EXISTS idx_shield_incidents_timestamp
  ON shield_incidents (timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_shield_incidents_source_ip
  ON shield_incidents (source_ip);

CREATE INDEX IF NOT EXISTS idx_shield_incidents_category
  ON shield_incidents (attack_category);

ALTER TABLE shield_incidents ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow anon select on shield_incidents"
  ON shield_incidents FOR SELECT
  TO anon
  USING (true);

CREATE POLICY "Allow anon insert on shield_incidents"
  ON shield_incidents FOR INSERT
  TO anon
  WITH CHECK (true);

-- ─── shield_blocked_ips ────────────────────────────────────
CREATE TABLE IF NOT EXISTS shield_blocked_ips (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at timestamptz DEFAULT now(),
  ip_address text NOT NULL,
  reason text NOT NULL DEFAULT 'auto',
  strike_count integer NOT NULL DEFAULT 0,
  blocked_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  last_attack_category text NOT NULL DEFAULT 'sqli',
  is_active boolean NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_shield_blocked_ips_address
  ON shield_blocked_ips (ip_address);

CREATE INDEX IF NOT EXISTS idx_shield_blocked_ips_active
  ON shield_blocked_ips (is_active);

ALTER TABLE shield_blocked_ips ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow anon select on shield_blocked_ips"
  ON shield_blocked_ips FOR SELECT
  TO anon
  USING (true);

CREATE POLICY "Allow anon insert on shield_blocked_ips"
  ON shield_blocked_ips FOR INSERT
  TO anon
  WITH CHECK (true);

CREATE POLICY "Allow anon update on shield_blocked_ips"
  ON shield_blocked_ips FOR UPDATE
  TO anon
  USING (true)
  WITH CHECK (true);

-- ─── shield_ai_reports ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS shield_ai_reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at timestamptz DEFAULT now(),
  date_range_start text NOT NULL,
  date_range_end text NOT NULL,
  incident_count integer NOT NULL DEFAULT 0,
  executive_summary text NOT NULL DEFAULT '',
  pattern_analysis text NOT NULL DEFAULT '',
  trend_analysis text NOT NULL DEFAULT '',
  risk_assessment text NOT NULL DEFAULT '',
  recommendations text NOT NULL DEFAULT '',
  threat_level text NOT NULL DEFAULT 'low',
  model_used text NOT NULL DEFAULT ''
);

ALTER TABLE shield_ai_reports ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow anon select on shield_ai_reports"
  ON shield_ai_reports FOR SELECT
  TO anon
  USING (true);

CREATE POLICY "Allow anon insert on shield_ai_reports"
  ON shield_ai_reports FOR INSERT
  TO anon
  WITH CHECK (true);

-- ─── shield_settings ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS shield_settings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at timestamptz DEFAULT now(),
  key text UNIQUE NOT NULL,
  value text NOT NULL DEFAULT ''
);

ALTER TABLE shield_settings ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow anon select on shield_settings"
  ON shield_settings FOR SELECT
  TO anon
  USING (true);

CREATE POLICY "Allow anon insert on shield_settings"
  ON shield_settings FOR INSERT
  TO anon
  WITH CHECK (true);

CREATE POLICY "Allow anon update on shield_settings"
  ON shield_settings FOR UPDATE
  TO anon
  USING (true)
  WITH CHECK (true);
