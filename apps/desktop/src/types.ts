export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type TelemetryEvent = {
  id: string;
  timestamp: number | string;
  event_type: string;
  source: string;
  payload: Record<string, unknown>;
};

export type BehavioralIncident = {
  id: string;
  timestamp: number | string;
  incident_key: string;
  score: number;
  severity: Severity;
  confidence: string;
  attack_chain_label: string;
  reason: string;
  supporting_events: string[];
  timeline_steps: string[];
  mitre_techniques: string[];
  primary_path: string | null;
  process_name: string | null;
  chain_root_pid: number | null;
  raw_payload: Record<string, unknown>;
};

export type AgentStatus = {
  running: boolean;
  simulation_mode: boolean;
};

export type AppView = "dashboard" | "incidents" | "history" | "dark-web" | "account";

export type AiExplainState = "idle" | "loading" | "done" | "error";

export type HoundTrace = {
  incident_id: string;
  timestamp: string;
  headline: string;
  what_happened: string;
  what_was_targeted: string;
  how_it_was_caught: string;
  what_we_did: string;
  risk_level: string;
  mitre_summary: string;
  verdict: string;
  ai_enhanced: boolean;
};

export type ExecutionSource = "terminal" | "ide" | "ci" | "script" | "unknown";

export type ExecutionTrace = {
  id: string;
  timestamp: string | number;
  command: string;
  args: string;
  source: ExecutionSource;
  violation_kind: string | null; // null = clean execution
  reason: string;
  headline: string;
};

export type AcknowledgedRecord = {
  id: string;
  resolved_reason: string;
  resolved_at: string;
};

export type FeedTab = "inbox" | "resolved" | "all";
