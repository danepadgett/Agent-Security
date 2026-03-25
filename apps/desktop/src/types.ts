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

export type AppView = "incidents" | "health" | "settings";

export type AiExplainState = "idle" | "loading" | "done" | "error";
