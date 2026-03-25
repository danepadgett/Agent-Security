import type { BehavioralIncident, Severity, TelemetryEvent } from "./types";

export function getTimestampMs(value: number | string | undefined): number {
  if (typeof value === "number") {
    return value < 10_000_000_000 ? value * 1000 : value;
  }
  if (typeof value === "string") {
    const numeric = Number(value);
    if (!Number.isNaN(numeric) && value.trim() !== "") {
      return numeric < 10_000_000_000 ? numeric * 1000 : numeric;
    }
    const parsed = Date.parse(value);
    if (!Number.isNaN(parsed)) return parsed;
  }
  return 0;
}

export function formatTimestamp(value: number | string | undefined): string {
  const ms = getTimestampMs(value);
  if (!ms) return "unknown";
  return new Date(ms).toLocaleString();
}

export function formatRelativeTime(value: number | string | undefined): string {
  const ms = getTimestampMs(value);
  if (!ms) return "unknown";
  const diffSecs = Math.floor((Date.now() - ms) / 1000);
  if (diffSecs < 5) return "just now";
  if (diffSecs < 60) return `${diffSecs}s ago`;
  const diffMins = Math.floor(diffSecs / 60);
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  return `${Math.floor(diffHours / 24)}d ago`;
}

export function asString(v: unknown): string | null {
  return typeof v === "string" && v.trim().length > 0 ? v : null;
}

export function asNumber(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string") {
    const n = Number(v);
    if (!Number.isNaN(n)) return n;
  }
  return null;
}

export function asStringArray(v: unknown): string[] | null {
  if (!Array.isArray(v)) return null;
  return v.filter((item): item is string => typeof item === "string");
}

export function normalizeSeverity(s: string | null | undefined): Severity {
  switch (s?.toLowerCase()) {
    case "critical": return "critical";
    case "high": return "high";
    case "medium": return "medium";
    case "low": return "low";
    default: return "info";
  }
}

export function severityRank(severity: Severity): number {
  switch (severity) {
    case "critical": return 5;
    case "high": return 4;
    case "medium": return 3;
    case "low": return 2;
    default: return 1;
  }
}

export function severityColor(severity: Severity): string {
  switch (severity) {
    case "critical": return "#ef4444";
    case "high": return "#f97316";
    case "medium": return "#eab308";
    case "low": return "#22c55e";
    default: return "#6b7280";
  }
}

export function severityLabel(severity: Severity): string {
  return severity.toUpperCase();
}

export function parseBehavioralIncident(event: TelemetryEvent): BehavioralIncident {
  const p = event.payload;
  const details = (typeof p.details === "object" && p.details !== null
    ? (p.details as Record<string, unknown>)
    : {});

  return {
    id: event.id,
    timestamp: event.timestamp,
    incident_key:
      asString(p.incident_key) ?? asString(details.incident_key) ?? event.id,
    score: asNumber(p.score) ?? 0,
    severity: normalizeSeverity(asString(p.severity)),
    confidence:
      asString(p.confidence) ?? asString(details.confidence) ?? "unknown",
    attack_chain_label:
      asString(p.attack_chain_label) ?? "Behavioral Incident",
    reason:
      asString(p.reason) ?? "Suspicious behavioral pattern detected",
    supporting_events:
      asStringArray(p.supporting_events) ??
      asStringArray(details.supporting_events) ??
      [],
    timeline_steps:
      asStringArray(p.timeline_steps) ??
      asStringArray(details.timeline_steps) ??
      [],
    mitre_techniques: asStringArray(p.mitre_techniques) ?? [],
    primary_path:
      asString(details.primary_path) ?? asString(p.primary_path) ?? null,
    process_name: asString(details.process_name) ?? null,
    chain_root_pid:
      asNumber(details.chain_root_pid) ?? asNumber(p.chain_root_pid) ?? null,
    raw_payload: p,
  };
}

export function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const mins = Math.floor(seconds / 60);
  if (mins < 60) return `${mins}m`;
  const hours = Math.floor(mins / 60);
  const rem = mins % 60;
  if (hours < 24) return rem > 0 ? `${hours}h ${rem}m` : `${hours}h`;
  const days = Math.floor(hours / 24);
  const remH = hours % 24;
  return remH > 0 ? `${days}d ${remH}h` : `${days}d`;
}

// Lookup table for MITRE ATT&CK technique display names.
const MITRE_NAMES: Record<string, string> = {
  // Execution
  "T1059":     "Command Scripting",
  "T1059.002": "AppleScript",
  "T1059.004": "Unix Shell",
  "T1059.006": "Python",
  "T1059.007": "JavaScript",
  "T1204.002": "Malicious File",
  "T1569":     "System Services",
  "T1106":     "Native API",
  "T1218":     "Signed Binary Proxy",
  // Persistence
  "T1037.002": "Login/Logout Hooks",
  "T1053.003": "Cron Job",
  "T1176":     "Browser Extension",
  "T1543.001": "Launch Daemon",
  "T1543.004": "Launch Agent",
  "T1547.001": "Login Items",
  // Privilege Escalation
  "T1548.001": "Setuid/Setgid",
  "T1548.004": "Elevated Execution Prompt",
  // Defense Evasion
  "T1027":     "Obfuscated Files",
  "T1036":     "Masquerading",
  "T1070":     "Indicator Removal",
  "T1070.003": "Clear History",
  "T1222.002": "File Permissions",
  "T1562":     "Impair Defenses",
  // Credential Access
  "T1056.001": "Keylogging",
  "T1555.001": "Keychain Access",
  "T1555.003": "Browser Credentials",
  "T1552.001": "Credentials in Files",
  "T1552.004": "SSH Private Keys",
  // Discovery
  "T1016":     "Network Config Discovery",
  "T1057":     "Process Discovery",
  "T1082":     "System Info Discovery",
  "T1083":     "File Discovery",
  // Lateral Movement
  "T1021.004": "SSH",
  "T1021.005": "VNC",
  // Collection
  "T1005":     "Local Data Staging",
  "T1113":     "Screen Capture",
  "T1560":     "Archive Data",
  // C2 & Exfiltration
  "T1041":     "Exfil Over C2",
  "T1071":     "App Layer Protocol",
  "T1105":     "Ingress Tool Transfer",
  // Impact
  "T1485":     "Data Destruction",
  "T1486":     "Data Encrypted",
  "T1489":     "Service Stop",
  // Other
  "T1136":     "Create Account",
};

export function mitreName(techniqueId: string): string {
  return MITRE_NAMES[techniqueId] ?? techniqueId;
}
