import { useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { AiExplainState, BehavioralIncident, HoundTrace as HoundTraceType } from "../types";
import { formatTimestamp, mitreName } from "../utils";
import { XIcon, CheckIcon, SparklesIcon } from "./icons";
import { severityColor } from "../utils";

type Props = {
  incident: BehavioralIncident | null;
  houndTrace: HoundTraceType | null;
  houndTraceLoading: boolean;
  acknowledged: boolean;
  resolvedReason?: string;
  aiConfigured: boolean;
  onClose: () => void;
  onAcknowledge: (id: string, reason: string) => void;
};

const REASON_LABELS: Record<string, string> = {
  user_acknowledged: "Marked safe",
  file_removed:      "File removed",
  process_ended:     "Process ended",
  quarantined:       "Quarantined",
  whitelisted:       "Whitelisted",
};

export function HoundTracePanel({
  incident,
  houndTrace,
  houndTraceLoading,
  acknowledged,
  resolvedReason,
  aiConfigured,
  onClose,
  onAcknowledge,
}: Props) {
  const [aiState, setAiState] = useState<AiExplainState>("idle");
  const [aiText, setAiText] = useState("");
  const scrollRef = useRef<HTMLDivElement>(null);

  if (!incident) return null;

  async function handleAiEnhance() {
    if (!incident) return;
    setAiState("loading");
    try {
      const explanation = await invoke<string>("explain_incident", {
        incidentJson: JSON.stringify(incident.raw_payload),
      });
      setAiText(explanation);
      setAiState("done");
    } catch (err) {
      setAiText(String(err));
      setAiState("error");
    }
  }

  const timelineSteps =
    incident.timeline_steps.length > 0
      ? incident.timeline_steps
      : incident.supporting_events.map((e) => e.replace(/^alert_/, "").replace(/_/g, " "));

  const sevColor = severityColor(incident.severity);

  return (
    <div className="detail-panel">
      {/* Header */}
      <div className="detail-header">
        <button className="detail-close-btn" onClick={onClose} aria-label="Close">
          <XIcon size={14} />
        </button>
        <div className="detail-title">{incident.attack_chain_label}</div>
      </div>

      {/* Body */}
      <div className="detail-body" ref={scrollRef}>
        {/* Severity + time */}
        <div className="detail-sev-row">
          <span
            className="detail-sev-chip"
            style={{
              background: sevColor + "1a",
              color: sevColor,
            }}
          >
            {incident.severity.toUpperCase()}
          </span>
          <span className="detail-time">{formatTimestamp(incident.timestamp)}</span>
          {houndTrace?.ai_enhanced && (
            <span className="detail-ai-badge">
              <SparklesIcon size={11} />
              AI enhanced
            </span>
          )}
        </div>

        {/* Hound Trace loading */}
        {houndTraceLoading && (
          <div className="detail-section">
            <div className="detail-section-body" style={{ color: "var(--text-tertiary)" }}>
              Generating trace...
            </div>
          </div>
        )}

        {/* Hound Trace narrative */}
        {!houndTraceLoading && houndTrace && (
          <>
            {houndTrace.verdict && (
              <div className="detail-section">
                <div className="detail-section-title">Verdict</div>
                <div className="detail-section-body">{houndTrace.verdict}</div>
              </div>
            )}

            <div className="detail-section">
              <div className="detail-section-title">What happened</div>
              <div className="detail-section-body">{houndTrace.what_happened}</div>
            </div>

            <div className="detail-section">
              <div className="detail-section-title">What was targeted</div>
              <div className="detail-section-body">{houndTrace.what_was_targeted}</div>
            </div>

            <div className="detail-section">
              <div className="detail-section-title">How it was caught</div>
              <div className="detail-section-body">{houndTrace.how_it_was_caught}</div>
            </div>

            <div className="detail-section">
              <div className="detail-section-title">What we did</div>
              <div className="detail-section-body">{houndTrace.what_we_did}</div>
            </div>

            {houndTrace.mitre_summary && (
              <div className="detail-section">
                <div className="detail-section-title">ATT&amp;CK mapping</div>
                <div className="detail-section-body">{houndTrace.mitre_summary}</div>
              </div>
            )}
          </>
        )}

        {/* Fallback when no trace yet */}
        {!houndTraceLoading && !houndTrace && (
          <div className="detail-section">
            <div className="detail-section-body">{incident.reason}</div>
          </div>
        )}

        {/* Attack chain */}
        {timelineSteps.length > 0 && (
          <div className="detail-section">
            <div className="detail-section-title">Attack chain</div>
            <div className="detail-timeline">
              {timelineSteps.map((step, i) => (
                <div key={i} className="detail-timeline-step">
                  <span className="detail-timeline-dot" />
                  {step}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* MITRE techniques */}
        {incident.mitre_techniques.length > 0 && (
          <div className="detail-section">
            <div className="detail-section-title">MITRE ATT&amp;CK</div>
            <div className="detail-tags">
              {incident.mitre_techniques.map((t) => (
                <span key={t} className="detail-tag" title={mitreName(t)}>
                  {t}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Primary path */}
        {incident.primary_path && (
          <div className="detail-section">
            <div className="detail-section-title">Path</div>
            <div className="detail-path">{incident.primary_path}</div>
          </div>
        )}

        {/* AI enhancement */}
        {aiConfigured && (
          <div className="detail-section">
            <button
              className="detail-enhance-btn"
              onClick={handleAiEnhance}
              disabled={aiState === "loading"}
            >
              <SparklesIcon size={12} />
              {aiState === "loading" ? "Analyzing..." : aiState === "done" ? "Re-analyze with AI" : "Analyze with AI"}
            </button>
            {aiState === "done" && (
              <div className="detail-section-body" style={{ marginTop: 8 }}>{aiText}</div>
            )}
            {aiState === "error" && (
              <div className="detail-section-body" style={{ marginTop: 8, color: "var(--red)" }}>{aiText}</div>
            )}
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="detail-actions">
        {acknowledged ? (
          <div className="detail-resolved-row">
            <CheckIcon size={12} />
            {resolvedReason ? (REASON_LABELS[resolvedReason] ?? resolvedReason) : "Resolved"}
          </div>
        ) : (
          <button
            className="detail-action-primary"
            onClick={() => onAcknowledge(incident.id, "user_acknowledged")}
          >
            Mark as resolved
          </button>
        )}
        <button
          className="detail-action-secondary"
          onClick={() => onAcknowledge(incident.id, "whitelisted")}
          disabled={acknowledged}
        >
          Add to whitelist
        </button>
      </div>
    </div>
  );
}
