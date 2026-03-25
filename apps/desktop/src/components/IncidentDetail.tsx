import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { AiExplainState, BehavioralIncident } from "../types";
import { formatTimestamp, mitreName } from "../utils";
import { ArrowLeftIcon, CheckIcon, LockIcon, SparklesIcon, TrashIcon } from "./icons";

type Props = {
  incident: BehavioralIncident | null;
  acknowledged: boolean;
  onClose: () => void;
  onAcknowledge: (id: string) => void;
};

// SVG score arc — circumference of r=38 circle
const R = 38;
const CIRC = 2 * Math.PI * R;

export function IncidentDetail({ incident, acknowledged, onClose, onAcknowledge }: Props) {
  const [arcOffset, setArcOffset] = useState(CIRC);
  const [showRaw, setShowRaw] = useState(false);
  const [quarantineStatus, setQuarantineStatus] = useState<"idle" | "running" | "done" | "error">("idle");
  const [quarantineError, setQuarantineError] = useState("");
  const [aiState, setAiState] = useState<AiExplainState>("idle");
  const [aiExplanation, setAiExplanation] = useState("");
  const scrollRef = useRef<HTMLDivElement>(null);

  // Reset state when incident changes
  useEffect(() => {
    setShowRaw(false);
    setQuarantineStatus("idle");
    setQuarantineError("");
    setAiState("idle");
    setAiExplanation("");
    scrollRef.current?.scrollTo({ top: 0 });
  }, [incident?.id]);

  // Animate score arc after mount
  useEffect(() => {
    if (!incident) return;
    setArcOffset(CIRC);
    const raf = requestAnimationFrame(() => {
      const pct = Math.min(Math.max(incident.score / 100, 0), 1);
      setArcOffset(CIRC * (1 - pct));
    });
    return () => cancelAnimationFrame(raf);
  }, [incident?.id, incident?.score]);

  const isOpen = incident !== null;

  async function handleQuarantine() {
    if (!incident?.primary_path) return;
    setQuarantineStatus("running");
    setQuarantineError("");
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("quarantine_file", { filePath: incident.primary_path });
      setQuarantineStatus("done");
    } catch (err) {
      setQuarantineStatus("error");
      setQuarantineError(String(err));
    }
  }

  async function handleExplain() {
    if (!incident) return;
    setAiState("loading");
    setAiExplanation("");
    try {
      const explanation = await invoke<string>("explain_incident", {
        incidentJson: JSON.stringify(incident.raw_payload),
      });
      setAiExplanation(explanation);
      setAiState("done");
    } catch (err) {
      setAiExplanation(String(err));
      setAiState("error");
    }
  }

  const timelineSteps =
    incident && incident.timeline_steps.length > 0
      ? incident.timeline_steps
      : incident?.supporting_events.map((e) => e.replace(/^alert_/, "").replace(/_/g, " ")) ?? [];

  return (
    <div className={`detail-panel ${isOpen ? "detail-panel--open" : ""}`}>
      {incident && (
        <>
          {/* Header */}
          <div className="detail-header" data-sev={incident.severity}>
            <button className="detail-close" onClick={onClose} aria-label="Close">
              <ArrowLeftIcon size={15} />
            </button>
            <div className="detail-header-center">
              {/* Score arc */}
              <svg className="score-arc" width="96" height="96" viewBox="0 0 96 96">
                <circle
                  cx="48" cy="48" r={R}
                  fill="none"
                  stroke="var(--sev-border)"
                  strokeWidth="4"
                />
                <circle
                  cx="48" cy="48" r={R}
                  fill="none"
                  stroke="var(--sev)"
                  strokeWidth="4"
                  strokeLinecap="round"
                  strokeDasharray={CIRC}
                  strokeDashoffset={arcOffset}
                  style={{ transition: "stroke-dashoffset 0.8s cubic-bezier(.4,0,.2,1)", transform: "rotate(-90deg)", transformOrigin: "50% 50%" }}
                />
                <text x="48" y="52" textAnchor="middle" className="score-arc-text" fill="var(--sev)">
                  {incident.score}
                </text>
              </svg>
            </div>
            <div className="detail-header-meta">
              <div className="detail-severity-badge" data-sev={incident.severity}>
                {incident.severity.toUpperCase()}
              </div>
              <div className="detail-confidence">
                Confidence: {incident.confidence}
              </div>
            </div>
          </div>

          {/* Scrollable body */}
          <div className="detail-scroll" ref={scrollRef}>
            <div className="detail-title">{incident.attack_chain_label}</div>
            <div className="detail-meta-row">
              <span>{formatTimestamp(incident.timestamp)}</span>
              {incident.chain_root_pid !== null && (
                <>
                  <span className="meta-sep">·</span>
                  <span>PID {incident.chain_root_pid}</span>
                </>
              )}
            </div>

            <div className="detail-reason">{incident.reason}</div>

            {/* Affected target */}
            {(incident.primary_path || incident.process_name) && (
              <div className="detail-section">
                <div className="detail-section-label">Affected</div>
                <div className="detail-target-block">
                  {incident.process_name && (
                    <div className="detail-target-row">
                      <span className="target-key">Process</span>
                      <code className="target-val">{incident.process_name}</code>
                    </div>
                  )}
                  {incident.primary_path && (
                    <div className="detail-target-row">
                      <span className="target-key">Path</span>
                      <code className="target-val">{incident.primary_path}</code>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Attack chain timeline */}
            {timelineSteps.length > 0 && (
              <div className="detail-section">
                <div className="detail-section-label">Attack chain</div>
                <div className="timeline">
                  {timelineSteps.map((step, i) => (
                    <div
                      key={i}
                      className="timeline-step"
                      style={{ animationDelay: `${i * 60}ms` }}
                    >
                      <div className="timeline-dot" data-sev={incident.severity} />
                      {i < timelineSteps.length - 1 && <div className="timeline-line" />}
                      <div className="timeline-text">{step}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* MITRE techniques */}
            {incident.mitre_techniques.length > 0 && (
              <div className="detail-section">
                <div className="detail-section-label">MITRE ATT&amp;CK</div>
                <div className="mitre-list">
                  {incident.mitre_techniques.map((t) => (
                    <div key={t} className="mitre-item">
                      <span className="mitre-id">{t}</span>
                      <span className="mitre-name">{mitreName(t)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Signals */}
            {incident.supporting_events.length > 0 && (
              <div className="detail-section">
                <div className="detail-section-label">Signals</div>
                <div className="signal-list">
                  {incident.supporting_events.map((e) => (
                    <div key={e} className="signal-row">
                      <span className="signal-dot" data-sev={incident.severity} />
                      <span className="signal-name">
                        {e.replace(/^alert_/, "").replace(/_/g, " ")}
                      </span>
                      <code className="signal-code">{e}</code>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* AI explanation */}
            <div className="detail-section">
              <div className="ai-explain-header">
                <div className="detail-section-label">AI Analysis</div>
                <button
                  className="ai-explain-btn"
                  onClick={handleExplain}
                  disabled={aiState === "loading"}
                >
                  <SparklesIcon size={13} />
                  {aiState === "loading" ? "Analyzing…" : aiState === "done" ? "Re-explain" : "Explain with AI"}
                </button>
              </div>
              {aiState === "loading" && (
                <div className="ai-explain-loading">
                  <span className="ai-explain-dot" />
                  <span className="ai-explain-dot" />
                  <span className="ai-explain-dot" />
                </div>
              )}
              {aiState === "done" && (
                <div className="ai-explain-text">{aiExplanation}</div>
              )}
              {aiState === "error" && (
                <div className="ai-explain-error">{aiExplanation}</div>
              )}
            </div>

            {/* Raw JSON */}
            <div className="detail-section">
              <button className="raw-toggle" onClick={() => setShowRaw((v) => !v)}>
                {showRaw ? "Hide" : "View"} raw JSON
              </button>
              {showRaw && (
                <pre className="raw-json">
                  {JSON.stringify(incident.raw_payload, null, 2)}
                </pre>
              )}
            </div>

            {/* Feedback */}
            {quarantineStatus === "done" && (
              <div className="feedback feedback--ok">File moved to runtime/quarantine/</div>
            )}
            {quarantineStatus === "error" && (
              <div className="feedback feedback--err">Quarantine failed: {quarantineError}</div>
            )}

            {/* Actions */}
            <div className="detail-actions">
              {incident.primary_path && quarantineStatus !== "done" && (
                <button
                  className="action-btn action-btn--danger"
                  onClick={handleQuarantine}
                  disabled={quarantineStatus === "running"}
                >
                  <TrashIcon size={13} />
                  {quarantineStatus === "running" ? "Quarantining…" : "Quarantine File"}
                </button>
              )}
              {!acknowledged ? (
                <button
                  className="action-btn action-btn--secondary"
                  onClick={() => onAcknowledge(incident.id)}
                >
                  <CheckIcon size={13} />
                  Mark as Safe
                </button>
              ) : (
                <div className="acked-badge">
                  <CheckIcon size={12} />
                  Marked as safe
                </div>
              )}
              {incident.primary_path && (
                <button className="action-btn action-btn--ghost" disabled>
                  <LockIcon size={13} />
                  Block Process
                </button>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
