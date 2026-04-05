import { useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { AiExplainState, BehavioralIncident, StoryLine as StoryLineType } from "../types";
import { formatTimestamp, mitreName } from "../utils";
import { ArrowLeftIcon, CheckIcon, LockIcon, SparklesIcon, TrashIcon } from "./icons";

type Props = {
  incident: BehavioralIncident | null;
  storyline: StoryLineType | null;
  storylineLoading: boolean;
  acknowledged: boolean;
  resolvedReason?: string;
  aiConfigured: boolean;
  onClose: () => void;
  onAcknowledge: (id: string, reason: string) => void;
};

export function StoryLinePanel({
  incident,
  storyline,
  storylineLoading,
  acknowledged,
  resolvedReason,
  aiConfigured,
  onClose,
  onAcknowledge,
}: Props) {
  const [showTechnical, setShowTechnical] = useState(false);
  const [quarantineStatus, setQuarantineStatus] = useState<"idle" | "running" | "done" | "error">("idle");
  const [quarantineError, setQuarantineError] = useState("");
  const [aiState, setAiState] = useState<AiExplainState>("idle");
  const [aiEnhancement, setAiEnhancement] = useState("");
  const scrollRef = useRef<HTMLDivElement>(null);

  const isOpen = incident !== null;

  async function handleQuarantine() {
    if (!incident?.primary_path) return;
    setQuarantineStatus("running");
    try {
      await invoke("quarantine_file", { filePath: incident.primary_path });
      setQuarantineStatus("done");
    } catch (err) {
      setQuarantineStatus("error");
      setQuarantineError(String(err));
    }
  }

  async function handleAiEnhance() {
    if (!incident) return;
    setAiState("loading");
    try {
      const explanation = await invoke<string>("explain_incident", {
        incidentJson: JSON.stringify(incident.raw_payload),
      });
      setAiEnhancement(explanation);
      setAiState("done");
    } catch (err) {
      setAiEnhancement(String(err));
      setAiState("error");
    }
  }

  const verdictClass = storyline
    ? storyline.verdict === "Blocked" ? "blocked"
      : storyline.verdict === "Simulated block" ? "simulated"
      : "monitoring"
    : "monitoring";

  const riskClass = storyline
    ? storyline.risk_level.toLowerCase()
    : incident?.severity ?? "medium";

  const timelineSteps =
    incident && incident.timeline_steps.length > 0
      ? incident.timeline_steps
      : incident?.supporting_events.map((e) => e.replace(/^alert_/, "").replace(/_/g, " ")) ?? [];

  return (
    <div className={`detail-panel storyline-panel ${isOpen ? "detail-panel--open" : ""}`}>
      {incident && (
        <>
          {/* Header */}
          <div className="storyline-header" data-sev={incident.severity}>
            <button className="detail-close" onClick={onClose} aria-label="Close">
              <ArrowLeftIcon size={15} />
            </button>
            <div className="storyline-header-badges">
              {storyline && (
                <span className={`verdict-badge verdict-badge--${verdictClass}`}>
                  {storyline.verdict}
                </span>
              )}
              <span className={`risk-badge risk-badge--${riskClass}`}>
                {storyline ? storyline.risk_level : incident.severity.toUpperCase()}
              </span>
              {storyline?.ai_enhanced && (
                <span className="ai-enhanced-badge">
                  <SparklesIcon size={11} />
                  AI Enhanced
                </span>
              )}
            </div>
            <span className="storyline-header-time">{formatTimestamp(incident.timestamp)}</span>
          </div>

          {/* Scrollable body */}
          <div className="storyline-scroll" ref={scrollRef}>
            {storylineLoading && (
              <div className="storyline-loading">
                <div className="ai-explain-loading">
                  <span className="ai-explain-dot" />
                  <span className="ai-explain-dot" />
                  <span className="ai-explain-dot" />
                </div>
                <span className="storyline-loading-text">Generating story…</span>
              </div>
            )}

            {!storylineLoading && storyline && (
              <>
                {/* Headline */}
                <div className="storyline-headline">{storyline.headline}</div>

                <div className="storyline-divider" />

                {/* Narrative sections */}
                <div className="storyline-section">
                  <div className="storyline-section-label">📋 What happened</div>
                  <p className="storyline-text">{storyline.what_happened}</p>
                </div>

                <div className="storyline-section">
                  <div className="storyline-section-label">🎯 What was targeted</div>
                  <p className="storyline-text storyline-text--targeted">{storyline.what_was_targeted}</p>
                </div>

                <div className="storyline-section">
                  <div className="storyline-section-label">🔍 How it was caught</div>
                  <p className="storyline-text">{storyline.how_it_was_caught}</p>
                </div>

                <div className="storyline-section">
                  <div className="storyline-section-label">🛡️ What we did</div>
                  <p className="storyline-text">{storyline.what_we_did}</p>
                </div>

                {/* MITRE summary */}
                <div className="storyline-mitre-summary">{storyline.mitre_summary}</div>

                {/* AI enhancement section */}
                {aiConfigured && (
                  <div className="storyline-section">
                    <div className="storyline-ai-row">
                      <div className="storyline-section-label">AI Deep Dive</div>
                      <button
                        className="ai-explain-btn"
                        onClick={handleAiEnhance}
                        disabled={aiState === "loading"}
                      >
                        <SparklesIcon size={12} />
                        {aiState === "loading" ? "Analyzing…" : aiState === "done" ? "Re-analyze" : "Analyze with AI"}
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
                      <div className="ai-explain-text">{aiEnhancement}</div>
                    )}
                    {aiState === "error" && (
                      <div className="ai-explain-error">{aiEnhancement}</div>
                    )}
                  </div>
                )}

                {/* Technical details (expandable) */}
                <div className="storyline-technical">
                  <button
                    className="storyline-technical-toggle"
                    onClick={() => setShowTechnical((v) => !v)}
                  >
                    {showTechnical ? "▼" : "▶"} Technical details
                  </button>
                  {showTechnical && (
                    <div className="storyline-technical-body">
                      <div className="tech-row">
                        <span className="tech-key">Score</span>
                        <span className="tech-val">{incident.score}/100</span>
                      </div>
                      <div className="tech-row">
                        <span className="tech-key">Confidence</span>
                        <span className="tech-val">{incident.confidence}</span>
                      </div>
                      {incident.chain_root_pid !== null && (
                        <div className="tech-row">
                          <span className="tech-key">Root PID</span>
                          <span className="tech-val">{incident.chain_root_pid}</span>
                        </div>
                      )}
                      {incident.mitre_techniques.length > 0 && (
                        <div className="tech-section">
                          <div className="tech-section-label">MITRE ATT&amp;CK</div>
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
                      {incident.supporting_events.length > 0 && (
                        <div className="tech-section">
                          <div className="tech-section-label">Signals</div>
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
                      {timelineSteps.length > 0 && (
                        <div className="tech-section">
                          <div className="tech-section-label">Attack chain</div>
                          <div className="timeline">
                            {timelineSteps.map((step, i) => (
                              <div key={i} className="timeline-step" style={{ animationDelay: `${i * 60}ms` }}>
                                <div className="timeline-dot" data-sev={incident.severity} />
                                {i < timelineSteps.length - 1 && <div className="timeline-line" />}
                                <div className="timeline-text">{step}</div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </>
            )}

            {!storylineLoading && !storyline && (
              <div className="storyline-fallback">
                <div className="detail-title">{incident.attack_chain_label}</div>
                <div className="detail-reason">{incident.reason}</div>
              </div>
            )}

            {/* Response feedback */}
            {quarantineStatus === "done" && (
              <div className="feedback feedback--ok">File moved to quarantine.</div>
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
              {acknowledged ? (
                <div className="acked-badge">
                  <CheckIcon size={12} />
                  {resolvedReason === "quarantined" ? "Quarantined" : "Resolved"}
                </div>
              ) : (
                <button
                  className="action-btn action-btn--secondary"
                  onClick={() => onAcknowledge(incident.id, "user_acknowledged")}
                >
                  <CheckIcon size={13} />
                  Mark as Resolved
                </button>
              )}
              {incident.primary_path && (
                <button className="action-btn action-btn--ghost" disabled>
                  <LockIcon size={13} />
                  Block Process
                </button>
              )}
            </div>

            {!aiConfigured && (
              <div className="storyline-ai-hint">
                Add an Anthropic API key in Settings for AI-enhanced explanations
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
