import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { CheckIcon, SparklesIcon } from "./icons";

type Props = {
  aiConfigured: boolean;
  onAiConfigured: () => void;
};

export function SettingsView({ aiConfigured, onAiConfigured }: Props) {
  const [apiKey, setApiKey] = useState("");
  const [saveState, setSaveState] = useState<"idle" | "saving" | "saved" | "error">("idle");
  const [saveError, setSaveError] = useState("");

  async function handleSaveKey() {
    const trimmed = apiKey.trim();
    if (!trimmed) return;
    setSaveState("saving");
    setSaveError("");
    try {
      await invoke("set_api_key", { key: trimmed });
      setSaveState("saved");
      setApiKey("");
      onAiConfigured();
    } catch (err) {
      setSaveState("error");
      setSaveError(String(err));
    }
  }

  return (
    <div className="settings-view">
      <div className="settings-section">
        <div className="settings-section-title">AI Analysis</div>
        <div className="settings-section-desc">
          Explain security incidents in plain English using Claude. Requires an Anthropic API key.
          Your key is stored locally in <code>runtime/agent-config.toml</code>.
        </div>

        <div className="settings-ai-status">
          {aiConfigured ? (
            <div className="ai-status-badge ai-status-badge--ok">
              <CheckIcon size={13} />
              API key configured — AI explanations enabled
            </div>
          ) : (
            <div className="ai-status-badge ai-status-badge--unset">
              <SparklesIcon size={13} />
              No API key set — AI explanations disabled
            </div>
          )}
        </div>

        <div className="settings-field">
          <label className="settings-label" htmlFor="api-key-input">
            {aiConfigured ? "Replace API key" : "Anthropic API key"}
          </label>
          <div className="settings-input-row">
            <input
              id="api-key-input"
              className="settings-input"
              type="password"
              placeholder="sk-ant-..."
              value={apiKey}
              onChange={(e) => {
                setApiKey(e.target.value);
                if (saveState !== "idle") setSaveState("idle");
              }}
              onKeyDown={(e) => { if (e.key === "Enter") handleSaveKey(); }}
            />
            <button
              className="settings-save-btn"
              onClick={handleSaveKey}
              disabled={!apiKey.trim() || saveState === "saving"}
            >
              {saveState === "saving" ? "Saving…" : "Save"}
            </button>
          </div>
          {saveState === "saved" && (
            <div className="settings-feedback settings-feedback--ok">Key saved successfully.</div>
          )}
          {saveState === "error" && (
            <div className="settings-feedback settings-feedback--err">{saveError}</div>
          )}
        </div>

        <div className="settings-note">
          Keys are never sent to any server other than api.anthropic.com.
          Only the incident summary (severity, signals, MITRE techniques) is included in the prompt — not file contents.
          AI analysis is opt-in and runs only when you click "Explain with AI."
        </div>
      </div>

      <div className="settings-section">
        <div className="settings-section-title">Agent</div>
        <div className="settings-section-desc">
          Core detection and response settings are managed in <code>runtime/agent-config.toml</code>.
          Use the Health dashboard to toggle simulation mode.
        </div>
      </div>
    </div>
  );
}
