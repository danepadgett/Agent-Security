import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { CheckIcon, SparklesIcon } from "./icons";

type Props = {
  aiConfigured: boolean;
  onAiConfigured: () => void;
  logPath: string;
};

type WhitelistState = {
  trusted_process_paths: string[];
  trusted_process_names: string[];
  trusted_app_bundle_paths: string[];
};

const EMPTY_WHITELIST: WhitelistState = {
  trusted_process_paths: [],
  trusted_process_names: [],
  trusted_app_bundle_paths: [],
};

export function SettingsView({ aiConfigured, onAiConfigured, logPath }: Props) {
  const [apiKey, setApiKey] = useState("");
  const [saveState, setSaveState] = useState<"idle" | "saving" | "saved" | "error">("idle");
  const [saveError, setSaveError] = useState("");

  // Whitelist state
  const [whitelist, setWhitelist] = useState<WhitelistState>(EMPTY_WHITELIST);
  const [wlInput, setWlInput] = useState({ paths: "", names: "", bundles: "" });
  const [wlSaveState, setWlSaveState] = useState<"idle" | "saving" | "saved" | "error">("idle");
  const [wlError, setWlError] = useState("");

  // False positive cleanup
  const [fpState, setFpState] = useState<"idle" | "running" | "done" | "error">("idle");
  const [fpMessage, setFpMessage] = useState("");

  useEffect(() => {
    invoke<WhitelistState>("get_whitelist")
      .then((wl) => setWhitelist(wl))
      .catch(() => {}); // non-fatal — empty whitelist is safe default
  }, []);

  async function persistWhitelist(updated: WhitelistState) {
    setWlSaveState("saving");
    setWlError("");
    try {
      await invoke("update_whitelist", {
        trustedProcessPaths: updated.trusted_process_paths,
        trustedProcessNames: updated.trusted_process_names,
        trustedAppBundlePaths: updated.trusted_app_bundle_paths,
      });
      setWlSaveState("saved");
    } catch (err) {
      setWlSaveState("error");
      setWlError(String(err));
    }
  }

  function addToWhitelist(field: keyof WhitelistState, value: string) {
    const trimmed = value.trim();
    if (!trimmed || whitelist[field].includes(trimmed)) return;
    const updated = { ...whitelist, [field]: [...whitelist[field], trimmed] };
    setWhitelist(updated);
    setWlInput((prev) => ({ ...prev, [field === "trusted_process_paths" ? "paths" : field === "trusted_process_names" ? "names" : "bundles"]: "" }));
    persistWhitelist(updated);
  }

  function removeFromWhitelist(field: keyof WhitelistState, entry: string) {
    const updated = { ...whitelist, [field]: whitelist[field].filter((e) => e !== entry) };
    setWhitelist(updated);
    persistWhitelist(updated);
  }

  async function handleClearFalsePositives() {
    setFpState("running");
    setFpMessage("");
    try {
      const removed = await invoke<number>("clear_false_positives");
      setFpState("done");
      setFpMessage(
        removed === 0
          ? "No false positives found — inbox is already clean."
          : `Removed ${removed} incident${removed === 1 ? "" : "s"} caused by trusted development tools.`
      );
    } catch (err) {
      setFpState("error");
      setFpMessage(String(err));
    }
  }

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
          Your API key is stored securely in your macOS Keychain. It is never written to disk in plaintext.
          Only incident metadata (severity, signals, MITRE techniques) is sent to the API — not file contents.
          AI analysis is opt-in and runs only when you click "Explain with AI."
        </div>
      </div>

      <div className="settings-section">
        <div className="settings-section-title">Agent</div>
        <div className="settings-section-desc">
          Core detection and response settings are managed in <code>runtime/agent-config.toml</code>.
          Use the Health dashboard to toggle simulation mode.
        </div>
        <div className="settings-watch-path">Watching: <code>{logPath || "resolving…"}</code></div>
      </div>

      <div className="settings-section">
        <div className="settings-section-title">Trusted Processes</div>
        <div className="settings-section-desc">
          Processes and files matching these entries will never be killed or quarantined by the
          response engine, even when simulation mode is off.
        </div>

        <WhitelistGroup
          label="Process Binary Paths"
          hint="Full path to a binary, e.g. /usr/local/bin/node"
          entries={whitelist.trusted_process_paths}
          inputValue={wlInput.paths}
          onInputChange={(v) => setWlInput((p) => ({ ...p, paths: v }))}
          onAdd={() => addToWhitelist("trusted_process_paths", wlInput.paths)}
          onRemove={(e) => removeFromWhitelist("trusted_process_paths", e)}
        />

        <WhitelistGroup
          label="Process Names"
          hint="Command name only, e.g. node, python3"
          entries={whitelist.trusted_process_names}
          inputValue={wlInput.names}
          onInputChange={(v) => setWlInput((p) => ({ ...p, names: v }))}
          onAdd={() => addToWhitelist("trusted_process_names", wlInput.names)}
          onRemove={(e) => removeFromWhitelist("trusted_process_names", e)}
        />

        <WhitelistGroup
          label="App Bundle Paths"
          hint="Bundle path prefix, e.g. /Applications/Xcode.app"
          entries={whitelist.trusted_app_bundle_paths}
          inputValue={wlInput.bundles}
          onInputChange={(v) => setWlInput((p) => ({ ...p, bundles: v }))}
          onAdd={() => addToWhitelist("trusted_app_bundle_paths", wlInput.bundles)}
          onRemove={(e) => removeFromWhitelist("trusted_app_bundle_paths", e)}
        />

        {wlSaveState === "saved" && (
          <div className="settings-feedback settings-feedback--ok">Whitelist saved.</div>
        )}
        {wlSaveState === "error" && (
          <div className="settings-feedback settings-feedback--err">{wlError}</div>
        )}
      </div>

      <div className="settings-section">
        <div className="settings-section-title">Inbox Cleanup</div>
        <div className="settings-section-desc">
          Remove incidents from the inbox that were generated by trusted development tools
          (cargo builds, npm installs, ZoomUpdater, etc.). These are false positives — real
          attacks are not affected.
        </div>
        <div className="settings-input-row">
          <button
            className="settings-save-btn settings-save-btn--danger"
            onClick={handleClearFalsePositives}
            disabled={fpState === "running"}
          >
            {fpState === "running" ? "Cleaning…" : "Clear False Positives"}
          </button>
        </div>
        {fpState === "done" && (
          <div className="settings-feedback settings-feedback--ok">{fpMessage}</div>
        )}
        {fpState === "error" && (
          <div className="settings-feedback settings-feedback--err">{fpMessage}</div>
        )}
      </div>
    </div>
  );
}

function WhitelistGroup({
  label,
  hint,
  entries,
  inputValue,
  onInputChange,
  onAdd,
  onRemove,
}: {
  label: string;
  hint: string;
  entries: string[];
  inputValue: string;
  onInputChange: (v: string) => void;
  onAdd: () => void;
  onRemove: (entry: string) => void;
}) {
  return (
    <div className="whitelist-group">
      <div className="whitelist-group-label">{label}</div>
      {entries.length > 0 && (
        <ul className="whitelist-entries">
          {entries.map((entry) => (
            <li key={entry} className="whitelist-entry">
              <span className="whitelist-entry-text">{entry}</span>
              <button
                className="whitelist-entry-remove"
                onClick={() => onRemove(entry)}
                aria-label={`Remove ${entry}`}
                title="Remove"
              >
                ×
              </button>
            </li>
          ))}
        </ul>
      )}
      <div className="settings-input-row">
        <input
          className="settings-input"
          type="text"
          placeholder={hint}
          value={inputValue}
          onChange={(e) => onInputChange(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") onAdd(); }}
        />
        <button
          className="settings-save-btn"
          onClick={onAdd}
          disabled={!inputValue.trim()}
        >
          Add
        </button>
      </div>
    </div>
  );
}
