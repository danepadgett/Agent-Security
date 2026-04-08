import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { XIcon, CheckIcon, SparklesIcon } from "./icons";

type Props = {
  aiConfigured: boolean;
  onAiConfigured: () => void;
  logPath: string;
  agentSimMode: boolean;
  onToggleSimMode: (enabled: boolean) => void;
  onClose: () => void;
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

export function SettingsView({
  aiConfigured,
  onAiConfigured,
  logPath,
  agentSimMode,
  onToggleSimMode,
  onClose,
}: Props) {
  const [apiKey, setApiKey] = useState("");
  const [saveState, setSaveState] = useState<"idle" | "saving" | "saved" | "error">("idle");
  const [saveError, setSaveError] = useState("");

  const [whitelist, setWhitelist] = useState<WhitelistState>(EMPTY_WHITELIST);
  const [wlInput, setWlInput] = useState({ paths: "", names: "", bundles: "" });
  const [wlSaveState, setWlSaveState] = useState<"idle" | "saving" | "saved" | "error">("idle");
  const [wlError, setWlError] = useState("");

  const [fpState, setFpState] = useState<"idle" | "running" | "done" | "error">("idle");
  const [fpMessage, setFpMessage] = useState("");

  useEffect(() => {
    invoke<WhitelistState>("get_whitelist")
      .then((wl) => setWhitelist(wl))
      .catch(() => {});
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
    const inputKey = field === "trusted_process_paths" ? "paths" : field === "trusted_process_names" ? "names" : "bundles";
    setWlInput((prev) => ({ ...prev, [inputKey]: "" }));
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
          : `Removed ${removed} incident${removed === 1 ? "" : "s"} from trusted development tools.`
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
    <div className="settings-overlay" onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="settings-modal">
        <div className="settings-modal-header">
          <div className="settings-modal-title">Settings</div>
          <button className="settings-modal-close" onClick={onClose} aria-label="Close">
            <XIcon size={14} />
          </button>
        </div>

        <div className="settings-modal-body">
          {/* Detection */}
          <div className="settings-section">
            <div className="settings-section-title">Detection</div>
            <div className="settings-row">
              <div className="settings-row-left">
                <div className="settings-row-label">Simulation mode</div>
                <div className="settings-row-sub">
                  Log and alert without killing processes or quarantining files
                </div>
              </div>
              <label className="toggle">
                <input
                  type="checkbox"
                  checked={agentSimMode}
                  onChange={(e) => onToggleSimMode(e.target.checked)}
                />
                <span className="toggle-track" />
                <span className="toggle-thumb" />
              </label>
            </div>
          </div>

          {/* AI */}
          <div className="settings-section">
            <div className="settings-section-title">AI Analysis</div>
            <div className="settings-row">
              <div className="settings-row-left">
                <div className="settings-row-label">
                  {aiConfigured ? (
                    <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <CheckIcon size={13} />
                      API key configured
                    </span>
                  ) : (
                    <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <SparklesIcon size={13} />
                      No API key
                    </span>
                  )}
                </div>
                <div className="settings-row-sub">
                  Stored in macOS Keychain, never written to disk
                </div>
              </div>
            </div>
            <div className="settings-api-input-row">
              <input
                className="settings-api-input"
                type="password"
                placeholder="sk-ant-..."
                value={apiKey}
                onChange={(e) => { setApiKey(e.target.value); if (saveState !== "idle") setSaveState("idle"); }}
                onKeyDown={(e) => { if (e.key === "Enter") handleSaveKey(); }}
              />
              <button
                className="settings-save-btn"
                onClick={handleSaveKey}
                disabled={!apiKey.trim() || saveState === "saving"}
              >
                {saveState === "saving" ? "Saving..." : "Save"}
              </button>
            </div>
            {saveState === "saved" && (
              <div style={{ fontSize: 11, color: "var(--text-tertiary)", marginTop: 4 }}>Saved.</div>
            )}
            {saveState === "error" && (
              <div style={{ fontSize: 11, color: "var(--red)", marginTop: 4 }}>{saveError}</div>
            )}
          </div>

          {/* Trusted processes */}
          <div className="settings-section">
            <div className="settings-section-title">Trusted Processes</div>
            <div style={{ fontSize: 11, color: "var(--text-tertiary)", marginBottom: 12 }}>
              Processes matching these entries will never be killed or quarantined.
            </div>

            <WhitelistGroup
              label="Process names (e.g. node, python3)"
              entries={whitelist.trusted_process_names}
              inputValue={wlInput.names}
              onInputChange={(v) => setWlInput((p) => ({ ...p, names: v }))}
              onAdd={() => addToWhitelist("trusted_process_names", wlInput.names)}
              onRemove={(e) => removeFromWhitelist("trusted_process_names", e)}
            />

            <WhitelistGroup
              label="Binary paths (e.g. /usr/local/bin/node)"
              entries={whitelist.trusted_process_paths}
              inputValue={wlInput.paths}
              onInputChange={(v) => setWlInput((p) => ({ ...p, paths: v }))}
              onAdd={() => addToWhitelist("trusted_process_paths", wlInput.paths)}
              onRemove={(e) => removeFromWhitelist("trusted_process_paths", e)}
            />

            <WhitelistGroup
              label="App bundles (e.g. /Applications/Xcode.app)"
              entries={whitelist.trusted_app_bundle_paths}
              inputValue={wlInput.bundles}
              onInputChange={(v) => setWlInput((p) => ({ ...p, bundles: v }))}
              onAdd={() => addToWhitelist("trusted_app_bundle_paths", wlInput.bundles)}
              onRemove={(e) => removeFromWhitelist("trusted_app_bundle_paths", e)}
            />

            {wlSaveState === "saved" && (
              <div style={{ fontSize: 11, color: "var(--text-tertiary)", marginTop: 4 }}>Saved.</div>
            )}
            {wlSaveState === "error" && (
              <div style={{ fontSize: 11, color: "var(--red)", marginTop: 4 }}>{wlError}</div>
            )}
          </div>

          {/* Agent */}
          <div className="settings-section">
            <div className="settings-section-title">Agent</div>
            <div className="settings-row">
              <div className="settings-row-left">
                <div className="settings-row-label">Log path</div>
              </div>
            </div>
            <div className="settings-log-path">{logPath || "Resolving..."}</div>
          </div>

          {/* Danger zone */}
          <div className="settings-section">
            <div className="settings-section-title">Danger Zone</div>
            <div className="settings-row">
              <div className="settings-row-left">
                <div className="settings-row-label">Clear false positives</div>
                <div className="settings-row-sub">
                  Remove inbox items caused by trusted development tools
                </div>
              </div>
              <button
                className="settings-danger-btn"
                onClick={handleClearFalsePositives}
                disabled={fpState === "running"}
              >
                {fpState === "running" ? "Clearing..." : "Clear"}
              </button>
            </div>
            {(fpState === "done" || fpState === "error") && (
              <div style={{ fontSize: 11, color: fpState === "error" ? "var(--red)" : "var(--text-tertiary)", marginTop: 4 }}>
                {fpMessage}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function WhitelistGroup({
  label,
  entries,
  inputValue,
  onInputChange,
  onAdd,
  onRemove,
}: {
  label: string;
  entries: string[];
  inputValue: string;
  onInputChange: (v: string) => void;
  onAdd: () => void;
  onRemove: (entry: string) => void;
}) {
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.06em", color: "var(--text-tertiary)", marginBottom: 6, textTransform: "uppercase" }}>
        {label}
      </div>
      {entries.length > 0 && (
        <div className="settings-whitelist">
          {entries.map((entry) => (
            <div key={entry} className="settings-whitelist-item">
              <span className="settings-whitelist-item-text">{entry}</span>
              <button
                className="settings-whitelist-remove"
                onClick={() => onRemove(entry)}
                aria-label={`Remove ${entry}`}
              >
                <XIcon size={11} />
              </button>
            </div>
          ))}
        </div>
      )}
      <div className="settings-whitelist-add">
        <input
          type="text"
          placeholder="Add entry..."
          value={inputValue}
          onChange={(e) => onInputChange(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") onAdd(); }}
        />
        <button
          className="settings-whitelist-add-btn"
          onClick={onAdd}
          disabled={!inputValue.trim()}
        >
          Add
        </button>
      </div>
    </div>
  );
}
