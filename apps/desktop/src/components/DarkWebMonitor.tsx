import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { CheckIcon, XIcon } from "./icons";

type BreachResult = {
  name: string;
  title: string;
  domain: string;
  breach_date: string;
  description: string;
  pwn_count: number;
  data_classes: string[];
};

type Props = {
  onBreachCountChange?: (count: number) => void;
};

export function DarkWebMonitor({ onBreachCountChange }: Props) {
  const [hibpConfigured, setHibpConfigured] = useState(false);
  const [apiKeyInput, setApiKeyInput] = useState("");
  const [keyState, setKeyState] = useState<"idle" | "saving" | "saved" | "error">("idle");
  const [keyError, setKeyError] = useState("");

  const [emails, setEmails] = useState<string[]>([]);
  const [breaches, setBreaches] = useState<Record<string, BreachResult[]>>({});
  const [lastChecked, setLastChecked] = useState<Record<string, string>>({});
  const [emailInput, setEmailInput] = useState("");
  const [checkingEmail, setCheckingEmail] = useState<string | null>(null);
  const [checkError, setCheckError] = useState<Record<string, string>>({});
  const [addState, setAddState] = useState<"idle" | "checking" | "error">("idle");
  const [addError, setAddError] = useState("");

  const loadAll = useCallback(async () => {
    try {
      const [configured, monitoredEmails, breachData, checkedTimes] = await Promise.all([
        invoke<boolean>("get_hibp_configured"),
        invoke<string[]>("get_monitored_emails"),
        invoke<Record<string, BreachResult[]>>("get_breach_results"),
        invoke<Record<string, string>>("get_last_checked"),
      ]);
      setHibpConfigured(configured);
      setEmails(monitoredEmails);
      setBreaches(breachData);
      setLastChecked(checkedTimes);
    } catch { /* non-fatal */ }
  }, []);

  useEffect(() => {
    loadAll();
  }, [loadAll]);

  // Update parent with total breach count whenever breach data changes
  useEffect(() => {
    if (!onBreachCountChange) return;
    const total = Object.values(breaches).reduce((sum, arr) => sum + arr.length, 0);
    onBreachCountChange(total);
  }, [breaches, onBreachCountChange]);

  async function handleSaveApiKey() {
    const trimmed = apiKeyInput.trim();
    if (!trimmed) return;
    setKeyState("saving");
    setKeyError("");
    try {
      await invoke("save_hibp_api_key", { key: trimmed });
      setKeyState("saved");
      setHibpConfigured(true);
      setApiKeyInput("");
    } catch (err) {
      setKeyState("error");
      setKeyError(String(err));
    }
  }

  async function handleAddEmail() {
    const email = emailInput.trim().toLowerCase();
    if (!email || !email.includes("@")) {
      setAddError("Enter a valid email address.");
      return;
    }
    if (emails.includes(email)) {
      setAddError("This email is already monitored.");
      return;
    }
    setAddState("checking");
    setAddError("");
    try {
      await invoke("save_monitored_email", { email });
      setEmails((prev) => [...prev, email]);
      setEmailInput("");
      setAddState("idle");
      // Immediately check it if HIBP is configured
      if (hibpConfigured) {
        handleCheckEmail(email);
      }
    } catch (err) {
      setAddState("error");
      setAddError(String(err));
    }
  }

  async function handleRemoveEmail(email: string) {
    try {
      await invoke("remove_monitored_email", { email });
      setEmails((prev) => prev.filter((e) => e !== email));
      setBreaches((prev) => { const n = { ...prev }; delete n[email]; return n; });
      setLastChecked((prev) => { const n = { ...prev }; delete n[email]; return n; });
    } catch { /* non-fatal */ }
  }

  async function handleCheckEmail(email: string) {
    setCheckingEmail(email);
    setCheckError((prev) => ({ ...prev, [email]: "" }));
    try {
      const results = await invoke<BreachResult[]>("check_email_breaches", { email });
      setBreaches((prev) => ({ ...prev, [email]: results }));
      setLastChecked((prev) => ({ ...prev, [email]: new Date().toISOString() }));
    } catch (err) {
      setCheckError((prev) => ({ ...prev, [email]: String(err) }));
    } finally {
      setCheckingEmail(null);
    }
  }

  function formatRelativeTime(iso: string): string {
    if (!iso) return "Never";
    const diff = Date.now() - new Date(iso).getTime();
    const mins = Math.floor(diff / 60_000);
    if (mins < 1) return "Just now";
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  }

  function formatBreachDate(date: string): string {
    if (!date) return "";
    const d = new Date(date);
    return d.toLocaleDateString("en-US", { year: "numeric", month: "long" });
  }

  const allBreaches = Object.values(breaches).flat();

  return (
    <div className="dw-root">
      {/* Header */}
      <div className="dw-header">
        <div className="dw-header-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
            <circle cx="12" cy="12" r="3" stroke="currentColor" strokeWidth="1.5" />
          </svg>
        </div>
        <div>
          <div className="dw-header-title">Dark Web Monitor</div>
          <div className="dw-header-sub">
            Check if your email addresses appear in known data breaches
          </div>
        </div>
      </div>

      <div className="dw-body">
        {/* API Key section */}
        {!hibpConfigured ? (
          <div className="dw-section">
            <div className="dw-section-title">Enable monitoring</div>
            <div className="dw-api-notice">
              <div className="dw-api-notice-body">
                <p>
                  Hound uses the <strong>HaveIBeenPwned API</strong> to check your email addresses
                  against thousands of known data breaches. A personal API key is required —
                  it costs <strong>$3.95/month</strong>, paid directly to HaveIBeenPwned (not to Hound).
                </p>
                <p style={{ marginTop: 8 }}>
                  Get your key at{" "}
                  <span className="dw-link">haveibeenpwned.com/API/Key</span>
                </p>
              </div>
            </div>
            <div className="dw-input-row">
              <input
                className="dw-input"
                type="password"
                placeholder="Paste your HIBP API key…"
                value={apiKeyInput}
                onChange={(e) => setApiKeyInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSaveApiKey()}
              />
              <button
                className="dw-btn-primary"
                onClick={handleSaveApiKey}
                disabled={keyState === "saving" || !apiKeyInput.trim()}
              >
                {keyState === "saving" ? "Saving…" : "Save Key"}
              </button>
            </div>
            {keyState === "error" && <div className="dw-error">{keyError}</div>}
          </div>
        ) : (
          <div className="dw-section">
            <div className="dw-key-configured">
              <CheckIcon size={14} />
              <span>HIBP API key configured</span>
            </div>
          </div>
        )}

        {/* Add email */}
        <div className="dw-section">
          <div className="dw-section-title">Monitored addresses</div>
          <div className="dw-input-row">
            <input
              className="dw-input"
              type="email"
              placeholder="Add email address…"
              value={emailInput}
              onChange={(e) => setEmailInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleAddEmail()}
            />
            <button
              className="dw-btn-primary"
              onClick={handleAddEmail}
              disabled={addState === "checking" || !emailInput.trim()}
            >
              {addState === "checking" ? "Adding…" : "Add"}
            </button>
          </div>
          {addError && <div className="dw-error">{addError}</div>}

          {/* Email list */}
          {emails.length === 0 ? (
            <div className="dw-empty">No email addresses added yet.</div>
          ) : (
            <div className="dw-email-list">
              {emails.map((email) => {
                const emailBreaches = breaches[email] ?? [];
                const checked = lastChecked[email];
                const isChecking = checkingEmail === email;
                const err = checkError[email];
                const isClean = checked !== undefined && emailBreaches.length === 0;
                const hasBreaches = emailBreaches.length > 0;

                return (
                  <div key={email} className={`dw-email-row ${hasBreaches ? "dw-email-row--breach" : isClean ? "dw-email-row--clean" : ""}`}>
                    <div className="dw-email-info">
                      <div className="dw-email-addr">{email}</div>
                      <div className="dw-email-meta">
                        {isChecking ? (
                          <span className="dw-checking">Checking…</span>
                        ) : checked ? (
                          <>
                            {isClean && <span className="dw-clean-badge"><CheckIcon size={11} /> Secure</span>}
                            {hasBreaches && <span className="dw-breach-badge">{emailBreaches.length} breach{emailBreaches.length !== 1 ? "es" : ""}</span>}
                            <span className="dw-last-checked">Checked {formatRelativeTime(checked)}</span>
                          </>
                        ) : (
                          <span className="dw-last-checked">Not yet checked</span>
                        )}
                        {err && <span className="dw-error dw-error--inline">{err}</span>}
                      </div>
                    </div>
                    <div className="dw-email-actions">
                      {hibpConfigured && (
                        <button
                          className="dw-btn-ghost"
                          onClick={() => handleCheckEmail(email)}
                          disabled={isChecking}
                          title="Check now"
                        >
                          {isChecking ? "…" : "Check"}
                        </button>
                      )}
                      <button
                        className="dw-btn-ghost dw-btn-ghost--remove"
                        onClick={() => handleRemoveEmail(email)}
                        title="Remove"
                        aria-label={`Remove ${email}`}
                      >
                        <XIcon size={13} />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Breach alerts */}
        {allBreaches.length > 0 && (
          <div className="dw-section">
            <div className="dw-section-title">Recent breach alerts</div>
            <div className="dw-breach-list">
              {Object.entries(breaches).map(([email, emailBreaches]) =>
                emailBreaches.map((breach) => (
                  <div key={`${email}-${breach.name}`} className="dw-breach-card">
                    <div className="dw-breach-header">
                      <span className="dw-breach-icon">⚠</span>
                      <div>
                        <div className="dw-breach-title">{breach.title || breach.name}</div>
                        <div className="dw-breach-meta">
                          {email}
                          {breach.breach_date && (
                            <> · Breached {formatBreachDate(breach.breach_date)}</>
                          )}
                          {breach.pwn_count > 0 && (
                            <> · {breach.pwn_count.toLocaleString()} accounts affected</>
                          )}
                        </div>
                      </div>
                    </div>
                    {breach.data_classes.length > 0 && (
                      <div className="dw-breach-data">
                        <span className="dw-breach-data-label">Exposed:</span>{" "}
                        {breach.data_classes.join(", ")}
                      </div>
                    )}
                    <div className="dw-breach-advice">
                      {breach.data_classes.some((d) =>
                        d.toLowerCase().includes("password")
                      ) && (
                        <div className="dw-advice-item">
                          → Change your {breach.title || breach.name} password if you haven't already
                        </div>
                      )}
                      <div className="dw-advice-item">
                        → Check if you reuse this password on other services
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {/* All clear */}
        {emails.length > 0 && allBreaches.length === 0 && Object.keys(lastChecked).length === emails.length && (
          <div className="dw-section">
            <div className="dw-all-clear">
              <CheckIcon size={16} />
              <div>
                <div className="dw-all-clear-title">No breaches found</div>
                <div className="dw-all-clear-sub">
                  Your monitored addresses don't appear in any known data breaches.
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
