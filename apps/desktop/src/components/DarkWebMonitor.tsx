import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { XIcon } from "./icons";

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

  useEffect(() => { loadAll(); }, [loadAll]);

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
      if (hibpConfigured) handleCheckEmail(email);
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

  function rel(iso: string): string {
    if (!iso) return "Never";
    const diff = Date.now() - new Date(iso).getTime();
    const mins = Math.floor(diff / 60_000);
    if (mins < 1) return "Just now";
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  }

  function breachDate(date: string): string {
    if (!date) return "";
    return new Date(date).toLocaleDateString("en-US", { year: "numeric", month: "long" });
  }

  const allBreaches = Object.values(breaches).flat();

  return (
    <div className="dark-web-view">
      <div className="dark-web-header">
        <div className="dark-web-title">Dark Web Monitor</div>
        <div className="dark-web-sub">
          Check if your email addresses appear in known data breaches
        </div>
      </div>

      {/* Add email */}
      <div className="dark-web-email-form">
        <input
          className="dark-web-email-input"
          type="email"
          placeholder="Add email address..."
          value={emailInput}
          onChange={(e) => setEmailInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleAddEmail()}
        />
        <button
          className="dark-web-check-btn"
          onClick={handleAddEmail}
          disabled={addState === "checking" || !emailInput.trim()}
        >
          {addState === "checking" ? "Adding..." : "Add"}
        </button>
      </div>

      {addError && (
        <div style={{ padding: "4px 20px", fontSize: 11, color: "var(--red)" }}>{addError}</div>
      )}

      {/* Email chips */}
      {emails.length > 0 && (
        <div className="dark-web-emails">
          {emails.map((email) => (
            <span key={email} className="dark-web-email-chip">
              {email}
              <button onClick={() => handleRemoveEmail(email)} aria-label={`Remove ${email}`}>
                <XIcon size={10} />
              </button>
            </span>
          ))}
        </div>
      )}

      {/* HIBP API key setup */}
      {!hibpConfigured && (
        <div style={{ padding: "12px 20px", borderBottom: "1px solid var(--border-subtle)" }}>
          <div style={{ fontSize: 11, color: "var(--text-tertiary)", marginBottom: 8 }}>
            A HaveIBeenPwned API key is required to check breaches ($3.95/month, paid to HIBP directly).
          </div>
          <div style={{ display: "flex", gap: 6 }}>
            <input
              className="dark-web-email-input"
              type="password"
              placeholder="Paste HIBP API key..."
              value={apiKeyInput}
              onChange={(e) => setApiKeyInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSaveApiKey()}
            />
            <button
              className="dark-web-check-btn"
              onClick={handleSaveApiKey}
              disabled={keyState === "saving" || !apiKeyInput.trim()}
            >
              {keyState === "saving" ? "Saving..." : "Save key"}
            </button>
          </div>
          {keyState === "error" && (
            <div style={{ marginTop: 4, fontSize: 11, color: "var(--red)" }}>{keyError}</div>
          )}
        </div>
      )}

      {/* Results */}
      <div className="dark-web-results">
        {emails.length === 0 ? (
          <div className="dark-web-empty">
            Add an email address to check for data breaches.
          </div>
        ) : allBreaches.length === 0 && emails.every((e) => lastChecked[e]) ? (
          <div className="dark-web-safe">
            <div className="dark-web-safe-label">No breaches found</div>
            <div className="dark-web-safe-sub">
              Your monitored addresses don't appear in any known data breaches.
            </div>
          </div>
        ) : emails.some((e) => !lastChecked[e]) && hibpConfigured ? (
          <div className="dark-web-loading">
            {emails.filter((e) => checkingEmail === e).length > 0
              ? "Checking..."
              : emails.filter((e) => !lastChecked[e]).map((e) => (
                  <div key={e} style={{ display: "flex", gap: 8, justifyContent: "center", alignItems: "center" }}>
                    <span>{e}</span>
                    <button
                      className="dark-web-check-btn"
                      onClick={() => handleCheckEmail(e)}
                      disabled={checkingEmail === e}
                      style={{ padding: "4px 10px", fontSize: 11 }}
                    >
                      Check now
                    </button>
                  </div>
                ))
            }
          </div>
        ) : (
          Object.entries(breaches).flatMap(([email, emailBreaches]) =>
            emailBreaches.map((breach) => (
              <div key={`${email}-${breach.name}`} className="breach-row">
                <div className="breach-row-icon">
                  {breach.title?.[0] ?? breach.name?.[0] ?? "?"}
                </div>
                <div className="breach-row-body">
                  <div className="breach-row-name">{breach.title || breach.name}</div>
                  <div className="breach-row-date">
                    {email}
                    {breach.breach_date && ` · Breached ${breachDate(breach.breach_date)}`}
                    {breach.pwn_count > 0 && ` · ${breach.pwn_count.toLocaleString()} accounts`}
                  </div>
                  {breach.data_classes.length > 0 && (
                    <div className="breach-data-classes">
                      {breach.data_classes.map((dc) => (
                        <span key={dc} className="breach-data-class">{dc}</span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ))
          )
        )}

        {/* Per-email check buttons */}
        {hibpConfigured && emails.map((email) => (
          checkError[email] ? (
            <div key={email} style={{ padding: "8px 20px", fontSize: 11, color: "var(--red)" }}>
              {email}: {checkError[email]}
            </div>
          ) : null
        ))}
      </div>

      {/* Check all button */}
      {hibpConfigured && emails.length > 0 && (
        <div style={{ padding: "10px 20px", borderTop: "1px solid var(--border-subtle)", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <span style={{ fontSize: 11, color: "var(--text-tertiary)" }}>
            {emails.map((e) => lastChecked[e] ? `Checked ${rel(lastChecked[e])}` : "").filter(Boolean)[0] ?? ""}
          </span>
          <button
            className="dark-web-check-btn"
            onClick={() => emails.forEach((e) => handleCheckEmail(e))}
            disabled={checkingEmail !== null}
            style={{ padding: "5px 12px", fontSize: 11 }}
          >
            {checkingEmail ? "Checking..." : "Check all"}
          </button>
        </div>
      )}
    </div>
  );
}
