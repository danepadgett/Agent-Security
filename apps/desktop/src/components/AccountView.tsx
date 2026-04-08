import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { Session } from "@supabase/supabase-js";

type Props = {
  session: Session | null;
  onSignOut: () => void;
};

export function AccountView({ session, onSignOut }: Props) {
  const [agentId, setAgentId] = useState<string | null>(null);
  const [macosVersion, setMacosVersion] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    Promise.all([
      invoke<string>("get_agent_id").catch(() => null),
      invoke<string>("get_macos_version").catch(() => null),
    ]).then(([id, os]) => {
      setAgentId(id);
      setMacosVersion(os);
    });
  }, []);

  function copyAgentId() {
    if (!agentId) return;
    navigator.clipboard.writeText(agentId).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }

  const memberSince = session?.user.created_at
    ? new Date(session.user.created_at).toLocaleDateString("en-US", {
        month: "long",
        year: "numeric",
      })
    : null;

  const agentIdShort = agentId ? agentId.slice(0, 8) : null;

  return (
    <div className="account-view">
      {/* Account */}
      <div className="account-section">
        <div className="account-section-title">Account</div>
        {session ? (
          <>
            <div className="account-row">
              <span className="account-row-label">Email</span>
              <span className="account-row-value">{session.user.email}</span>
            </div>
            {memberSince && (
              <div className="account-row">
                <span className="account-row-label">Member since</span>
                <span className="account-row-value">{memberSince}</span>
              </div>
            )}
            <div className="account-row" style={{ marginTop: 8 }}>
              <button className="account-sign-out-btn" onClick={onSignOut}>
                Sign out
              </button>
            </div>
          </>
        ) : (
          <>
            <div className="account-row">
              <span className="account-row-label">Status</span>
              <span className="account-row-value" style={{ color: "var(--text-tertiary)" }}>
                Not signed in
              </span>
            </div>
            <div className="account-row" style={{ marginTop: 8 }}>
              <span style={{ fontSize: 11, color: "var(--text-tertiary)" }}>
                Sign in to sync your security history across devices.
              </span>
            </div>
          </>
        )}
      </div>

      {/* Device */}
      <div className="account-section">
        <div className="account-section-title">Device</div>
        <div className="account-row">
          <span className="account-row-label">Agent ID</span>
          <span className="account-row-value" style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontFamily: "monospace" }}>{agentIdShort ?? "..."}</span>
            {agentId && (
              <button
                onClick={copyAgentId}
                style={{
                  background: "none",
                  border: "1px solid var(--border-default)",
                  borderRadius: "var(--radius-sm)",
                  color: copied ? "var(--text-primary)" : "var(--text-tertiary)",
                  cursor: "pointer",
                  fontSize: 10,
                  padding: "1px 6px",
                  lineHeight: "16px",
                  transition: "color 0.15s",
                }}
              >
                {copied ? "Copied" : "Copy"}
              </button>
            )}
          </span>
        </div>
        <div className="account-row">
          <span className="account-row-label">macOS version</span>
          <span className="account-row-value">{macosVersion ?? "..."}</span>
        </div>
      </div>

      {/* App */}
      <div className="account-section">
        <div className="account-section-title">About Hound</div>
        <div className="account-row">
          <span className="account-row-label">Version</span>
          <span className="account-row-value">0.1.0</span>
        </div>
        <div className="account-row">
          <span className="account-row-label">Detection engine</span>
          <span className="account-row-value">165 tests</span>
        </div>
        <div className="account-row">
          <span className="account-row-label">MITRE coverage</span>
          <span className="account-row-value">~95% user-space</span>
        </div>
      </div>
    </div>
  );
}
