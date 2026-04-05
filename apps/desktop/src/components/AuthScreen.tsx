import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { supabase } from "../lib/supabase";

type Tab = "signup" | "signin";
type Strength = "weak" | "fair" | "strong";

type Props = {
  onComplete: () => void;
};

function ShieldAuthIcon({ size = 64 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
      <path
        d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z"
        fill="rgba(16,185,129,0.15)"
        stroke="#10b981"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <path
        d="M9 12l2 2 4-4"
        stroke="#10b981"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function EyeIcon({ show }: { show: boolean }) {
  if (show) {
    return (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
        <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
        <path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
        <path d="M1 1l22 22" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
      </svg>
    );
  }
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"/>
      <circle cx="12" cy="12" r="3" stroke="currentColor" strokeWidth="1.5"/>
    </svg>
  );
}

function Spinner() {
  return (
    <svg className="auth-spinner" width="16" height="16" viewBox="0 0 24 24" fill="none">
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="2.5" strokeOpacity="0.25"/>
      <path d="M12 2a10 10 0 0110 10" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"/>
    </svg>
  );
}

function passwordStrength(pw: string): Strength {
  if (pw.length < 8) return "weak";
  const hasUpper = /[A-Z]/.test(pw);
  const hasLower = /[a-z]/.test(pw);
  const hasNum = /[0-9]/.test(pw);
  const hasSpecial = /[^A-Za-z0-9]/.test(pw);
  const score = [hasUpper, hasLower, hasNum, hasSpecial].filter(Boolean).length;
  if (pw.length >= 12 && score >= 3) return "strong";
  if (pw.length >= 8 && score >= 2) return "fair";
  return "weak";
}

function PasswordInput({
  label,
  value,
  onChange,
  onKeyDown,
  autoComplete,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  onKeyDown?: (e: React.KeyboardEvent) => void;
  autoComplete: string;
  placeholder?: string;
}) {
  const [show, setShow] = useState(false);
  return (
    <div className="auth-field">
      <label className="auth-label">{label}</label>
      <div className="auth-input-wrap">
        <input
          className="auth-input"
          type={show ? "text" : "password"}
          placeholder={placeholder ?? label}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={onKeyDown}
          autoComplete={autoComplete}
        />
        <button
          type="button"
          className="auth-eye-btn"
          onClick={() => setShow((s) => !s)}
          tabIndex={-1}
        >
          <EyeIcon show={show} />
        </button>
      </div>
    </div>
  );
}

export function AuthScreen({ onComplete }: Props) {
  const [tab, setTab] = useState<Tab>("signup");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [showFreeScreen, setShowFreeScreen] = useState(false);

  function switchTab(t: Tab) {
    setTab(t);
    setError("");
    setConfirmPassword("");
  }

  async function handleSignUp() {
    if (!email.trim() || !password.trim()) {
      setError("Please fill in all fields.");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const { data, error: err } = await supabase.auth.signUp({ email, password });
      if (err) {
        setError(err.message);
        return;
      }
      if (data.session?.access_token) {
        await invoke("save_auth_token", { token: data.session.access_token }).catch(() => {});
      }
      setShowFreeScreen(true);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  async function handleSignIn() {
    if (!email.trim() || !password.trim()) {
      setError("Please fill in all fields.");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const { data, error: err } = await supabase.auth.signInWithPassword({ email, password });
      if (err) {
        setError(err.message);
        return;
      }
      if (data.session?.access_token) {
        await invoke("save_auth_token", { token: data.session.access_token }).catch(() => {});
      }
      onComplete();
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  async function handleForgotPassword() {
    if (!email.trim()) {
      setError("Enter your email address first.");
      return;
    }
    await supabase.auth.resetPasswordForEmail(email.trim()).catch(() => {});
    setError("Password reset email sent — check your inbox.");
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Enter") {
      tab === "signup" ? handleSignUp() : handleSignIn();
    }
  }

  if (showFreeScreen) {
    return <FreeScreen onComplete={onComplete} />;
  }

  const strength = password ? passwordStrength(password) : null;

  return (
    <div className="auth-overlay">
      <div className="auth-card">
        {/* Logo */}
        <div className="auth-logo-block">
          <ShieldAuthIcon size={64} />
          <div className="auth-wordmark">Hound</div>
        </div>

        {/* Tabs */}
        <div className="auth-tabs">
          <button
            className={`auth-tab ${tab === "signup" ? "auth-tab--active" : ""}`}
            onClick={() => switchTab("signup")}
          >
            Sign Up
          </button>
          <button
            className={`auth-tab ${tab === "signin" ? "auth-tab--active" : ""}`}
            onClick={() => switchTab("signin")}
          >
            Sign In
          </button>
        </div>

        {/* Form */}
        <div className="auth-form">
          <div className="auth-field">
            <label className="auth-label">Email</label>
            <input
              className="auth-input"
              type="email"
              placeholder="you@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              onKeyDown={handleKeyDown}
              autoComplete="email"
            />
          </div>

          <PasswordInput
            label="Password"
            value={password}
            onChange={setPassword}
            onKeyDown={handleKeyDown}
            autoComplete={tab === "signup" ? "new-password" : "current-password"}
          />

          {tab === "signup" && strength && (
            <div className="auth-strength">
              <div className={`auth-strength-bar auth-strength-bar--${strength}`} />
              <span className="auth-strength-label">{strength.charAt(0).toUpperCase() + strength.slice(1)} password</span>
            </div>
          )}

          {tab === "signup" && (
            <PasswordInput
              label="Confirm Password"
              value={confirmPassword}
              onChange={setConfirmPassword}
              onKeyDown={handleKeyDown}
              autoComplete="new-password"
            />
          )}

          {error && <div className="auth-error">{error}</div>}

          {tab === "signup" ? (
            <>
              <button className="auth-submit-btn" onClick={handleSignUp} disabled={loading}>
                {loading ? <><Spinner /> Creating account…</> : "Create Account"}
              </button>
              <p className="auth-disclaimer">
                By creating an account, you agree to our privacy policy.
                Hound is free — no credit card required, ever.
              </p>
            </>
          ) : (
            <>
              <button className="auth-submit-btn" onClick={handleSignIn} disabled={loading}>
                {loading ? <><Spinner /> Signing in…</> : "Sign In"}
              </button>
              <div className="auth-forgot-row">
                <button className="auth-forgot" onClick={handleForgotPassword}>
                  Forgot password?
                </button>
              </div>
            </>
          )}
        </div>

        <button className="auth-skip" onClick={onComplete}>
          Continue without an account →
        </button>
      </div>
    </div>
  );
}

// ── "Everything Is Free" screen shown after sign-up ───────────────────────

const FREE_FEATURES = [
  "Full behavioral detection engine",
  "Real-time threat response",
  "Plain-English explanations",
  "Complete security history",
  "1 Mac included",
];

function FreeScreen({ onComplete }: { onComplete: () => void }) {
  return (
    <div className="auth-overlay">
      <div className="auth-free-card">
        <ShieldAuthIcon size={64} />
        <h2 className="auth-free-title">Protection that should exist for everyone.</h2>
        <p className="auth-free-subtitle">
          Behavioral endpoint security for your Mac. Free, forever.
        </p>

        <div className="auth-free-plan">
          <div className="auth-free-features">
            {FREE_FEATURES.map((f) => (
              <div key={f} className="auth-free-feature">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
                  <path d="M20 6L9 17l-5-5" stroke="#10b981" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
                {f}
              </div>
            ))}
          </div>
          <div className="auth-free-price">Free — always</div>
          <button className="auth-submit-btn" onClick={onComplete}>
            Get Protected →
          </button>
        </div>

        <p className="auth-free-coming-soon">Coming soon: Family &amp; Team plans</p>
      </div>
    </div>
  );
}
