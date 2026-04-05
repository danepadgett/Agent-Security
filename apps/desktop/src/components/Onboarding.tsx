import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";

// ── SVG Icons ──────────────────────────────────────────────────────────────

function ShieldLargeIcon() {
  return (
    <svg width="80" height="80" viewBox="0 0 24 24" fill="none">
      <path
        d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z"
        fill="rgba(16, 185, 129, 0.15)"
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

function EyeStepIcon() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
      <path
        d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <circle cx="12" cy="12" r="3" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  );
}

function ShieldStepIcon() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
      <path
        d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <path
        d="M9 12l2 2 4-4"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}


function DocumentStepIcon() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
      <path
        d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <polyline points="14 2 14 8 20 8" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
      <line x1="9" y1="13" x2="15" y2="13" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <line x1="9" y1="17" x2="12" y2="17" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
      <circle cx="12" cy="12" r="10" stroke="#10b981" strokeWidth="1.5" />
      <path d="M9 12l2 2 4-4" stroke="#10b981" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function XIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
      <circle cx="12" cy="12" r="10" stroke="#ef4444" strokeWidth="1.5" />
      <line x1="15" y1="9" x2="9" y2="15" stroke="#ef4444" strokeWidth="1.5" strokeLinecap="round" />
      <line x1="9" y1="9" x2="15" y2="15" stroke="#ef4444" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  );
}

function FolderLockIcon() {
  return (
    <svg width="26" height="26" viewBox="0 0 24 24" fill="none">
      <path
        d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <rect x="9" y="13" width="6" height="5" rx="1" stroke="currentColor" strokeWidth="1.5" />
      <path d="M10 13v-1a2 2 0 114 0v1" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  );
}

function PersonCircleIcon() {
  return (
    <svg width="26" height="26" viewBox="0 0 24 24" fill="none">
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="1.5" />
      <circle cx="12" cy="10" r="3" stroke="currentColor" strokeWidth="1.5" />
      <path
        d="M6 20.662C6.868 18.528 9.184 17 12 17s5.132 1.528 6 3.662"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
    </svg>
  );
}

function SmallCheckIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
      <path
        d="M20 6L9 17l-5-5"
        stroke="#10b981"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

// ── Types ──────────────────────────────────────────────────────────────────

type PermissionStatus = { full_disk_access: boolean; accessibility: boolean };

type Props = {
  onComplete: () => void;
};

// ── Main Component ─────────────────────────────────────────────────────────

export function Onboarding({ onComplete }: Props) {
  const [screen, setScreen] = useState(1);
  const [direction, setDirection] = useState<"forward" | "backward">("forward");
  const [permStatus, setPermStatus] = useState<PermissionStatus>({
    full_disk_access: false,
    accessibility: false,
  });
  const [permCheckFailed, setPermCheckFailed] = useState(false);
  const [manualOverrideVisible, setManualOverrideVisible] = useState(false);
  const [readyChecks, setReadyChecks] = useState(0);
  const [telemetryToggle, setTelemetryToggle] = useState(false);
  const [telemetryExpanded, setTelemetryExpanded] = useState(false);

  function goForward(next: number) {
    setDirection("forward");
    setScreen(next);
  }

  function goBack(prev: number) {
    setDirection("backward");
    setScreen(prev);
  }

  // Check and poll permissions on screen 4 (index 3, 1-based screen 4)
  useEffect(() => {
    if (screen !== 4) return;

    // Reset state each time we enter the screen
    setPermCheckFailed(false);
    setManualOverrideVisible(false);

    const checkCurrentPermissions = async () => {
      try {
        const status = await invoke<PermissionStatus>("check_permissions");
        setPermStatus(status);
        setPermCheckFailed(false);
      } catch (e) {
        console.error("Permission check failed:", e);
        setPermCheckFailed(true);
      }
    };

    // Check immediately on load — so pre-granted permissions appear right away
    checkCurrentPermissions();

    // Poll every 2 seconds for changes after the user grants in System Settings
    const pollId = setInterval(checkCurrentPermissions, 2000);

    // After 5 seconds, show manual override Continue regardless of detection
    const overrideTimer = setTimeout(() => setManualOverrideVisible(true), 5000);

    return () => {
      clearInterval(pollId);
      clearTimeout(overrideTimer);
    };
  }, [screen]);

  // Animate health checks on screen 5
  useEffect(() => {
    if (screen !== 5) return;
    setReadyChecks(0);
    for (let i = 0; i < 5; i++) {
      setTimeout(() => setReadyChecks((p) => p + 1), (i + 1) * 400);
    }
  }, [screen]);

  async function handleComplete() {
    await invoke("complete_onboarding").catch(() => {});
    onComplete();
  }

  return (
    <div className="onboarding-overlay">
      {/* Progress dots */}
      <div className="onboarding-dots">
        {[1, 2, 3, 4, 5].map((i) => (
          <div
            key={i}
            className={[
              "onboarding-dot",
              screen === i ? "onboarding-dot--active" : "",
              screen > i ? "onboarding-dot--done" : "",
            ]
              .filter(Boolean)
              .join(" ")}
          />
        ))}
      </div>

      {/* Screen — key forces remount on each change, triggering the enter animation */}
      <div
        key={`${screen}-${direction}`}
        className={`onboarding-screen onboarding-screen--${direction}`}
      >
        {screen === 1 && <Screen1 onNext={() => goForward(2)} />}
        {screen === 2 && (
          <Screen2 onNext={() => goForward(3)} onBack={() => goBack(1)} />
        )}
        {screen === 3 && (
          <Screen3
            onNext={() => goForward(4)}
            onBack={() => goBack(2)}
            telemetryToggle={telemetryToggle}
            onTelemetryToggle={setTelemetryToggle}
            telemetryExpanded={telemetryExpanded}
            onTelemetryExpand={setTelemetryExpanded}
          />
        )}
        {screen === 4 && (
          <Screen4
            permStatus={permStatus}
            permCheckFailed={permCheckFailed}
            manualOverrideVisible={manualOverrideVisible}
            onNext={() => goForward(5)}
            onBack={() => goBack(3)}
          />
        )}
        {screen === 5 && (
          <Screen5 readyChecks={readyChecks} onComplete={handleComplete} />
        )}
      </div>
    </div>
  );
}

// ── Screen 1 — Welcome ─────────────────────────────────────────────────────

function Screen1({ onNext }: { onNext: () => void }) {
  return (
    <div className="onboarding-content onboarding-content--centered">
      <div className="onboarding-icon-wrap">
        <ShieldLargeIcon />
      </div>
      <h1 className="onboarding-headline">Hound</h1>
      <p className="onboarding-subheadline">
        Behavioral endpoint protection for your Mac. Free, forever.
      </p>
      <div className="onboarding-pills">
        <span className="onboarding-pill">🔒 Local only</span>
        <span className="onboarding-pill">👁 Open source</span>
        <span className="onboarding-pill">💸 Free forever</span>
      </div>
      <button className="onboarding-btn onboarding-btn--primary" onClick={onNext}>
        Get Started →
      </button>
    </div>
  );
}

// ── Screen 2 — How It Works ────────────────────────────────────────────────

function Screen2({ onNext, onBack }: { onNext: () => void; onBack: () => void }) {
  return (
    <div className="onboarding-content">
      <h2 className="onboarding-section-title">How It Works</h2>
      <div className="onboarding-cards">
        <div className="onboarding-card">
          <div className="onboarding-card-icon onboarding-card-icon--green">
            <EyeStepIcon />
          </div>
          <div className="onboarding-card-body">
            <div className="onboarding-card-title">Watches behavior, not files</div>
            <div className="onboarding-card-desc">
              Detects attack patterns that signature-based tools miss
            </div>
          </div>
        </div>
        <div className="onboarding-card">
          <div className="onboarding-card-icon onboarding-card-icon--orange">
            <ShieldStepIcon />
          </div>
          <div className="onboarding-card-body">
            <div className="onboarding-card-title">Stops threats in real time</div>
            <div className="onboarding-card-desc">
              Kills malicious processes and quarantines files before damage occurs
            </div>
          </div>
        </div>
        <div className="onboarding-card">
          <div className="onboarding-card-icon onboarding-card-icon--blue">
            <DocumentStepIcon />
          </div>
          <div className="onboarding-card-body">
            <div className="onboarding-card-title">Explains everything</div>
            <div className="onboarding-card-desc">
              Every incident gets a plain-English explanation so you always understand what happened
            </div>
          </div>
        </div>
      </div>
      <p className="onboarding-how-desc">
        Unlike traditional antivirus, Hound catches attacks it has never seen before.
      </p>
      <div className="onboarding-nav">
        <button className="onboarding-btn onboarding-btn--ghost" onClick={onBack}>
          ← Back
        </button>
        <button className="onboarding-btn onboarding-btn--primary" onClick={onNext}>
          Makes sense →
        </button>
      </div>
    </div>
  );
}

// ── Screen 3 — Privacy ─────────────────────────────────────────────────────

type Screen3Props = {
  onNext: () => void;
  onBack: () => void;
  telemetryToggle: boolean;
  onTelemetryToggle: (v: boolean) => void;
  telemetryExpanded: boolean;
  onTelemetryExpand: (v: boolean) => void;
};

function Screen3({
  onNext,
  onBack,
  telemetryToggle,
  onTelemetryToggle,
  telemetryExpanded,
  onTelemetryExpand,
}: Screen3Props) {
  const doItems = [
    "Watch for suspicious behavior",
    "Block threats on your device",
    "Keep a history on your Mac",
    "Explain what happened in plain English",
  ];
  const dontItems = [
    "Read your files",
    "Send data to the cloud",
    "Know who you are",
    "Require an account",
  ];

  return (
    <div className="onboarding-content">
      <h2 className="onboarding-section-title">Your Privacy</h2>
      <div className="onboarding-privacy-cols">
        <div className="onboarding-privacy-col">
          <div className="onboarding-privacy-col-title onboarding-privacy-col-title--green">
            We DO
          </div>
          {doItems.map((item) => (
            <div key={item} className="onboarding-privacy-row">
              <CheckIcon />
              <span>{item}</span>
            </div>
          ))}
        </div>
        <div className="onboarding-privacy-col">
          <div className="onboarding-privacy-col-title onboarding-privacy-col-title--red">
            We DON'T
          </div>
          {dontItems.map((item) => (
            <div key={item} className="onboarding-privacy-row">
              <XIcon />
              <span>{item}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="onboarding-telemetry">
        <div className="onboarding-telemetry-row">
          <div className="onboarding-telemetry-text">
            <span>Help improve Hound — share anonymous attack patterns</span>
            <button
              className="onboarding-telemetry-expand"
              onClick={() => onTelemetryExpand(!telemetryExpanded)}
            >
              What does this mean?
            </button>
            {telemetryExpanded && (
              <span className="onboarding-telemetry-detail">
                When enabled, we share only that an attack pattern was detected — never file names,
                paths, or personal data. This helps improve detection for everyone.
              </span>
            )}
          </div>
          <button
            className={`onboarding-toggle ${telemetryToggle ? "onboarding-toggle--on" : ""}`}
            onClick={() => onTelemetryToggle(!telemetryToggle)}
            aria-pressed={telemetryToggle}
          >
            <span className="onboarding-toggle-thumb" />
          </button>
        </div>
      </div>

      <div className="onboarding-nav">
        <button className="onboarding-btn onboarding-btn--ghost" onClick={onBack}>
          ← Back
        </button>
        <button className="onboarding-btn onboarding-btn--primary" onClick={onNext}>
          Got it →
        </button>
      </div>
    </div>
  );
}

// ── Screen 4 — Permissions ─────────────────────────────────────────────────

type Screen4Props = {
  permStatus: PermissionStatus;
  permCheckFailed: boolean;
  manualOverrideVisible: boolean;
  onNext: () => void;
  onBack: () => void;
};

function Screen4({ permStatus, permCheckFailed, manualOverrideVisible, onNext, onBack }: Screen4Props) {
  function openFullDiskAccess() {
    openUrl(
      "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
    ).catch(() => {});
  }

  function openAccessibility() {
    openUrl(
      "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility"
    ).catch(() => {});
  }

  // Continue is enabled if FDA is detected OR the manual override timer has fired
  const canContinue = permStatus.full_disk_access || manualOverrideVisible;

  return (
    <div className="onboarding-content">
      <h2 className="onboarding-section-title">Grant Permissions</h2>
      <p className="onboarding-section-subtitle">
        Hound needs access to protect you effectively.
      </p>

      {/* Full Disk Access */}
      <div
        className={`onboarding-perm-card ${
          permStatus.full_disk_access ? "onboarding-perm-card--granted" : ""
        }`}
      >
        <div className="onboarding-perm-icon">
          <FolderLockIcon />
        </div>
        <div className="onboarding-perm-body">
          <div className="onboarding-perm-title">Full Disk Access</div>
          <div className="onboarding-perm-desc">
            Lets Hound watch your Downloads folder and other common attack targets.
            Without this, protection is limited.
          </div>
        </div>
        <div className="onboarding-perm-action">
          {permStatus.full_disk_access ? (
            // Bug 3: granted state shows immediately with green button style, disabled
            <button
              className="onboarding-btn onboarding-btn--perm onboarding-btn--perm-granted"
              disabled
            >
              ✓ Full Disk Access Granted
            </button>
          ) : (
            <button
              className="onboarding-btn onboarding-btn--perm"
              onClick={openFullDiskAccess}
            >
              Grant Access →
            </button>
          )}
        </div>
      </div>

      {/* Bug 4 fallback: if permission detection fails, show a note */}
      {permCheckFailed && !permStatus.full_disk_access && (
        <div className="onboarding-perm-fallback">
          <span className="onboarding-perm-fallback-icon">ℹ</span>
          <span>
            Can't detect permission status automatically. If you've already granted Full
            Disk Access, click <strong>Continue</strong> below.
          </span>
        </div>
      )}

      {/* Accessibility (optional) */}
      <div
        className={`onboarding-perm-card ${
          permStatus.accessibility ? "onboarding-perm-card--granted" : ""
        }`}
      >
        <div className="onboarding-perm-icon">
          <PersonCircleIcon />
        </div>
        <div className="onboarding-perm-body">
          <div className="onboarding-perm-title">
            Accessibility{" "}
            <span className="onboarding-perm-optional">(Optional)</span>
          </div>
          <div className="onboarding-perm-desc">
            Enables detection of advanced attacks that try to control your Mac remotely.
            You're still protected without this.
          </div>
        </div>
        <div className="onboarding-perm-action">
          {permStatus.accessibility ? (
            <div className="onboarding-perm-granted">✓ Granted</div>
          ) : (
            <div className="onboarding-perm-action-group">
              <button
                className="onboarding-btn onboarding-btn--perm"
                onClick={openAccessibility}
              >
                Grant Access →
              </button>
              <button className="onboarding-btn onboarding-btn--link" onClick={onNext}>
                Skip for now
              </button>
            </div>
          )}
        </div>
      </div>

      <div className="onboarding-nav">
        <button className="onboarding-btn onboarding-btn--ghost" onClick={onBack}>
          ← Back
        </button>
        {/* Bug 2: enabled as soon as full_disk_access is true OR manual override fires */}
        <button
          className="onboarding-btn onboarding-btn--primary"
          onClick={onNext}
          disabled={!canContinue}
        >
          Continue →
        </button>
      </div>
    </div>
  );
}

// ── Screen 5 — Ready ───────────────────────────────────────────────────────

const READY_CHECKS = [
  "Agent running",
  "Watching Downloads, Desktop, Documents",
  "Monitoring startup items",
  "Network activity tracking enabled",
  "Full Disk Access confirmed",
];

function Screen5({
  readyChecks,
  onComplete,
}: {
  readyChecks: number;
  onComplete: () => void;
}) {
  const allDone = readyChecks >= READY_CHECKS.length;

  return (
    <div className="onboarding-content onboarding-content--centered">
      <h2 className="onboarding-section-title">
        {allDone ? "You're Protected" : "Running health check…"}
      </h2>

      <div className="onboarding-ready-list">
        {READY_CHECKS.map((check, i) => (
          <div
            key={check}
            className={`onboarding-ready-item ${
              i < readyChecks ? "onboarding-ready-item--visible" : ""
            }`}
          >
            <span className="onboarding-ready-check-icon">
              {i < readyChecks ? <SmallCheckIcon /> : null}
            </span>
            <span>{check}</span>
          </div>
        ))}
      </div>

      {allDone && (
        <div className="onboarding-ready-complete">
          <div className="onboarding-ready-checkmark">✓ Protected</div>
          <p className="onboarding-ready-subtext">
            Hound is running quietly in the background. You'll only hear
            from us if something suspicious happens.
          </p>
          <button className="onboarding-btn onboarding-btn--primary" onClick={onComplete}>
            Open Dashboard →
          </button>
        </div>
      )}
    </div>
  );
}
