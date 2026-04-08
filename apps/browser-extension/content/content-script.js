// Hound — Content Script
// Runs on every page (document_start) to detect social engineering and credential harvesting.

'use strict';

// ── ClickFix detection patterns (mirrored from service worker) ─────────────────

const CLICKFIX_PATTERNS = [
  /verify you are human/i,
  /i am not a robot/i,
  /press.*windows.*r/i,
  /open.*run.*dialog/i,
  /ctrl\s*\+\s*v/i,
  /paste.*terminal/i,
  /paste.*command/i,
  /paste.*powershell/i,
  /cloudflare.*verification/i,
  /verifying.*browser/i,
  /curl.*\|.*bash/i,
  /curl.*\|.*sh/i,
  /wget.*\|.*bash/i,
  /base64.*decode/i,
];

// ── Credential harvesting signals ─────────────────────────────────────────────

function hasCredentialHarvestingSignals() {
  const signals = [];

  // Password field present
  const passwordFields = document.querySelectorAll('input[type="password"]');
  if (passwordFields.length > 0) signals.push('password_field');

  // Page text signals
  const bodyText = document.body?.innerText || '';
  if (/enter.*password.*below/i.test(bodyText)) signals.push('password_request');
  if (/your account.*suspended/i.test(bodyText)) signals.push('account_suspended_lure');
  if (/confirm.*identity.*immediately/i.test(bodyText)) signals.push('urgency_language');
  if (/unusual.*activity.*detected/i.test(bodyText)) signals.push('unusual_activity_lure');
  if (/verify.*credit.*card/i.test(bodyText)) signals.push('credit_card_request');
  if (/social.*security.*number/i.test(bodyText)) signals.push('ssn_request');

  return signals;
}

// ── ClickFix page check ────────────────────────────────────────────────────────

function checkForClickFix() {
  const bodyText = document.body?.innerText || '';
  const matched = CLICKFIX_PATTERNS.filter((p) => p.test(bodyText));
  if (matched.length > 0) {
    // Notify the service worker
    chrome.runtime.sendMessage({
      type: 'CLICKFIX_DETECTED',
      url: window.location.href,
      patterns: matched.map((p) => p.source),
    });
    return true;
  }
  return false;
}

// ── Inline warning banner injection ───────────────────────────────────────────

function injectClickFixBanner(patterns) {
  if (document.getElementById('hound-banner')) return; // already injected

  const banner = document.createElement('div');
  banner.id = 'hound-banner';
  banner.setAttribute('style', [
    'position: fixed',
    'top: 0',
    'left: 0',
    'right: 0',
    'z-index: 2147483647',
    'background: #1a0505',
    'border-bottom: 2px solid #ff3b3b',
    'color: #ffffff',
    'font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    'font-size: 14px',
    'padding: 12px 20px',
    'display: flex',
    'align-items: center',
    'gap: 12px',
    'box-shadow: 0 2px 20px rgba(255,59,59,0.4)',
  ].join('; '));

  const icon = document.createElement('span');
  icon.setAttribute('style', 'font-size: 20px; flex-shrink: 0;');
  icon.textContent = '⚠️';

  const text = document.createElement('span');
  text.setAttribute('style', 'flex: 1;');
  text.innerHTML = '<strong>Hound: ClickFix Attack Detected</strong> — This page is attempting a social engineering attack. Do not copy or run any commands.';

  const closeBtn = document.createElement('button');
  closeBtn.setAttribute('style', [
    'background: rgba(255,255,255,0.1)',
    'border: 1px solid rgba(255,255,255,0.2)',
    'color: #fff',
    'border-radius: 4px',
    'padding: 4px 10px',
    'cursor: pointer',
    'font-size: 12px',
    'flex-shrink: 0',
  ].join('; '));
  closeBtn.textContent = 'Dismiss';
  closeBtn.addEventListener('click', () => banner.remove());

  banner.appendChild(icon);
  banner.appendChild(text);
  banner.appendChild(closeBtn);
  document.documentElement.insertBefore(banner, document.documentElement.firstChild);
}

// ── Phishing credential harvesting banner ──────────────────────────────────────

function injectPhishingBanner(signals) {
  if (document.getElementById('hound-banner')) return;

  const banner = document.createElement('div');
  banner.id = 'hound-banner';
  banner.setAttribute('style', [
    'position: fixed',
    'top: 0',
    'left: 0',
    'right: 0',
    'z-index: 2147483647',
    'background: #1a0d00',
    'border-bottom: 2px solid #ff8c00',
    'color: #ffffff',
    'font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    'font-size: 14px',
    'padding: 12px 20px',
    'display: flex',
    'align-items: center',
    'gap: 12px',
    'box-shadow: 0 2px 20px rgba(255,140,0,0.3)',
  ].join('; '));

  const icon = document.createElement('span');
  icon.setAttribute('style', 'font-size: 20px; flex-shrink: 0;');
  icon.textContent = '🎣';

  const text = document.createElement('span');
  text.setAttribute('style', 'flex: 1;');
  text.innerHTML = '<strong>Hound: Possible Phishing Page</strong> — Suspicious signals detected. Be cautious entering credentials here.';

  const closeBtn = document.createElement('button');
  closeBtn.setAttribute('style', [
    'background: rgba(255,255,255,0.1)',
    'border: 1px solid rgba(255,255,255,0.2)',
    'color: #fff',
    'border-radius: 4px',
    'padding: 4px 10px',
    'cursor: pointer',
    'font-size: 12px',
    'flex-shrink: 0',
  ].join('; '));
  closeBtn.textContent = 'Dismiss';
  closeBtn.addEventListener('click', () => banner.remove());

  banner.appendChild(icon);
  banner.appendChild(text);
  banner.appendChild(closeBtn);
  document.documentElement.insertBefore(banner, document.documentElement.firstChild);
}

// ── Main analysis (runs after DOM is ready) ───────────────────────────────────

function runAnalysis() {
  // Skip extension pages and non-http pages
  if (!window.location.href.startsWith('http')) return;

  // 1. ClickFix check
  const clickfixDetected = checkForClickFix();
  if (clickfixDetected) {
    injectClickFixBanner([]);
    return; // Don't pile on with phishing banner too
  }

  // 2. Phishing / credential harvesting check
  const phishingSignals = hasCredentialHarvestingSignals();
  // Need 2+ signals to show banner (single password field is normal)
  if (phishingSignals.length >= 2) {
    chrome.runtime.sendMessage({
      type: 'PHISHING_DETECTED',
      url: window.location.href,
      signals: phishingSignals,
    });
    injectPhishingBanner(phishingSignals);
  }
}

// ── Run timing ────────────────────────────────────────────────────────────────

// Run on DOMContentLoaded for most pages
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', runAnalysis);
} else {
  // Already loaded (document_start can race)
  runAnalysis();
}

// Also run after a short delay for SPAs that inject content late
setTimeout(runAnalysis, 1500);
