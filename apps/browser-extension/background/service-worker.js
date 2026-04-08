// Hound — Background Service Worker
// Intercepts navigations, runs threat detection, manages statistics.

'use strict';

// ── Bypass set (in-memory, session-only) ─────────────────────────────────────
// URLs the user explicitly chose to visit despite a warning.
const bypassedUrls = new Set();

// ── Storage helpers ───────────────────────────────────────────────────────────

async function getSettings() {
  const { settings } = await chrome.storage.local.get('settings');
  return Object.assign(
    {
      gsb_api_key: '',
      clickfix_detection: true,
      phishing_heuristics: true,
      show_notifications: true,
      share_anonymous_data: false,
    },
    settings || {}
  );
}

async function saveSettings(patch) {
  const current = await getSettings();
  await chrome.storage.local.set({ settings: { ...current, ...patch } });
}

async function getStats() {
  const { stats } = await chrome.storage.local.get('stats');
  const today = new Date().toDateString();
  const s = Object.assign(
    {
      sites_checked_today: 0,
      threats_blocked_today: 0,
      phishing_blocked_today: 0,
      last_reset: today,
      all_time_blocked: 0,
    },
    stats || {}
  );
  // Midnight rollover
  if (s.last_reset !== today) {
    s.sites_checked_today = 0;
    s.threats_blocked_today = 0;
    s.phishing_blocked_today = 0;
    s.last_reset = today;
    await chrome.storage.local.set({ stats: s });
  }
  return s;
}

async function incrementStat(key, amount = 1) {
  const s = await getStats();
  s[key] = (s[key] || 0) + amount;
  if (key === 'threats_blocked_today') {
    s.all_time_blocked = (s.all_time_blocked || 0) + amount;
  }
  await chrome.storage.local.set({ stats: s });
}

async function addRecentBlock(url, threatType, source) {
  const { recent_blocks: blocks = [] } = await chrome.storage.local.get('recent_blocks');
  let displayUrl;
  try { displayUrl = new URL(url).hostname; } catch { displayUrl = url.slice(0, 50); }
  blocks.unshift({ url, display_url: displayUrl, threat_type: threatType, timestamp: Date.now(), source });
  if (blocks.length > 50) blocks.length = 50;
  await chrome.storage.local.set({ recent_blocks: blocks });
}

// ── Google Safe Browsing ──────────────────────────────────────────────────────

async function checkGoogleSafeBrowsing(url) {
  const settings = await getSettings();
  const apiKey = settings.gsb_api_key;
  if (!apiKey) return { safe: true, source: 'gsb_skipped' };

  try {
    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: 'hound', clientVersion: '0.1.0' },
          threatInfo: {
            threatTypes: [
              'MALWARE',
              'SOCIAL_ENGINEERING',
              'UNWANTED_SOFTWARE',
              'POTENTIALLY_HARMFUL_APPLICATION',
            ],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url }],
          },
        }),
      }
    );
    if (!response.ok) return { safe: true, source: 'gsb_error' };
    const data = await response.json();
    const match = data.matches?.[0];
    return {
      safe: !match,
      threatType: match?.threatType || null,
      source: 'google_safe_browsing',
    };
  } catch {
    return { safe: true, source: 'gsb_error' };
  }
}

// ── ClickFix detection ────────────────────────────────────────────────────────

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

function detectClickFix(pageContent) {
  const matched = CLICKFIX_PATTERNS.filter((p) => p.test(pageContent)).map((p) => p.source);
  return { detected: matched.length > 0, patterns: matched };
}

// ── Phishing heuristics ───────────────────────────────────────────────────────

const DOMAIN_SQUAT_PATTERNS = [
  /app1e\./i, /micosoft\./i, /paypa1\./i, /g00gle\./i,
  /faceb00k\./i, /arnazon\./i, /netf1ix\./i,
];

function detectPhishingHeuristics(url, pageContent = '') {
  const signals = [];

  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname;
    const path = parsed.pathname;

    if (DOMAIN_SQUAT_PATTERNS.some((p) => p.test(hostname))) signals.push('domain_squatting');
    if (path.includes('login') && path.includes('verify')) signals.push('login_verify_combo');
    if (hostname.split('.').length > 5) signals.push('excessive_subdomains');
    if (/\d{10,}/.test(hostname)) signals.push('long_number_in_hostname');
  } catch { /* invalid URL */ }

  if (/enter.*password.*below/i.test(pageContent)) signals.push('password_request');
  if (/your account.*suspended/i.test(pageContent)) signals.push('account_suspended_lure');
  if (/confirm.*identity.*immediately/i.test(pageContent)) signals.push('urgency_language');
  if (/unusual.*activity.*detected/i.test(pageContent)) signals.push('unusual_activity_lure');

  return {
    isPhishing: signals.length >= 2,
    signals,
    confidence: Math.min(signals.length / 4, 1.0),
  };
}

// ── Threat type display mapping ───────────────────────────────────────────────

function toDisplayType(threatType) {
  switch (threatType) {
    case 'SOCIAL_ENGINEERING': return 'PHISHING';
    case 'MALWARE':            return 'MALWARE';
    case 'UNWANTED_SOFTWARE':
    case 'POTENTIALLY_HARMFUL_APPLICATION': return 'SUSPICIOUS SITE';
    case 'CLICKFIX':           return 'CLICKFIX DETECTED';
    case 'PHISHING':           return 'PHISHING';
    default:                   return threatType || 'SUSPICIOUS SITE';
  }
}

// ── Main URL check (URL-only, runs before page loads) ────────────────────────

async function checkUrlOnly(url) {
  const settings = await getSettings();

  // 1. Google Safe Browsing
  const gsb = await checkGoogleSafeBrowsing(url);
  if (!gsb.safe) {
    return {
      safe: false,
      threatType: gsb.threatType,
      displayType: toDisplayType(gsb.threatType),
      source: 'Google Safe Browsing',
      detail: gsb.threatType,
    };
  }

  // 2. URL-only phishing heuristics (no page content yet)
  if (settings.phishing_heuristics) {
    const ph = detectPhishingHeuristics(url);
    if (ph.isPhishing) {
      return {
        safe: false,
        threatType: 'PHISHING',
        displayType: 'PHISHING',
        source: 'Behavioral Analysis',
        detail: ph.signals.join(', '),
      };
    }
  }

  return { safe: true };
}

// ── Navigation interception ───────────────────────────────────────────────────

chrome.webNavigation.onBeforeNavigate.addListener(
  async (details) => {
    // Main frame only, HTTP/HTTPS only, not our own extension pages
    if (details.frameId !== 0) return;
    if (!details.url.startsWith('http')) return;
    if (details.url.includes(chrome.runtime.id)) return;

    // User explicitly bypassed this URL
    if (bypassedUrls.has(details.url)) return;

    await incrementStat('sites_checked_today');

    const result = await checkUrlOnly(details.url);
    if (!result.safe) {
      await incrementStat('threats_blocked_today');
      await addRecentBlock(details.url, result.displayType, result.source);

      // Persist blocked URL data for the warning page to read
      await chrome.storage.session.set({
        [`blocked_${details.tabId}`]: {
          url: details.url,
          threat: result,
          timestamp: Date.now(),
        },
      });

      const settings = await getSettings();
      if (settings.show_notifications) {
        let hostname;
        try { hostname = new URL(details.url).hostname; } catch { hostname = details.url; }
        chrome.notifications.create(`block_${details.tabId}_${Date.now()}`, {
          type: 'basic',
          iconUrl: 'icons/icon-48.png',
          title: 'Hound blocked a threat',
          message: `Blocked: ${hostname} (${result.displayType})`,
          silent: false,
        });
      }

      // Redirect to warning page
      chrome.tabs.update(details.tabId, {
        url: chrome.runtime.getURL(`warning/warning.html?tabId=${details.tabId}`),
      });
    }
  },
  { url: [{ schemes: ['http', 'https'] }] }
);

// ── Messages from content script and popup ────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.type) {

    case 'CLICKFIX_DETECTED': {
      (async () => {
        const settings = await getSettings();
        if (!settings.clickfix_detection) { sendResponse({ ok: true }); return; }

        await incrementStat('threats_blocked_today');
        await addRecentBlock(message.url, 'CLICKFIX DETECTED', 'Behavioral Analysis');

        if (settings.show_notifications) {
          let hostname;
          try { hostname = new URL(message.url).hostname; } catch { hostname = message.url; }
          chrome.notifications.create(`clickfix_${Date.now()}`, {
            type: 'basic',
            iconUrl: 'icons/icon-48.png',
            title: 'Hound: ClickFix Detected',
            message: `Social engineering attack on ${hostname}`,
          });
        }
        sendResponse({ ok: true });
      })();
      return true; // keep channel open
    }

    case 'PHISHING_DETECTED': {
      (async () => {
        const settings = await getSettings();
        if (!settings.phishing_heuristics) { sendResponse({ ok: true }); return; }
        await incrementStat('threats_blocked_today');
        await addRecentBlock(message.url, 'PHISHING', 'Behavioral Analysis');
        sendResponse({ ok: true });
      })();
      return true;
    }

    case 'GET_PAGE_SAFETY': {
      (async () => {
        const result = await checkUrlOnly(message.url);
        sendResponse(result);
      })();
      return true;
    }

    case 'BYPASS_URL': {
      bypassedUrls.add(message.url);
      // Auto-remove after 30s (single navigation window)
      setTimeout(() => bypassedUrls.delete(message.url), 30_000);
      sendResponse({ ok: true });
      return true;
    }

    case 'GET_STATS': {
      (async () => {
        const stats = await getStats();
        const { recent_blocks = [] } = await chrome.storage.local.get('recent_blocks');
        const { desktop_agent_connected = false } = await chrome.storage.local.get('desktop_agent_connected');
        sendResponse({ stats, recent_blocks, desktop_agent_connected });
      })();
      return true;
    }

    case 'GET_SETTINGS': {
      getSettings().then((s) => sendResponse(s));
      return true;
    }

    case 'SAVE_SETTINGS': {
      saveSettings(message.patch).then(() => sendResponse({ ok: true }));
      return true;
    }
  }
});

// ── Daily reset alarm ─────────────────────────────────────────────────────────

chrome.alarms.create('daily_reset', { periodInMinutes: 1440 });

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== 'daily_reset') return;
  const s = await getStats();
  s.sites_checked_today = 0;
  s.threats_blocked_today = 0;
  s.phishing_blocked_today = 0;
  s.last_reset = new Date().toDateString();
  await chrome.storage.local.set({ stats: s });
});

// ── Desktop app connectivity check (future-ready) ────────────────────────────
// When the desktop Hound app ships an IPC endpoint on localhost:52821,
// this check will flip desktop_agent_connected to true automatically.

async function checkDesktopAgentConnected() {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 1000);
    const resp = await fetch('http://localhost:52821/api/ping', { signal: ctrl.signal });
    clearTimeout(timer);
    return resp.ok;
  } catch {
    return false;
  }
}

// Run connectivity check on startup and every 60s
async function refreshDesktopStatus() {
  const connected = await checkDesktopAgentConnected();
  await chrome.storage.local.set({ desktop_agent_connected: connected });
}

refreshDesktopStatus();
setInterval(refreshDesktopStatus, 60_000);
