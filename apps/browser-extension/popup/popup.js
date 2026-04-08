// Hound — Popup Script
'use strict';

// ── DOM refs ──────────────────────────────────────────────────────────────────

const mainView      = document.getElementById('mainView');
const settingsView  = document.getElementById('settingsView');
const settingsBtn   = document.getElementById('settingsBtn');
const backBtn       = document.getElementById('backBtn');

const statusCard    = document.getElementById('statusCard');
const shieldSvg     = document.getElementById('shieldSvg');
const statusLabel   = document.getElementById('statusLabel');
const statusSublabel = document.getElementById('statusSublabel');

const statChecked   = document.getElementById('statChecked');
const statBlocked   = document.getElementById('statBlocked');
const statAllTime   = document.getElementById('statAllTime');

const desktopDot    = document.getElementById('desktopDot');
const desktopLabel  = document.getElementById('desktopLabel');

const recentList    = document.getElementById('recentList');
const recentCount   = document.getElementById('recentCount');

// Settings
const toggleClickfix      = document.getElementById('toggleClickfix');
const togglePhishing      = document.getElementById('togglePhishing');
const toggleNotifications = document.getElementById('toggleNotifications');
const gsbApiKey           = document.getElementById('gsbApiKey');
const saveBtn             = document.getElementById('saveBtn');
const saveFeedback        = document.getElementById('saveFeedback');

// ── Navigation ────────────────────────────────────────────────────────────────

settingsBtn.addEventListener('click', () => {
  mainView.classList.add('hidden');
  settingsView.classList.remove('hidden');
  loadSettings();
});

backBtn.addEventListener('click', () => {
  settingsView.classList.add('hidden');
  mainView.classList.remove('hidden');
});

// ── Helpers ───────────────────────────────────────────────────────────────────

function timeAgo(ts) {
  const diff = Date.now() - ts;
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function threatBadgeClass(threatType) {
  if (!threatType) return '';
  if (threatType.includes('CLICKFIX')) return 'recent-badge--purple';
  if (threatType.includes('PHISHING') || threatType.includes('SOCIAL')) return 'recent-badge--orange';
  return ''; // default red
}

// ── Load stats and recent blocks ─────────────────────────────────────────────

function loadStats() {
  chrome.runtime.sendMessage({ type: 'GET_STATS' }, (response) => {
    if (!response) return;

    const { stats, recent_blocks, desktop_agent_connected } = response;

    // Stats
    statChecked.textContent = stats.sites_checked_today ?? 0;
    statBlocked.textContent = stats.threats_blocked_today ?? 0;
    statAllTime.textContent = stats.all_time_blocked ?? 0;

    // Status card
    const hasThreats = (stats.threats_blocked_today ?? 0) > 0;
    if (hasThreats) {
      statusCard.classList.add('status--threat');
      statusLabel.textContent = 'Threats Blocked';
      statusSublabel.textContent = `${stats.threats_blocked_today} blocked today`;
    } else {
      statusCard.classList.remove('status--threat');
      statusLabel.textContent = 'Protected';
      statusSublabel.textContent = 'No threats detected today';
    }

    // Desktop agent
    if (desktop_agent_connected) {
      desktopDot.classList.add('connected');
      desktopLabel.textContent = 'Desktop agent: connected';
    } else {
      desktopDot.classList.remove('connected');
      desktopLabel.textContent = 'Desktop agent: not running';
    }

    // Recent blocks
    if (!recent_blocks || recent_blocks.length === 0) {
      recentList.innerHTML = '<div class="empty-state">No threats blocked yet.<br/>Stay safe out there.</div>';
      recentCount.textContent = '0';
      return;
    }

    recentCount.textContent = recent_blocks.length;
    recentList.innerHTML = '';

    recent_blocks.slice(0, 10).forEach((block) => {
      const item = document.createElement('div');
      item.className = 'recent-item';

      const badge = document.createElement('span');
      badge.className = `recent-badge ${threatBadgeClass(block.threat_type)}`;
      badge.textContent = block.threat_type || 'THREAT';

      const url = document.createElement('span');
      url.className = 'recent-url';
      url.textContent = block.display_url || block.url;
      url.title = block.url;

      const time = document.createElement('span');
      time.className = 'recent-time';
      time.textContent = timeAgo(block.timestamp);

      item.appendChild(badge);
      item.appendChild(url);
      item.appendChild(time);
      recentList.appendChild(item);
    });
  });
}

// ── Load and save settings ────────────────────────────────────────────────────

let currentSettings = {};

function loadSettings() {
  chrome.runtime.sendMessage({ type: 'GET_SETTINGS' }, (settings) => {
    if (!settings) return;
    currentSettings = settings;

    setToggle(toggleClickfix, settings.clickfix_detection !== false);
    setToggle(togglePhishing, settings.phishing_heuristics !== false);
    setToggle(toggleNotifications, settings.show_notifications !== false);
    gsbApiKey.value = settings.gsb_api_key || '';
  });
}

function setToggle(el, on) {
  if (on) {
    el.classList.add('on');
  } else {
    el.classList.remove('on');
  }
  el.dataset.value = on ? '1' : '0';
}

function toggleValue(el) {
  const current = el.dataset.value === '1';
  setToggle(el, !current);
}

toggleClickfix.addEventListener('click', () => toggleValue(toggleClickfix));
togglePhishing.addEventListener('click', () => toggleValue(togglePhishing));
toggleNotifications.addEventListener('click', () => toggleValue(toggleNotifications));

saveBtn.addEventListener('click', () => {
  const patch = {
    clickfix_detection:   toggleClickfix.dataset.value === '1',
    phishing_heuristics:  togglePhishing.dataset.value === '1',
    show_notifications:   toggleNotifications.dataset.value === '1',
    gsb_api_key:          gsbApiKey.value.trim(),
  };

  chrome.runtime.sendMessage({ type: 'SAVE_SETTINGS', patch }, () => {
    saveFeedback.textContent = 'Saved ✓';
    setTimeout(() => { saveFeedback.textContent = ''; }, 2000);
  });
});

// ── Init ──────────────────────────────────────────────────────────────────────

loadStats();
