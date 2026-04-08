#!/usr/bin/env node
// Hound Browser Extension — URL Detection Tests
// Tests the heuristic detection functions directly (no Chrome APIs needed).
// Usage: node test/test-urls.js

'use strict';

// ── Inline copies of detection functions (from service-worker.js) ─────────────

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

// ── Test runner ───────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓  ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗  ${name}`);
    console.error(`     ${err.message}`);
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

// ── ClickFix detection tests ──────────────────────────────────────────────────

console.log('\nClickFix Detection:');

test('detects "verify you are human" text', () => {
  const r = detectClickFix('Please verify you are human to continue');
  assert(r.detected, 'should detect');
});

test('detects curl pipe bash pattern', () => {
  const r = detectClickFix('Run this to verify: curl https://example.com | bash');
  assert(r.detected, 'should detect');
});

test('detects ctrl+v paste instruction', () => {
  const r = detectClickFix('Press Ctrl+V to paste the verification code');
  assert(r.detected, 'should detect');
});

test('detects paste into PowerShell', () => {
  const r = detectClickFix('Open PowerShell and paste the following command');
  assert(r.detected, 'should detect');
});

test('detects base64 decode instruction', () => {
  const r = detectClickFix('Open terminal and run: echo "abc" | base64 --decode | bash');
  assert(r.detected, 'should detect');
});

test('does not flag normal page content', () => {
  const r = detectClickFix('Welcome to our store. Browse our products and add items to cart.');
  assert(!r.detected, 'should not detect');
});

test('does not flag news article', () => {
  const r = detectClickFix('The government announced new security measures. Citizens are asked to verify identity at polling stations.');
  assert(!r.detected, 'should not detect');
});

test('does not flag developer documentation', () => {
  const r = detectClickFix('Install Node.js by running: brew install node. Then run npm install in your project directory.');
  assert(!r.detected, 'should not detect: normal install instructions');
});

// ── Phishing heuristics tests ─────────────────────────────────────────────────

console.log('\nPhishing Heuristics:');

test('detects domain squatting (app1e)', () => {
  const r = detectPhishingHeuristics('https://app1e.com/login');
  assert(r.signals.includes('domain_squatting'), 'should flag domain_squatting');
});

test('detects login+verify URL combo', () => {
  const r = detectPhishingHeuristics('https://accounts.example.com/login/verify/identity');
  assert(r.signals.includes('login_verify_combo'), 'should flag login_verify_combo');
});

test('detects excessive subdomains', () => {
  const r = detectPhishingHeuristics('https://a.b.c.d.e.f.example.com/page');
  assert(r.signals.includes('excessive_subdomains'), 'should flag excessive_subdomains');
});

test('detects long number in hostname', () => {
  const r = detectPhishingHeuristics('https://12345678901234.example.com/');
  assert(r.signals.includes('long_number_in_hostname'), 'should flag long_number_in_hostname');
});

test('isPhishing requires 2+ signals', () => {
  const r1 = detectPhishingHeuristics('https://app1e.com/page');
  assertEqual(r1.isPhishing, false, 'single signal should not flag');

  const r2 = detectPhishingHeuristics(
    'https://app1e.com/login/verify',
    'enter your password below'
  );
  assert(r2.isPhishing, 'multiple signals should flag');
});

test('does not flag google.com', () => {
  const r = detectPhishingHeuristics('https://www.google.com/search?q=hello');
  assert(!r.isPhishing, 'google.com should be clean');
});

test('does not flag github.com login', () => {
  const r = detectPhishingHeuristics('https://github.com/login');
  assert(!r.isPhishing, 'github login should be clean');
});

test('does not flag amazon.com product page', () => {
  const r = detectPhishingHeuristics('https://www.amazon.com/dp/B08N5WRWNW');
  assert(!r.isPhishing, 'amazon product should be clean');
});

test('does not flag apple.com (not app1e)', () => {
  const r = detectPhishingHeuristics('https://www.apple.com/iphone');
  assert(!r.isPhishing, 'apple.com should be clean');
});

test('account suspended + urgency language triggers phishing', () => {
  const content = 'Your account has been suspended. Confirm your identity immediately to restore access.';
  const r = detectPhishingHeuristics('https://secure-account-restore.xyz/', content);
  assert(r.isPhishing, 'multiple content signals should flag');
});

// ── Results ───────────────────────────────────────────────────────────────────

console.log(`\n${'─'.repeat(40)}`);
console.log(`Results: ${passed} passed, ${failed} failed`);

if (failed > 0) {
  console.log('\nSome tests failed. Fix detection logic before shipping.');
  process.exit(1);
} else {
  console.log('\nAll tests passed ✓');
}
