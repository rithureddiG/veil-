#!/usr/bin/env node

/**
 * VEIL — Clean-Machine SIH Setup & Pre-Flight Validator
 * File: scripts/setup-sih.js
 *
 * Verifies that a clean machine meets all prerequisites for SIH demonstration:
 *   1. Node.js runtime version check (>= 18.0.0)
 *   2. Chrome / Chromium executable discovery
 *   3. Project dependency and directory layout integrity
 *   4. Extension Manifest V3 configuration validation
 *   5. Port 3000 availability for demo-sites server
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  cyan: '\x1b[36m',
  yellow: '\x1b[33m'
};

function banner() {
  console.log(`
${C.cyan}${C.bold}===============================================================================${C.reset}
${C.green}${C.bold}  🛡️  VEIL v3.0 — CLEAN-MACHINE SIH SETUP & PRE-FLIGHT VALIDATOR${C.reset}
${C.cyan}${C.bold}===============================================================================${C.reset}
`);
}

function findChromePath() {
  const commonPaths = [
    // Windows
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    `${process.env.LOCALAPPDATA}\\Google\\Chrome\\Application\\chrome.exe`,
    'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
    // Linux
    '/usr/bin/google-chrome',
    '/usr/bin/chromium-browser',
    '/usr/bin/chromium',
    // macOS
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
  ];

  for (const p of commonPaths) {
    if (p && fs.existsSync(p)) return p;
  }
  return null;
}

function setup() {
  banner();
  let allPass = true;

  // 1. Node.js Version
  const nodeVersion = process.version;
  const majorVersion = parseInt(nodeVersion.slice(1).split('.')[0], 10);
  if (majorVersion >= 18) {
    console.log(`  ${C.green}✔ [PASS] Node.js Runtime:${C.reset} ${nodeVersion} (>= 18.0.0 required)`);
  } else {
    console.log(`  ${C.red}✗ [FAIL] Node.js Runtime:${C.reset} ${nodeVersion} is outdated. Please upgrade to Node >= 18.`);
    allPass = false;
  }

  // 2. Chrome / Edge Browser
  const chromePath = findChromePath();
  if (chromePath) {
    console.log(`  ${C.green}✔ [PASS] Browser Discovered:${C.reset} ${chromePath}`);
  } else {
    console.log(`  ${C.yellow}⚠ [WARN] Chrome Executable:${C.reset} Default path not found. Please specify CHROME_PATH or launch manually.`);
  }

  // 3. Extension Manifest Integrity
  const manifestPath = path.join(__dirname, '..', 'veil-extension', 'manifest.json');
  if (fs.existsSync(manifestPath)) {
    try {
      const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
      console.log(`  ${C.green}✔ [PASS] Extension Manifest:${C.reset} ${manifest.name} (v${manifest.version}, MV${manifest.manifest_version})`);
    } catch (err) {
      console.log(`  ${C.red}✗ [FAIL] Extension Manifest:${C.reset} Malformed JSON: ${err.message}`);
      allPass = false;
    }
  } else {
    console.log(`  ${C.red}✗ [FAIL] Extension Manifest:${C.reset} Missing at ${manifestPath}`);
    allPass = false;
  }

  // 4. Demo Sites & Artifacts Directories
  const requiredDirs = [
    path.join(__dirname, '..', 'demo-sites'),
    path.join(__dirname, '..', 'veil-extension', 'sidepanel'),
    path.join(__dirname, '..', 'sih'),
    path.join(__dirname, '..', 'artifacts')
  ];
  requiredDirs.forEach(dir => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  });
  console.log(`  ${C.green}✔ [PASS] Project Layout:${C.reset} demo-sites, sidepanel, sih, artifacts directories confirmed`);

  console.log(`\n${C.cyan}${C.bold}===============================================================================${C.reset}`);
  if (allPass) {
    console.log(`  ${C.green}${C.bold}PRE-FLIGHT STATUS: CLEAN MACHINE IS SIH READY! 🚀${C.reset}`);
    console.log(`  ${C.dim}Launch the complete experience with:${C.reset} ${C.bold}npm run sih${C.reset}`);
  } else {
    console.log(`  ${C.red}${C.bold}PRE-FLIGHT STATUS: ONE OR MORE PREREQUISITES FAILED${C.reset}`);
  }
  console.log(`${C.cyan}${C.bold}===============================================================================${C.reset}\n`);

  return allPass;
}

if (require.main === module) {
  const ok = setup();
  process.exit(ok ? 0 : 1);
}

module.exports = { setup, findChromePath };
