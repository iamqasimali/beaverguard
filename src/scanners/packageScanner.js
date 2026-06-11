'use strict';

const fs = require('fs');
const path = require('path');
const axios = require('axios');
const {
  KNOWN_MALICIOUS_PACKAGES,
  TRUSTED_PACKAGES,
  SUSPICIOUS_PATTERNS,
  SUSPICIOUS_SCRIPT_PATTERNS,
} = require('../utils/signatures');
const { SEVERITY, createFinding, printFinding, printSummary, printHeader } = require('../utils/reporter');

const INSTALL_HOOKS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepack'];
const DEP_SECTIONS = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];
const LOCAL_PREFIXES = ['file:', 'git+', 'github:', 'bitbucket:', 'gitlab:'];
const SOCKET_API = 'https://socket.dev/api/npm/package';

/**
 * Fetch a package's security score from Socket.dev.
 * Returns null on any network/parse error — never throws.
 * @param {string} packageName
 * @returns {Promise<{score: number, issues: object}|null>}
 */
async function fetchSocketScore(packageName) {
  try {
    const { data } = await axios.get(`${SOCKET_API}/${encodeURIComponent(packageName)}/score`, {
      timeout: 3000,
      headers: { 'User-Agent': 'beaverguard-scanner/1.0' },
    });
    return { score: data.score, issues: data.issues || {} };
  } catch (_) {
    return null;
  }
}

/**
 * Analyse a single npm package name + version for threat indicators.
 * @param {string} name
 * @param {string} version
 * @returns {object[]} findings
 */
function analysePackage(name, version) {
  if (KNOWN_MALICIOUS_PACKAGES.has(name)) {
    return [createFinding(
      SEVERITY.CRITICAL,
      'Known malicious package',
      name,
      'Package is a confirmed BeaverTail/DPRK malicious package used in Contagious Interview attacks.',
      `Version: ${version}`
    )];
  }

  if (TRUSTED_PACKAGES.has(name)) return [];

  for (const { pattern, reason } of SUSPICIOUS_PATTERNS) {
    if (pattern.test(name)) {
      return [createFinding(SEVERITY.HIGH, 'Suspicious package name', name, reason, `Version: ${version}`)];
    }
  }

  for (const prefix of LOCAL_PREFIXES) {
    if (version.startsWith(prefix)) {
      return [createFinding(
        SEVERITY.MEDIUM,
        'Non-registry package source',
        name,
        `Package version uses non-registry source: "${prefix}" — may bypass npm security scanning.`,
        `Version: ${version}`
      )];
    }
  }

  if (version === '*' || version === 'latest') {
    return [createFinding(
      SEVERITY.LOW,
      'Unpinned version',
      name,
      `Package version is "${version}" — unpinned versions can silently pull malicious updates.`,
      `Version: ${version}`
    )];
  }

  return [];
}

/**
 * Scan a package.json file for threat indicators.
 * @param {string} packageJsonPath
 * @returns {{ findings: object[], packageName: string, elapsed: number }}
 */
function scanPackageJson(packageJsonPath) {
  const start = Date.now();
  const absPath = path.resolve(packageJsonPath);

  if (!fs.existsSync(absPath)) {
    throw new Error(`package.json not found: ${absPath}`);
  }

  let pkg;
  try {
    pkg = JSON.parse(fs.readFileSync(absPath, 'utf8'));
  } catch (e) {
    throw new Error(`Invalid JSON in ${absPath}: ${e.message}`);
  }

  const findings = [];

  // Scan dependency sections
  for (const section of DEP_SECTIONS) {
    const deps = pkg[section];
    if (!deps || typeof deps !== 'object') continue;
    for (const [name, version] of Object.entries(deps)) {
      const results = analysePackage(name, String(version));
      for (const f of results) {
        f.detail = f.detail ? `${f.detail} | section: ${section}` : `section: ${section}`;
        findings.push(f);
      }
    }
  }

  // Scan install hooks
  const scripts = pkg.scripts || {};
  for (const hook of INSTALL_HOOKS) {
    const script = scripts[hook];
    if (!script) continue;
    for (const { pattern, reason } of SUSPICIOUS_SCRIPT_PATTERNS) {
      if (pattern.test(script)) {
        findings.push(createFinding(
          SEVERITY.CRITICAL,
          'Malicious install script',
          `scripts.${hook}`,
          reason,
          script.substring(0, 120)
        ));
        break;
      }
    }
  }

  // Check custom registry
  const registry = pkg.publishConfig && pkg.publishConfig.registry;
  if (registry && !registry.includes('npmjs.org') && !registry.includes('npmjs.com')) {
    findings.push(createFinding(
      SEVERITY.MEDIUM,
      'Custom registry',
      'publishConfig.registry',
      `Package uses a non-standard npm registry: ${registry}`,
      registry
    ));
  }

  return { findings, packageName: pkg.name || path.basename(absPath), elapsed: Date.now() - start };
}

/**
 * Run a full package scan with optional Socket.dev network checks.
 * @param {string} packageJsonPath
 * @param {{ noNetwork?: boolean }} [options]
 * @returns {Promise<{ findings: object[], packageName: string, elapsed: number }>}
 */
async function scanPackageJsonWithNetwork(packageJsonPath, options = {}) {
  const result = scanPackageJson(packageJsonPath);
  if (options.noNetwork) return result;

  // Collect unique package names not already flagged CRITICAL and not trusted
  const flaggedCritical = new Set(
    result.findings.filter((f) => f.severity === SEVERITY.CRITICAL).map((f) => f.target)
  );

  let pkg;
  try {
    pkg = JSON.parse(fs.readFileSync(path.resolve(packageJsonPath), 'utf8'));
  } catch (_) {
    return result;
  }

  const toCheck = new Set();
  for (const section of DEP_SECTIONS) {
    const deps = pkg[section] || {};
    for (const name of Object.keys(deps)) {
      if (!flaggedCritical.has(name) && !TRUSTED_PACKAGES.has(name)) toCheck.add(name);
    }
  }

  // Sequential to avoid rate-limiting Socket.dev
  for (const name of toCheck) {
    const data = await fetchSocketScore(name);
    if (data && typeof data.score === 'number' && data.score < 0.5) {
      result.findings.push(createFinding(
        SEVERITY.HIGH,
        'Low Socket.dev score',
        name,
        `Socket.dev security score is ${data.score.toFixed(2)} (threshold: 0.50) — package flagged for suspicious behaviour.`,
        `https://socket.dev/npm/package/${name}`
      ));
    }
  }

  result.elapsed = Date.now() - (Date.now() - result.elapsed);
  return result;
}

/**
 * Run a full package scan and print results.
 * @param {string} packageJsonPath
 * @param {{ noNetwork?: boolean }} [options]
 * @returns {Promise<object[]>} findings
 */
async function runPackageScan(packageJsonPath, options = {}) {
  printHeader('Package Scanner');
  const { findings, packageName, elapsed } = await scanPackageJsonWithNetwork(packageJsonPath, options);
  for (const f of findings) printFinding(f);
  printSummary(`Package Scanner — ${packageName}`, findings, elapsed);
  return findings;
}

module.exports = { analysePackage, scanPackageJson, scanPackageJsonWithNetwork, fetchSocketScore, runPackageScan };
