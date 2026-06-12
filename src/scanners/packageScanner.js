'use strict';

const fs = require('fs');
const path = require('path');
const axios = require('axios');
const {
  KNOWN_MALICIOUS_PACKAGES,
  TRUSTED_PACKAGES,
  TRUSTED_SCOPES,
  SUSPICIOUS_PATTERNS,
  SUSPICIOUS_SCRIPT_PATTERNS,
} = require('../utils/signatures');
const { SEVERITY, createFinding, printFinding, printSummary, printHeader } = require('../utils/reporter');

const INSTALL_HOOKS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepack'];
const DEP_SECTIONS = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];
const LOCAL_PREFIXES = ['file:', 'git+', 'github:', 'bitbucket:', 'gitlab:'];
const OSV_API = 'https://api.osv.dev/v1/querybatch';

/**
 * Look up npm packages against the OSV.dev advisory database in a single
 * batch request, returning only malicious-package advisories (MAL-* IDs).
 * Returns null on any network/parse error — never throws.
 * @param {string[]} packageNames
 * @returns {Promise<Object<string, string[]>|null>} map of package name → MAL advisory IDs
 */
async function fetchOsvMalware(packageNames) {
  if (!packageNames || packageNames.length === 0) return {};
  try {
    const queries = packageNames.map((name) => ({ package: { name, ecosystem: 'npm' } }));
    const { data } = await axios.post(OSV_API, { queries }, {
      timeout: 8000,
      headers: { 'User-Agent': 'beaverguard-scanner/1.0' },
    });
    const malicious = {};
    (data.results || []).forEach((result, i) => {
      const malIds = ((result && result.vulns) || [])
        .map((v) => v.id)
        .filter((id) => typeof id === 'string' && id.startsWith('MAL-'));
      if (malIds.length > 0) malicious[packageNames[i]] = malIds;
    });
    return malicious;
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

  // Scoped packages under official vendor scopes (e.g. @metamask/sdk) are
  // legit SDKs — exempt them from the name-pattern heuristics.
  if (name.startsWith('@') && TRUSTED_SCOPES.has(name.split('/')[0])) return [];

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
 * Run a full package scan with optional OSV.dev network checks.
 * @param {string} packageJsonPath
 * @param {{ noNetwork?: boolean }} [options]
 * @returns {Promise<{ findings: object[], packageName: string, elapsed: number }>}
 */
async function scanPackageJsonWithNetwork(packageJsonPath, options = {}) {
  const result = scanPackageJson(packageJsonPath);
  if (options.noNetwork) return result;

  // Collect unique package names not already flagged CRITICAL by the local
  // signature scan. Trusted packages are included too — a hijacked legit
  // package would still surface via its OSV MAL advisory.
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
      if (!flaggedCritical.has(name)) toCheck.add(name);
    }
  }

  const netStart = Date.now();
  const malicious = await fetchOsvMalware([...toCheck]);
  if (malicious) {
    for (const [name, ids] of Object.entries(malicious)) {
      result.findings.push(createFinding(
        SEVERITY.CRITICAL,
        'OSV malicious package advisory',
        name,
        `Package has ${ids.length} malicious-package advisor${ids.length === 1 ? 'y' : 'ies'} in the OSV.dev database (${ids.join(', ')}).`,
        `https://osv.dev/vulnerability/${ids[0]}`
      ));
    }
  }

  result.elapsed += Date.now() - netStart;
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

module.exports = { analysePackage, scanPackageJson, scanPackageJsonWithNetwork, fetchOsvMalware, runPackageScan };
