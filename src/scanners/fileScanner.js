'use strict';

const fs = require('fs');
const path = require('path');
const { MALICIOUS_FILE_PATTERNS, SENSITIVE_FILE_NAMES, SAFE_EXTERNAL_HOSTS } = require('../utils/signatures');
const { SEVERITY, createFinding, printFinding, printSummary, printHeader } = require('../utils/reporter');
const { loadConfig } = require('../utils/config');

const config = loadConfig();

const SCANNABLE_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.mts', '.tsx', '.jsx', '.py',
  '.sh', '.bash', '.zsh', '.json', '.env', '.yaml', '.yml',
]);

const IGNORE_DIRS = new Set([
  'node_modules', '.git', '.next', 'dist', 'build',
  'coverage', '.turbo', '.cache', '__pycache__',
]);

const ENTROPY_EXTENSIONS = new Set(['.js', '.ts', '.py', '.tsx', '.jsx']);
const MAX_FILE_SIZE = config.max_file_size_kb * 1024;

/**
 * Compute Shannon entropy of a string.
 * @param {string} content
 * @returns {number}
 */
function shannonEntropy(content) {
  const freq = {};
  for (const ch of content) freq[ch] = (freq[ch] || 0) + 1;
  const len = content.length;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Recursively collect scannable file paths under dir.
 * @param {string} dir
 * @param {string[]} [files]
 * @returns {string[]}
 */
function collectFiles(dir, files = []) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (e) {
    return files;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!IGNORE_DIRS.has(entry.name)) collectFiles(fullPath, files);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      const base = entry.name.toLowerCase();
      const isSensitive = SENSITIVE_FILE_NAMES.some((s) => s.name.toLowerCase() === base);
      if (SCANNABLE_EXTENSIONS.has(ext) || isSensitive) files.push(fullPath);
    }
  }
  return files;
}

/**
 * Scan a single file for malicious indicators.
 * @param {string} filePath
 * @returns {object[]} findings
 */
function scanFileContent(filePath) {
  const findings = [];
  const base = path.basename(filePath).toLowerCase();

  // Check sensitive filename
  for (const { name, reason } of SENSITIVE_FILE_NAMES) {
    if (name.toLowerCase() === base) {
      findings.push(createFinding(SEVERITY.HIGH, 'Sensitive filename', filePath, reason, ''));
      break;
    }
  }

  let stat;
  try {
    stat = fs.statSync(filePath);
  } catch (e) {
    return findings;
  }
  if (stat.size === 0 || stat.size > MAX_FILE_SIZE) return findings;

  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch (e) {
    return findings;
  }

  // Check for binary-like content (null bytes)
  if (content.includes('\u0000')) return findings;

  const lines = content.split('\n');

  for (const { pattern, reason, severity } of MALICIOUS_FILE_PATTERNS) {
    if (pattern.test(content)) {
      // Skip axios.post/fetch POST to safe external hosts (OpenAI, Stripe, etc.)
      if (reason.includes('exfiltration') || reason.includes('POST to external')) {
        const urlMatch = content.match(/(['"`])(https?:\/\/[^'"`]+)\1/);
        if (urlMatch) {
          const url = urlMatch[2];
          try {
            const hostname = new URL(url).hostname;
            if (SAFE_EXTERNAL_HOSTS.has(hostname)) continue;
          } catch (e) {
            // Invalid URL — continue with the finding
          }
        }
      }

      let detail = '';
      for (let i = 0; i < lines.length; i++) {
        if (pattern.test(lines[i])) {
          detail = `Line ${i + 1}: ${lines[i].trim().substring(0, 100)}`;
          break;
        }
      }
      findings.push(createFinding(severity || SEVERITY.HIGH, 'Malicious code pattern', filePath, reason, detail));
    }
  }

  // Shannon entropy check for JS/TS/PY files
  const ext = path.extname(filePath).toLowerCase();
  if (ENTROPY_EXTENSIONS.has(ext) && content.length > 500) {
    const entropy = shannonEntropy(content);
    if (entropy > config.entropy_threshold) {
      findings.push(createFinding(
        SEVERITY.MEDIUM,
        'High entropy content',
        filePath,
        `File entropy is ${entropy.toFixed(2)} — may contain obfuscated or encrypted payload.`,
        ''
      ));
    }
  }

  return findings;
}

/**
 * Scan a file or directory for malicious indicators.
 * @param {string} targetPath
 * @returns {{ findings: object[], filesScanned: number, elapsed: number }}
 */
function scanFiles(targetPath) {
  const start = Date.now();
  const absPath = path.resolve(targetPath);
  const findings = [];
  let filesScanned = 0;

  let filePaths;
  let stat;
  try {
    stat = fs.statSync(absPath);
  } catch (e) {
    console.warn(`Warning: target path not found: ${targetPath}`);
    return { findings: [], filesScanned: 0, elapsed: Date.now() - start };
  }

  if (stat.isDirectory()) {
    filePaths = collectFiles(absPath);
  } else {
    filePaths = [absPath];
  }

  for (const fp of filePaths) {
    const result = scanFileContent(fp);
    findings.push(...result);
    filesScanned++;
  }

  return { findings, filesScanned, elapsed: Date.now() - start };
}

/**
 * Run a full file scan and print results.
 * @param {string} targetPath
 * @returns {object[]} findings
 */
function runFileScan(targetPath) {
  printHeader('File Scanner');
  const { findings, filesScanned, elapsed } = scanFiles(targetPath);
  for (const f of findings) printFinding(f);
  printSummary(`File Scanner — ${filesScanned} files scanned`, findings, elapsed);
  return findings;
}

module.exports = { collectFiles, scanFileContent, scanFiles, runFileScan };
