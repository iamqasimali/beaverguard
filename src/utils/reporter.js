'use strict';

const chalk = require('chalk');

const SEVERITY = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  INFO: 'INFO',
};

const SEVERITY_COLORS = {
  CRITICAL: (s) => chalk.bgRed.white.bold(s),
  HIGH: (s) => chalk.red.bold(s),
  MEDIUM: (s) => chalk.yellow.bold(s),
  LOW: (s) => chalk.cyan(s),
  INFO: (s) => chalk.gray(s),
};

const SEVERITY_EMOJIS = {
  CRITICAL: '🚨',
  HIGH: '🔴',
  MEDIUM: '🟡',
  LOW: '🔵',
  INFO: 'ℹ️',
};

/**
 * @param {string} severity
 * @param {string} type
 * @param {string} target
 * @param {string} reason
 * @param {string} [detail]
 * @returns {object} Finding
 */
function createFinding(severity, type, target, reason, detail = '') {
  return { severity, type, target, reason, detail, timestamp: new Date().toISOString() };
}

/**
 * Print a single finding to stdout with color.
 * @param {object} finding
 */
function printFinding(finding) {
  const { severity, type, target, reason, detail } = finding;
  const colorFn = SEVERITY_COLORS[severity] || SEVERITY_COLORS.INFO;
  const emoji = SEVERITY_EMOJIS[severity] || 'ℹ️';

  console.log(`\n${emoji} ${colorFn(severity)} ${chalk.bold(target)}`);
  console.log(`  Type   : ${type}`);
  console.log(`  Reason : ${reason}`);
  if (detail) {
    console.log(`  Detail : ${detail}`);
  }
}

/**
 * Print summary stats for a completed scan.
 * @param {string} scannerName
 * @param {object[]} findings
 * @param {number} elapsed - ms
 */
function printSummary(scannerName, findings, elapsed) {
  console.log('\n' + chalk.dim('─'.repeat(60)));
  console.log(chalk.bold(`Scanner : ${scannerName}`));
  console.log(`Elapsed : ${elapsed}ms`);

  if (findings.length === 0) {
    console.log(chalk.green('✅ No threats detected.'));
    return;
  }

  const counts = {};
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  }

  for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']) {
    if (counts[sev]) {
      const colorFn = SEVERITY_COLORS[sev];
      console.log(`  ${colorFn(sev.padEnd(8))} : ${counts[sev]}`);
    }
  }
}

/**
 * Print the BeaverGuard banner.
 * @param {string} title
 */
function printHeader(title) {
  console.log('\n' + chalk.bgRed.white.bold(` 🛡  BeaverGuard — ${title} `));
}

module.exports = { SEVERITY, createFinding, printFinding, printSummary, printHeader };
