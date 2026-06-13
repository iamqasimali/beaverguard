'use strict';

const path = require('path');
const chokidar = require('chokidar');
const { scanFileContent } = require('./fileScanner');
const { printFinding, printHeader } = require('../utils/reporter');
const chalk = require('chalk');

const WATCH_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.mts', '.tsx', '.jsx', '.py',
  '.sh', '.bash', '.zsh', '.json', '.env', '.yaml', '.yml',
]);
const IGNORE_DIRS = [/node_modules/, /\.git/, /dist\//, /build\//, /\.next\//, /__pycache__/];
const ALERT_COOLDOWN_MS = 10_000;

/** filePath → last alert timestamp */
const alertedFiles = new Map();

/**
 * Handle a file add/change event.
 * @param {string} filePath
 * @param {string} event
 * @param {{ verbose: boolean, onFinding: Function|null }} options
 */
function handleFile(filePath, event, options) {
  const ext = path.extname(filePath).toLowerCase();
  const base = path.basename(filePath).toLowerCase();
  const isEnv = base === '.env' || base.startsWith('.env.');
  if (!WATCH_EXTENSIONS.has(ext) && !isEnv) return;

  if (options.verbose) {
    console.log(chalk.dim(`[${event}] ${filePath}`));
  }

  const now = Date.now();
  const lastAlert = alertedFiles.get(filePath) || 0;
  if (now - lastAlert < ALERT_COOLDOWN_MS) return;

  const findings = scanFileContent(filePath);
  if (findings.length > 0) {
    alertedFiles.set(filePath, now);
    console.log('\n' + chalk.bgRed.white.bold(' 🚨 THREAT DETECTED ') + ' ' + chalk.bold(filePath));
    for (const f of findings) {
      printFinding(f);
      if (options.onFinding) options.onFinding(f);
    }
  } else if (options.verbose) {
    console.log(chalk.green(`  ✅ Clean: ${path.basename(filePath)}`));
  }
}

/**
 * Start a real-time filesystem watcher.
 * @param {string} watchPath
 * @param {{ verbose?: boolean, onFinding?: Function }} [options]
 * @returns {object} chokidar watcher instance
 */
function startWatcher(watchPath, options = {}) {
  const absPath = path.resolve(watchPath);
  const { verbose = false, onFinding = null } = options;
  const opts = { verbose, onFinding };

  printHeader('Real-Time Watcher');
  console.log(chalk.cyan(`Watching: ${absPath}`));

  const watcher = chokidar.watch(absPath, {
    persistent: true,
    ignoreInitial: true,
    ignored: IGNORE_DIRS,
    awaitWriteFinish: { stabilityThreshold: 300, pollInterval: 100 },
    usePolling: false,
  });

  watcher.on('add', (fp) => handleFile(fp, 'add', opts));
  watcher.on('change', (fp) => handleFile(fp, 'change', opts));
  watcher.on('error', (err) => console.error(chalk.red(`Watcher error: ${err.message}`)));
  watcher.on('ready', () => console.log(chalk.green('✅ Watcher active — press Ctrl+C to stop.')));

  process.on('SIGINT', () => {
    watcher.close();
    console.log(chalk.dim('\nWatcher stopped.'));
    process.exit(0);
  });

  return watcher;
}

module.exports = { startWatcher };
