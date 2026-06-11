'use strict';

/**
 * BeaverGuard — Public API
 *
 * @example
 * // Package scan
 * const { scanPackageJson } = require('beaverguard');
 * const { findings } = scanPackageJson('./package.json');
 *
 * @example
 * // File scan
 * const { scanFiles } = require('beaverguard');
 * const { findings } = scanFiles('./src');
 *
 * @example
 * // GitHub repo pre-clone check
 * const { scanGitHubRepo } = require('beaverguard');
 * const { findings } = await scanGitHubRepo('https://github.com/owner/repo');
 */

const { scanPackageJson, scanPackageJsonWithNetwork, fetchSocketScore, runPackageScan } = require('./scanners/packageScanner');
const { scanFiles, runFileScan } = require('./scanners/fileScanner');
const { scanGitHubRepo, runRepoScan } = require('./scanners/repoScanner');
const { startWatcher } = require('./scanners/watchScanner');
const { SEVERITY, createFinding } = require('./utils/reporter');
const signatures = require('./utils/signatures');

module.exports = {
  // Package scanner
  scanPackageJson,
  scanPackageJsonWithNetwork,
  fetchSocketScore,
  runPackageScan,
  // File scanner
  scanFiles,
  runFileScan,
  // Repo scanner
  scanGitHubRepo,
  runRepoScan,
  // Watch scanner
  startWatcher,
  // Utilities
  SEVERITY,
  createFinding,
  signatures,
};
