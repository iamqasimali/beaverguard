#!/usr/bin/env node
'use strict';

const { Command } = require('commander');
const chalk = require('chalk');
const path = require('path');
const fs = require('fs');

const { runPackageScan, scanPackageJsonWithNetwork, scanLockfile } = require('../src/scanners/packageScanner');
const { runFileScan, scanFiles } = require('../src/scanners/fileScanner');
const { runRepoScan, scanGitHubRepo } = require('../src/scanners/repoScanner');
const { startWatcher } = require('../src/scanners/watchScanner');
const { printFinding } = require('../src/utils/reporter');

const program = new Command();

/**
 * Exit 1 if any finding is CRITICAL or HIGH (the documented CI contract).
 * @param {object[]} findings
 */
function exitOnSevere(findings) {
  const severe = findings.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH');
  if (severe.length > 0) process.exit(1);
}

program
  .name('beaverguard')
  .version(require('../package.json').version)
  .description(`${chalk.red.bold('BeaverGuard')} ${chalk.dim('— BeaverTail/DPRK malware scanner')}`);

// scan-packages
program
  .command('scan-packages [path]')
  .alias('sp')
  .description('Scan a package.json for malicious dependencies and install scripts')
  .option('--json', 'Output results as JSON')
  .option('--no-network', 'Skip OSV.dev remote checks (offline mode)')
  .option('--lockfile [path]', 'Also scan package-lock.json (auto-detects if no path given)')
  .action(async (pkgPath = './package.json', opts) => {
    try {
      const noNetwork = opts.network === false;
      const allFindings = [];

      if (opts.json) {
        const result = await scanPackageJsonWithNetwork(pkgPath, { noNetwork });
        allFindings.push(...result.findings);

        if (opts.lockfile) {
          const lockPath = opts.lockfile === true
            ? path.join(path.dirname(path.resolve(pkgPath)), 'package-lock.json')
            : opts.lockfile;
          try {
            const lockResult = scanLockfile(lockPath);
            allFindings.push(...lockResult.findings);
          } catch (lockErr) {
            console.warn(chalk.yellow(`Warning: ${lockErr.message}`));
          }
        }

        console.log(JSON.stringify({ findings: allFindings, total: allFindings.length }, null, 2));
        exitOnSevere(allFindings);
      } else {
        const findings = await runPackageScan(pkgPath, { noNetwork });
        allFindings.push(...findings);

        if (opts.lockfile) {
          const lockPath = opts.lockfile === true
            ? path.join(path.dirname(path.resolve(pkgPath)), 'package-lock.json')
            : opts.lockfile;
          try {
            const lockResult = scanLockfile(lockPath);
            console.log(chalk.bold.cyan('\n--- Package Lock File Scan ---'));
            for (const f of lockResult.findings) {
              printFinding(f);
            }
            console.log(chalk.dim(`Checked ${lockResult.packagesChecked} packages in ${lockResult.elapsed}ms`));
            allFindings.push(...lockResult.findings);
          } catch (lockErr) {
            console.warn(chalk.yellow(`Warning: ${lockErr.message}`));
          }
        }

        exitOnSevere(allFindings);
      }
    } catch (err) {
      console.error(chalk.red(`Error: ${err.message}`));
      process.exit(1);
    }
  });

// scan-files
program
  .command('scan-files [path]')
  .alias('sf')
  .description('Recursively scan files for malicious code patterns')
  .option('--json', 'Output results as JSON')
  .action((targetPath = '.', opts) => {
    try {
      if (opts.json) {
        const result = scanFiles(targetPath);
        console.log(JSON.stringify(result, null, 2));
        exitOnSevere(result.findings);
      } else {
        const findings = runFileScan(targetPath);
        exitOnSevere(findings);
      }
    } catch (err) {
      console.error(chalk.red(`Error: ${err.message}`));
      process.exit(1);
    }
  });

// scan-repo
program
  .command('scan-repo <github-url>')
  .alias('sr')
  .description('Check a GitHub repository for threat indicators before cloning')
  .option('--token <token>', 'GitHub personal access token (overrides GITHUB_TOKEN env var)')
  .option('--json', 'Output results as JSON')
  .action(async (repoUrl, opts) => {
    try {
      const token = opts.token || process.env.GITHUB_TOKEN;
      if (opts.json) {
        const result = await scanGitHubRepo(repoUrl, token);
        console.log(JSON.stringify(result, null, 2));
        exitOnSevere(result.findings);
      } else {
        const findings = await runRepoScan(repoUrl, token);
        exitOnSevere(findings);
      }
    } catch (err) {
      console.error(chalk.red(`Error: ${err.message}`));
      process.exit(1);
    }
  });

// watch
program
  .command('watch [path]')
  .alias('w')
  .description('Watch a directory in real-time for newly added/changed malicious files')
  .option('--verbose', 'Log every scanned file, not just threats')
  .action((watchPath = '.', opts) => {
    startWatcher(watchPath, { verbose: opts.verbose });
  });

// scan (combined)
program
  .command('scan [path]')
  .alias('s')
  .description('Run all static scans (packages + files) on a directory')
  .option('--json', 'Output combined findings as JSON')
  .option('--no-network', 'Skip OSV.dev remote checks (offline mode)')
  .action(async (targetPath = '.', opts) => {
    const absPath = path.resolve(targetPath);
    const pkgPath = path.join(absPath, 'package.json');
    const noNetwork = opts.network === false;
    const allFindings = [];

    try {
      if (opts.json) {
        if (fs.existsSync(pkgPath)) {
          const pkgResult = await scanPackageJsonWithNetwork(pkgPath, { noNetwork });
          for (const f of pkgResult.findings) allFindings.push({ ...f, scanner: 'packages' });
        }
        const fileResult = scanFiles(targetPath);
        for (const f of fileResult.findings) allFindings.push({ ...f, scanner: 'files' });
        console.log(JSON.stringify({ findings: allFindings, total: allFindings.length }, null, 2));
      } else {
        if (fs.existsSync(pkgPath)) {
          const pkgFindings = await runPackageScan(pkgPath, { noNetwork });
          allFindings.push(...pkgFindings);
        }
        const fileFindings = runFileScan(targetPath);
        allFindings.push(...fileFindings);
      }
      exitOnSevere(allFindings);
    } catch (err) {
      console.error(chalk.red(`Error: ${err.message}`));
      process.exit(1);
    }
  });

// install-hook
program
  .command('install-hook')
  .description('Install a git pre-commit hook that runs scan-packages before every commit')
  .action(() => {
    const hookDir = path.resolve('.git/hooks');
    const hookPath = path.join(hookDir, 'pre-commit');

    if (!fs.existsSync(hookDir)) {
      console.error(chalk.red('Error: .git/hooks/ not found — run this inside a git repository.'));
      process.exit(1);
    }

    if (fs.existsSync(hookPath)) {
      console.error(chalk.yellow(`Warning: pre-commit hook already exists at ${hookPath}`));
      console.error(chalk.yellow('Remove it first with: beaverguard uninstall-hook'));
      process.exit(1);
    }

    const script = [
      '#!/bin/sh',
      '# Installed by BeaverGuard — beaverguard uninstall-hook to remove',
      'if command -v beaverguard >/dev/null 2>&1; then',
      '  beaverguard scan-packages ./package.json',
      'else',
      '  npx --yes beaverguard scan-packages ./package.json',
      'fi',
      '',
    ].join('\n');
    fs.writeFileSync(hookPath, script, { mode: 0o755 });
    console.log(chalk.green(`✅ Pre-commit hook installed at ${hookPath}`));
    console.log(chalk.dim('   Runs: beaverguard scan-packages ./package.json on every commit.'));
    console.log(chalk.dim('   Remove with: beaverguard uninstall-hook'));
  });

// uninstall-hook
program
  .command('uninstall-hook')
  .description('Remove the BeaverGuard git pre-commit hook')
  .action(() => {
    const hookPath = path.resolve('.git/hooks/pre-commit');

    if (!fs.existsSync(hookPath)) {
      console.error(chalk.yellow('No pre-commit hook found at .git/hooks/pre-commit'));
      process.exit(1);
    }

    const content = fs.readFileSync(hookPath, 'utf8');
    if (!content.includes('BeaverGuard')) {
      console.error(chalk.red('Error: pre-commit hook was not installed by BeaverGuard — not removing.'));
      process.exit(1);
    }

    fs.unlinkSync(hookPath);
    console.log(chalk.green('✅ BeaverGuard pre-commit hook removed.'));
  });

program.addHelpText('after', `
${chalk.bold('Examples:')}
  ${chalk.cyan('$ beaverguard scan-packages ./package.json')}
  ${chalk.cyan('$ beaverguard scan-files ./src')}
  ${chalk.cyan('$ beaverguard scan-repo https://github.com/owner/repo --token ghp_xxx')}
  ${chalk.cyan('$ beaverguard watch . --verbose')}
  ${chalk.cyan('$ beaverguard scan . --json > report.json')}
  ${chalk.cyan('$ beaverguard install-hook')}

${chalk.bold('Exit codes:')}
  ${chalk.green('0')} — No CRITICAL or HIGH findings
  ${chalk.red('1')} — At least one CRITICAL or HIGH finding (CI-friendly)
`);

program.parse(process.argv);
