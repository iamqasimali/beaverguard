#!/usr/bin/env node
'use strict';

const { Command } = require('commander');
const chalk = require('chalk');
const path = require('path');
const fs = require('fs');

const { runPackageScan, scanPackageJson } = require('../src/scanners/packageScanner');
const { runFileScan, scanFiles } = require('../src/scanners/fileScanner');
const { runRepoScan, scanGitHubRepo } = require('../src/scanners/repoScanner');
const { startWatcher } = require('../src/scanners/watchScanner');

const program = new Command();

program
  .name('beaverguard')
  .version('1.0.0')
  .description(`${chalk.red.bold('BeaverGuard')} ${chalk.dim('— BeaverTail/DPRK malware scanner')}`);

// scan-packages
program
  .command('scan-packages [path]')
  .alias('sp')
  .description('Scan a package.json for malicious dependencies and install scripts')
  .option('--json', 'Output results as JSON')
  .action((pkgPath = './package.json', opts) => {
    try {
      if (opts.json) {
        const result = scanPackageJson(pkgPath);
        console.log(JSON.stringify(result, null, 2));
      } else {
        const findings = runPackageScan(pkgPath);
        const critical = findings.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH');
        if (critical.length > 0) process.exit(1);
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
      } else {
        const findings = runFileScan(targetPath);
        const critical = findings.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH');
        if (critical.length > 0) process.exit(1);
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
      } else {
        const findings = await runRepoScan(repoUrl, token);
        const critical = findings.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH');
        if (critical.length > 0) process.exit(1);
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
  .action(async (targetPath = '.', opts) => {
    const absPath = path.resolve(targetPath);
    const pkgPath = path.join(absPath, 'package.json');
    const allFindings = [];

    try {
      if (opts.json) {
        if (fs.existsSync(pkgPath)) {
          const pkgResult = scanPackageJson(pkgPath);
          for (const f of pkgResult.findings) allFindings.push({ ...f, scanner: 'packages' });
        }
        const fileResult = scanFiles(targetPath);
        for (const f of fileResult.findings) allFindings.push({ ...f, scanner: 'files' });
        console.log(JSON.stringify({ findings: allFindings, total: allFindings.length }, null, 2));
      } else {
        let pkgFindings = [];
        if (fs.existsSync(pkgPath)) {
          pkgFindings = runPackageScan(pkgPath);
        }
        const fileFindings = runFileScan(targetPath);
        allFindings.push(...pkgFindings, ...fileFindings);
        const critical = allFindings.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH');
        if (critical.length > 0) process.exit(1);
      }
    } catch (err) {
      console.error(chalk.red(`Error: ${err.message}`));
      process.exit(1);
    }
  });

program.addHelpText('after', `
${chalk.bold('Examples:')}
  ${chalk.cyan('$ beaverguard scan-packages ./package.json')}
  ${chalk.cyan('$ beaverguard scan-files ./src')}
  ${chalk.cyan('$ beaverguard scan-repo https://github.com/owner/repo --token ghp_xxx')}
  ${chalk.cyan('$ beaverguard watch . --verbose')}
  ${chalk.cyan('$ beaverguard scan . --json > report.json')}

${chalk.bold('Exit codes:')}
  ${chalk.green('0')} — No CRITICAL or HIGH findings
  ${chalk.red('1')} — At least one CRITICAL or HIGH finding (CI-friendly)
`);

program.parse(process.argv);
