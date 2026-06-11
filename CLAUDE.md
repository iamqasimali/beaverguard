# BeaverGuard — Security Scanner

## What this is
A Node.js CLI + npm package that detects BeaverTail malware indicators.
BeaverTail is DPRK/Lazarus Group malware used in fake job interview attacks
targeting developers (Contagious Interview campaign).

## Project structure
- bin/cli.js              → CLI entry (commander)
- src/index.js            → public programmatic API
- src/scanners/
  - packageScanner.js     → npm package.json analysis
  - fileScanner.js        → file content + entropy analysis
  - repoScanner.js        → GitHub metadata pre-clone checks
  - watchScanner.js       → real-time chokidar watcher
- src/utils/
  - signatures.js         → threat database (patterns, known packages)
  - reporter.js           → chalk output + Finding objects
- test/test.js            → 12 scenario tests

## Stack
- Node.js ≥ 16, macOS/Linux only
- Dependencies: chalk@4, commander@11, chokidar@3, axios@1, ora@5
- No TypeScript — plain CommonJS ('use strict')

## Code style
- Always 'use strict' at top
- CommonJS (require/module.exports), NOT ES modules
- JSDoc for all exported functions
- Named exports from each scanner: scan* (returns data) + run* (prints + returns)

## CLI commands
- beaverguard scan-packages [path]   → scan package.json
- beaverguard scan-files [path]      → scan directory/file
- beaverguard scan-repo <url>        → pre-clone GitHub check
- beaverguard watch [path]           → real-time monitor
- beaverguard scan [path]            → all static scans combined

## Exit codes
- 0 → no HIGH or CRITICAL findings
- 1 → at least one HIGH or CRITICAL finding (CI-friendly)

## Testing
Run: node test/test.js
All 12 tests must pass before any commit.
Never commit with failing tests.

## Finding object shape (IMPORTANT — keep consistent)
{
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
  type: string,       // short label e.g. "Known malicious package"
  target: string,     // package name, file path, etc.
  reason: string,     // human-readable explanation
  detail: string,     // line number, script snippet, etc. (can be empty)
  timestamp: string,  // ISO 8601
}

## Workflow rules
- Always run node test/test.js after any change
- Never edit signatures.js without adding a corresponding test
- Keep CLAUDE.md updated when adding new scanner commands
- Commit after each scanner is implemented and tested
