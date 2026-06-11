# 🛡 BeaverGuard

A Node.js CLI and npm package that detects **BeaverTail malware** indicators —
the infostealer used by **Lazarus Group (DPRK)** in the **Contagious Interview**
campaign, where threat actors pose as recruiters and trick developers into
running malicious npm packages during fake technical interviews.

---

## What it does

| Scanner | What it catches |
|---|---|
| `scan-packages` | Known DPRK malicious packages, typosquats, malicious install hooks (`preinstall`/`postinstall`), non-registry sources |
| `scan-files` | Credential harvesting (SSH keys, `.env`, AWS/GitHub tokens), reverse shells, C2 callbacks, obfuscated base64 payloads |
| `scan-repo` | New/suspicious GitHub accounts, interview-themed repos, committed secrets, root-level droppers |
| `watch` | Real-time chokidar watcher — alerts immediately when a malicious file is added or changed |

---

## Install

```bash
npm install -g beaverguard
# or run without installing:
npx beaverguard scan-packages ./package.json
```

**Requirements:** Node.js ≥ 16, macOS or Linux

---

## CLI Usage

### scan-packages

Scan a `package.json` for malicious dependencies and install scripts.

```bash
beaverguard scan-packages ./package.json

# Example output:
# 🚨 CRITICAL node-telegram-utils
#   Type   : Known malicious package
#   Reason : Package is a confirmed BeaverTail/DPRK malicious package...
#   Detail : Version: 2.1.0 | section: dependencies
```

### scan-files

Recursively scan a directory or file for credential harvesting, reverse shells,
and obfuscated payloads.

```bash
beaverguard scan-files ./src
beaverguard scan-files ./suspicious-script.js
```

Scans `.js`, `.ts`, `.py`, `.sh`, `.json`, `.env`, `.yaml` files. Skips
`node_modules`, `.git`, `dist`, `build`.

### scan-repo

Check a GitHub repository for threat indicators **before cloning**.

```bash
beaverguard scan-repo https://github.com/owner/repo
beaverguard scan-repo https://github.com/owner/repo --token ghp_xxxxx
```

Reads `GITHUB_TOKEN` from the environment if `--token` is not passed.

### watch

Monitor a directory in real-time and alert on any new or modified malicious files.

```bash
beaverguard watch .
beaverguard watch ./projects --verbose
```

Press `Ctrl+C` to stop.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No CRITICAL or HIGH findings |
| `1` | At least one CRITICAL or HIGH finding |

---

## CI Integration

```yaml
# .github/workflows/security.yml
name: BeaverGuard Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm install -g beaverguard
      - run: beaverguard scan-packages ./package.json
      - run: beaverguard scan-files ./src
```

---

## Programmatic API

```js
const {
  scanPackageJson,   // sync — returns { findings, packageName, elapsed }
  scanFiles,         // sync — returns { findings, filesScanned, elapsed }
  scanGitHubRepo,    // async — returns { findings, owner, repo }
  startWatcher,      // returns chokidar watcher instance
  SEVERITY,
  createFinding,
} = require('beaverguard');

// Package scan
const { findings } = scanPackageJson('./package.json');

// File scan
const { findings, filesScanned } = scanFiles('./src');

// GitHub repo pre-clone check
const { findings } = await scanGitHubRepo('https://github.com/owner/repo');

// Real-time watcher with callback
startWatcher('./project', {
  verbose: true,
  onFinding: (finding) => sendAlert(finding),
});
```

### Finding object shape

```js
{
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
  type: string,      // short label, e.g. "Known malicious package"
  target: string,    // package name, file path, etc.
  reason: string,    // human-readable explanation
  detail: string,    // line number, script snippet, etc. (may be empty)
  timestamp: string, // ISO 8601
}
```

---

## What BeaverGuard detects

### Known malicious packages
30+ npm packages confirmed in BeaverTail campaigns: `node-telegram-utils`,
`nodejs-encrypt-agent`, `coinbase-wallet-scripts`, `metamask-utils`,
`solana-web3-util`, and more.

### Suspicious patterns
Typosquats (`expresss`, `lodahs`), DPRK-style compound names (`node-*-agent`,
`js-*-crypto`), crypto/wallet targeting, remote shell patterns.

### Malicious install scripts
`preinstall`/`postinstall` hooks containing `curl|bash`, inline Python/Node
execution, base64 decoding, access to `~/.ssh`, `~/.aws`, or `.env`.

### File-level indicators
SSH key reads, AWS/GitHub/NPM token access, `axios.post` to external URLs,
WebSocket C2 connections, large base64 payloads, `execSync` with shell commands.

### GitHub repo metadata
New accounts (< 90 days), interview-themed descriptions/topics, zero-engagement
repos, committed `.env` files, root-level `.sh`/`.py` droppers.

---

## Recommended workflow

Before running any code from a recruiter or stranger:

1. `beaverguard scan-repo <github-url>` — check before cloning
2. Clone into an isolated VM or container
3. `beaverguard scan-packages ./package.json` — check before `npm install`
4. `beaverguard scan-files .` — scan all source files
5. Proceed only if all scans are clean — **in the VM**

---

## Running tests

```bash
npm test
# or
node test/test.js
```

All 12 tests must pass.

---

## Contributing

To add new threat signatures, edit `src/utils/signatures.js`:

- **`KNOWN_MALICIOUS_PACKAGES`** — Add confirmed malicious package names with a
  source reference (e.g., link to OSINT report or VirusTotal entry).
- **`SUSPICIOUS_PATTERNS`** — Add RegExp patterns with `reason` strings.
- **`MALICIOUS_FILE_PATTERNS`** — Add RegExp patterns for file content.

Every addition to `signatures.js` **must** be accompanied by a corresponding test
in `test/test.js`. Open a PR with the source reference in the description.

---

## Disclaimer

BeaverGuard is a **heuristic scanner** — it detects *indicators*, not certainties.
False positives are possible. A clean scan does **not** guarantee safety.

**Always run untrusted code in an isolated VM regardless of scan results.**

---

## License

MIT © Qasim Ali Zahid
