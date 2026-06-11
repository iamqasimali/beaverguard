'use strict';

/** Confirmed BeaverTail/DPRK malicious npm packages */
const KNOWN_MALICIOUS_PACKAGES = new Set([
  'node-telegram-utils',
  'node-cron-utils',
  'postcss-optimizer',
  'react-native-async-storage',
  'dev-debugger-vite-plugin',
  'eslint-scope-util',
  'next-auth-util',
  'empty-array-validator',
  'nodejs-encrypt-agent',
  'nodejs-cookie-proxy-agent',
  'axios-proxy',
  'cross-top-level',
  'is-buffer-net',
  'coinbase-wallet-scripts',
  'metamask-utils',
  'solana-web3-util',
  'hardhat-utils-extra',
  'crypto-transaction-helper',
  'node-smtp-utils',
  'js-color-convert-extra',
  'node-proxy-agent-utils',
  'react-native-wallet-utils',
  'web3-utils-plus',
  'node-telegram-bot-utils',
  'ethers-utils-extra',
  'js-cookie-proxy-agent',
  'node-crypto-agent',
  'wallet-connect-utils',
  'phantom-wallet-utils',
  'solana-wallet-adapter-utils',
]);

/** Suspicious package name patterns */
const SUSPICIOUS_PATTERNS = [
  // Typosquats
  { pattern: /^expresss$/, reason: 'Typosquat of "express"' },
  { pattern: /^lodahs$/, reason: 'Typosquat of "lodash"' },
  { pattern: /^requst$/, reason: 'Typosquat of "request"' },
  { pattern: /^moongose$/, reason: 'Typosquat of "mongoose"' },
  { pattern: /^webpakc$/, reason: 'Typosquat of "webpack"' },
  { pattern: /^reacts$/, reason: 'Typosquat of "react"' },
  // DPRK compound name patterns
  { pattern: /^node-[\w]+-color$/, reason: 'DPRK-style compound package name (node-*-color)' },
  { pattern: /^node-[\w]+-crypto$/, reason: 'DPRK-style compound package name (node-*-crypto)' },
  { pattern: /^node-[\w]+-wallet$/, reason: 'DPRK-style compound package name (node-*-wallet)' },
  { pattern: /^node-[\w]+-telegram$/, reason: 'DPRK-style compound package name (node-*-telegram)' },
  { pattern: /^node-[\w]+-proxy$/, reason: 'DPRK-style compound package name (node-*-proxy)' },
  { pattern: /^node-[\w]+-agent$/, reason: 'DPRK-style compound package name (node-*-agent)' },
  { pattern: /^node-[\w]+-smtp$/, reason: 'DPRK-style compound package name (node-*-smtp)' },
  { pattern: /^node-[\w]+-cookie$/, reason: 'DPRK-style compound package name (node-*-cookie)' },
  { pattern: /^js-[\w]+-crypto$/, reason: 'DPRK-style compound package name (js-*-crypto)' },
  { pattern: /^js-[\w]+-wallet$/, reason: 'DPRK-style compound package name (js-*-wallet)' },
  { pattern: /^js-[\w]+-telegram$/, reason: 'DPRK-style compound package name (js-*-telegram)' },
  { pattern: /^js-[\w]+-proxy$/, reason: 'DPRK-style compound package name (js-*-proxy)' },
  { pattern: /^js-[\w]+-agent$/, reason: 'DPRK-style compound package name (js-*-agent)' },
  // Suspicious suffix patterns
  { pattern: /-utils-extra$/, reason: 'Suspicious suffix pattern "-utils-extra"' },
  { pattern: /-utils-pro$/, reason: 'Suspicious suffix pattern "-utils-pro"' },
  { pattern: /-utils-plus$/, reason: 'Suspicious suffix pattern "-utils-plus"' },
  { pattern: /-native-agent$/, reason: 'Suspicious suffix pattern "-native-agent"' },
  // Crypto/wallet targeting
  { pattern: /metamask/i, reason: 'Targets MetaMask wallet' },
  { pattern: /phantom.*wallet/i, reason: 'Targets Phantom wallet' },
  { pattern: /solana.*wallet/i, reason: 'Targets Solana wallet' },
  { pattern: /coinbase.*wallet/i, reason: 'Targets Coinbase wallet' },
  // Remote access patterns
  { pattern: /remote.*shell/i, reason: 'Remote shell pattern — possible backdoor' },
  { pattern: /reverse.*shell/i, reason: 'Reverse shell pattern — known RAT indicator' },
  { pattern: /ssh.*client/i, reason: 'SSH client pattern — possible credential harvester' },
];

/** Suspicious install script patterns */
const SUSPICIOUS_SCRIPT_PATTERNS = [
  { pattern: /curl\s+.+\|\s*bash/i, reason: 'Downloads and executes remote shell script via curl|bash' },
  { pattern: /wget\s+.+\|\s*bash/i, reason: 'Downloads and executes remote shell script via wget|bash' },
  { pattern: /curl\s+.+\|\s*sh/i, reason: 'Downloads and executes remote shell script via curl|sh' },
  { pattern: /bash\s+-[ic]/i, reason: 'Remote or inline bash execution' },
  { pattern: /python3?\s+-c\s+["']/i, reason: 'Inline Python execution — potential InvisibleFerret dropper' },
  { pattern: /node\s+-e\s+["']/i, reason: 'Inline Node.js execution in install script' },
  // Dynamic code execution detection (used as detection patterns, not execution)
  { pattern: new RegExp('\\beval\\s*\\(', 'i'), reason: 'Dynamic code execution in install script — code injection risk' },
  { pattern: /base64\s+--decode/i, reason: 'Base64 decoding in install script — obfuscated payload' },
  { pattern: /\batob\s*\(/i, reason: 'atob() base64 decode in install script' },
  { pattern: /chmod\s+\+x/i, reason: 'Makes file executable in install script' },
  { pattern: /\/tmp\//i, reason: 'Writes to /tmp/ — common malware staging area' },
  { pattern: /process\.env\.HOME/i, reason: 'Accesses HOME environment variable in install script' },
  { pattern: /process\.env\.SSH/i, reason: 'Accesses SSH-related environment variable in install script' },
  { pattern: /process\.env\.AWS/i, reason: 'Accesses AWS credentials in install script' },
  { pattern: /process\.env\.NPM_TOKEN/i, reason: 'Accesses NPM_TOKEN in install script' },
  { pattern: /~\/\.ssh\//i, reason: 'Accesses SSH directory in install script' },
  { pattern: /id_rsa/i, reason: 'References SSH private key (id_rsa) in install script' },
  { pattern: /authorized_keys/i, reason: 'References authorized_keys in install script' },
  { pattern: /~\/\.aws/i, reason: 'Accesses AWS credentials directory in install script' },
  { pattern: /\.env\b/i, reason: 'Accesses .env file in install script — credential harvesting risk' },
];

/** Malicious file content patterns (used for detection, not execution) */
const MALICIOUS_FILE_PATTERNS = [
  { pattern: /readFileSync\s*\(\s*['"`][^'"`]*\.env[^'"`]*['"`]/i, reason: 'Reads .env file contents — credential harvesting' },
  { pattern: /readFileSync\s*\(\s*['"`][^'"`]*\.ssh[^'"`]*['"`]/i, reason: 'Reads SSH directory — SSH key theft' },
  { pattern: /readFileSync\s*\(\s*['"`][^'"`]*\.aws[^'"`]*['"`]/i, reason: 'Reads AWS credentials directory' },
  { pattern: /readFileSync\s*\(\s*['"`][^'"`]*id_rsa[^'"`]*['"`]/i, reason: 'Reads SSH private key (id_rsa)' },
  { pattern: /process\.env\.AWS_ACCESS_KEY_ID/i, reason: 'Accesses AWS access key credentials' },
  { pattern: /process\.env\.AWS_SECRET/i, reason: 'Accesses AWS secret credentials' },
  { pattern: /process\.env\.AWS_SESSION/i, reason: 'Accesses AWS session token' },
  { pattern: /process\.env\.GITHUB_TOKEN/i, reason: 'Accesses GitHub personal access token' },
  { pattern: /process\.env\.NPM_TOKEN/i, reason: 'Accesses NPM authentication token' },
  { pattern: /process\.env\.GH_TOKEN/i, reason: 'Accesses GitHub token (GH_TOKEN)' },
  { pattern: /axios\.post\s*\(\s*['"`]https?:\/\//i, reason: 'POSTs data to external URL — possible exfiltration' },
  { pattern: /fetch\s*\(\s*['"`]https?:\/\/[^'"`]+['"`]\s*,\s*\{[^}]*method\s*:\s*['"`]POST['"`]/i, reason: 'fetch POST to external endpoint — possible exfiltration' },
  { pattern: /new\s+WebSocket\s*\(\s*['"`]wss?:\/\//i, reason: 'Opens WebSocket to external host — C2 communication pattern' },
  { pattern: /Buffer\.from\s*\(\s*['"`][A-Za-z0-9+/=]{40,}['"`]\s*,\s*['"`]base64['"`]\s*\)/i, reason: 'Large base64 payload — possible obfuscated/encrypted content' },
  // Dynamic code execution via filesystem read — detection pattern
  { pattern: new RegExp('eval\\s*\\(\\s*require\\s*\\(\\s*[\'"`]fs[\'"`]\\s*\\)', 'i'), reason: 'Dynamic code execution from filesystem read — high-risk pattern' },
  { pattern: /execSync\s*\(\s*['"`][^'"`]*(curl|wget|bash|python)[^'"`]*['"`]/i, reason: 'execSync with network/shell command — remote code execution' },
  { pattern: /spawn\s*\(\s*['"`](bash|sh|zsh)['"`]/i, reason: 'Spawns shell process — possible backdoor' },
  { pattern: /os\.homedir\s*\(\s*\)[^;]*\.ssh/i, reason: 'Accesses SSH directory via os.homedir() — SSH key theft' },
  { pattern: /import\s+subprocess[\s\S]{0,200}import\s+socket/im, reason: 'Python: imports subprocess + socket — common reverse shell pattern' },
  { pattern: /socket\.connect\s*\(\s*\(/i, reason: 'Python: socket.connect — possible reverse shell' },
];

/** Sensitive filenames to flag */
const SENSITIVE_FILE_NAMES = [
  { name: '.env', reason: 'Environment variables file — may contain secrets' },
  { name: '.env.local', reason: 'Local environment variables — may contain secrets' },
  { name: '.env.production', reason: 'Production environment variables — likely contains secrets' },
  { name: 'id_rsa', reason: 'SSH RSA private key' },
  { name: 'id_ed25519', reason: 'SSH Ed25519 private key' },
  { name: '.pem', reason: 'PEM certificate/key file' },
  { name: 'credentials', reason: 'Credentials file — may contain secrets' },
  { name: '.netrc', reason: '.netrc file — contains plaintext credentials' },
  { name: 'secrets.json', reason: 'Secrets JSON file — likely contains API keys or credentials' },
  { name: 'keystore.json', reason: 'Keystore file — may contain crypto wallet keys' },
];

/** Well-known safe packages — skip deep analysis */
const TRUSTED_PACKAGES = new Set([
  'express', 'react', 'react-dom', 'next', 'vue', 'nuxt', 'lodash', 'axios',
  'moment', 'dayjs', 'chalk', 'commander', 'typescript', 'webpack', 'vite',
  'rollup', 'esbuild', 'eslint', 'prettier', 'jest', 'mocha', 'vitest',
  'mongoose', 'sequelize', 'prisma', 'typeorm', 'dotenv', 'cors', 'helmet',
  'morgan', 'body-parser', 'jsonwebtoken', 'bcrypt', 'bcryptjs', 'passport',
  'socket.io', 'ws', 'uuid', 'nodemailer', 'multer', 'tailwindcss', 'postcss',
  'autoprefixer', '@types/node', '@types/react', '@types/express', 'ts-node',
  'tsx', 'nodemon', 'concurrently', 'chokidar', 'ora', 'cross-env',
  'rimraf', 'glob', 'minimatch', 'semver', 'debug', 'ms', 'path-to-regexp',
]);

module.exports = {
  KNOWN_MALICIOUS_PACKAGES,
  SUSPICIOUS_PATTERNS,
  SUSPICIOUS_SCRIPT_PATTERNS,
  MALICIOUS_FILE_PATTERNS,
  SENSITIVE_FILE_NAMES,
  TRUSTED_PACKAGES,
};
