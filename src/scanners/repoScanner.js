'use strict';

const axios = require('axios');
const { SEVERITY, createFinding, printFinding, printSummary, printHeader } = require('../utils/reporter');

const GITHUB_API = 'https://api.github.com';

const SUSPICIOUS_ACCOUNT_PATTERNS = [
  /^dev-[a-z]{4,8}-\d{2,4}$/i,
  /^recruit-[a-z]+$/i,
  /^hr-[a-z]+-corp$/i,
  /^tech-[a-z]+-hiring$/i,
];

const SUSPICIOUS_TOPICS = [
  'interview', 'assessment', 'take-home',
  'coding-challenge', 'hiring', 'recruitment', 'job-test',
];

const SUSPICIOUS_DESC_PATTERNS = [
  /coding\s+(challenge|test|assessment)/i,
  /take.?home\s+(assignment|test|project)/i,
  /interview\s+(task|project|assignment)/i,
  /hiring\s+(assessment|task)/i,
  /job\s+(application|interview)\s+test/i,
];

const MS_PER_DAY = 24 * 60 * 60 * 1000;

/**
 * Parse a GitHub URL into owner + repo.
 * @param {string} url
 * @returns {{ owner: string, repo: string }}
 */
function parseGitHubUrl(url) {
  const clean = url.replace(/\.git$/, '').replace(/\/$/, '');
  const match = clean.match(/github\.com\/([^/]+)\/([^/]+)/);
  if (!match) throw new Error(`Not a valid GitHub URL: ${url}`);
  return { owner: match[1], repo: match[2] };
}

/**
 * Fetch repo + owner + commits + contents from GitHub API.
 * @param {string} owner
 * @param {string} repo
 * @param {string} [token]
 * @returns {Promise<object>}
 */
async function fetchRepoData(owner, repo, token) {
  const headers = { 'User-Agent': 'beaverguard-scanner/1.0' };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const get = (url) => axios.get(url, { headers, timeout: 8000 });

  const [repoRes, ownerRes, commitsRes, contentsRes] = await Promise.allSettled([
    get(`${GITHUB_API}/repos/${owner}/${repo}`),
    get(`${GITHUB_API}/users/${owner}`),
    get(`${GITHUB_API}/repos/${owner}/${repo}/commits?per_page=5`),
    get(`${GITHUB_API}/repos/${owner}/${repo}/contents`),
  ]);

  return {
    repo: repoRes.status === 'fulfilled' ? repoRes.value.data : null,
    owner: ownerRes.status === 'fulfilled' ? ownerRes.value.data : null,
    commits: commitsRes.status === 'fulfilled' ? commitsRes.value.data : null,
    contents: contentsRes.status === 'fulfilled' ? contentsRes.value.data : null,
  };
}

/**
 * Analyse fetched GitHub repo data for threat indicators.
 * @param {object} data
 * @param {string} owner
 * @param {string} repo
 * @returns {object[]} findings
 */
function analyseRepo(data, owner, repo) {
  const findings = [];
  const now = Date.now();
  const repoTarget = `${owner}/${repo}`;

  // Account checks
  if (data.owner) {
    const acct = data.owner;
    const acctAge = (now - new Date(acct.created_at).getTime()) / MS_PER_DAY;

    if (acctAge < 90) {
      findings.push(createFinding(
        SEVERITY.HIGH,
        'New account',
        owner,
        `Account created ${Math.round(acctAge)} days ago — accounts < 90 days old are high risk.`,
        `Created: ${acct.created_at}`
      ));
    } else if (acct.followers < 5 && acct.public_repos < 3) {
      findings.push(createFinding(
        SEVERITY.MEDIUM,
        'Low-activity account',
        owner,
        `Account has ${acct.followers} followers and ${acct.public_repos} public repos — likely throwaway.`,
        ''
      ));
    }

    for (const pat of SUSPICIOUS_ACCOUNT_PATTERNS) {
      if (pat.test(owner)) {
        findings.push(createFinding(
          SEVERITY.HIGH,
          'Suspicious account name',
          owner,
          `Username matches a pattern associated with fake recruiter accounts: ${pat}`,
          ''
        ));
        break;
      }
    }
  }

  // Repo checks
  if (data.repo) {
    const r = data.repo;
    const repoAge = (now - new Date(r.created_at).getTime()) / MS_PER_DAY;

    if (repoAge < 30) {
      findings.push(createFinding(
        SEVERITY.MEDIUM,
        'New repository',
        repoTarget,
        `Repository created ${Math.round(repoAge)} days ago — very new repos with interview themes are suspicious.`,
        `Created: ${r.created_at}`
      ));
    }

    if (r.description) {
      for (const pat of SUSPICIOUS_DESC_PATTERNS) {
        if (pat.test(r.description)) {
          findings.push(createFinding(
            SEVERITY.HIGH,
            'Suspicious repo description',
            repoTarget,
            `Repository description matches interview/hiring patterns — common social engineering lure.`,
            r.description.substring(0, 120)
          ));
          break;
        }
      }
    }

    const topics = r.topics || [];
    const matchedTopics = topics.filter((t) => SUSPICIOUS_TOPICS.includes(t));
    if (matchedTopics.length > 0) {
      findings.push(createFinding(
        SEVERITY.MEDIUM,
        'Suspicious topics',
        repoTarget,
        `Repository has topics associated with fake interview campaigns.`,
        matchedTopics.join(', ')
      ));
    }

    if (r.stargazers_count === 0 && r.watchers_count === 0 && r.forks_count === 0) {
      findings.push(createFinding(
        SEVERITY.LOW,
        'Zero engagement',
        repoTarget,
        'Repository has zero stars, watchers, and forks — may be newly created for targeted attack.',
        ''
      ));
    }
  }

  // Contents checks
  if (data.contents && Array.isArray(data.contents)) {
    const repoTarget2 = `${owner}/${repo}`;
    const hasPackageJson = data.contents.some((f) => f.name === 'package.json');
    if (hasPackageJson) {
      findings.push(createFinding(
        SEVERITY.INFO,
        'Contains package.json',
        repoTarget2,
        'Repository has a package.json — run beaverguard scan-packages after cloning.',
        ''
      ));
    }

    for (const file of data.contents) {
      // Directories (e.g. bin/, scripts/) are not droppers — files only.
      if (file.type !== 'file') continue;
      const ext = file.name.split('.').pop().toLowerCase();
      const nameLower = file.name.toLowerCase();
      if (['sh', 'py', 'bin'].includes(ext) || nameLower === 'install') {
        findings.push(createFinding(
          SEVERITY.HIGH,
          'Executable file in repo root',
          `${repoTarget2}/${file.name}`,
          `Root-level executable file (${ext}) — common dropper placement.`,
          ''
        ));
      }
      if (nameLower === '.env' || nameLower.startsWith('.env.')) {
        findings.push(createFinding(
          SEVERITY.CRITICAL,
          'Committed .env file',
          `${repoTarget2}/${file.name}`,
          '.env file committed to repository — may contain secrets or be used to deliver malicious env vars.',
          ''
        ));
      }
    }
  }

  // Commit author checks
  if (data.commits && Array.isArray(data.commits)) {
    for (const commit of data.commits) {
      const email = (commit.commit && commit.commit.author && commit.commit.author.email) || '';
      if (/temp|test|fake|hiring/i.test(email)) {
        findings.push(createFinding(
          SEVERITY.MEDIUM,
          'Suspicious commit author',
          repoTarget,
          `Commit author email suggests throwaway account: ${email}`,
          email
        ));
        break;
      }
    }
  }

  return findings;
}

/**
 * Scan a GitHub repository URL for threat indicators.
 * @param {string} repoUrl
 * @param {string} [token]
 * @returns {Promise<{ findings: object[], owner: string, repo: string }>}
 */
async function scanGitHubRepo(repoUrl, token) {
  const { owner, repo } = parseGitHubUrl(repoUrl);
  const t = token || process.env.GITHUB_TOKEN;
  const data = await fetchRepoData(owner, repo, t);
  const findings = analyseRepo(data, owner, repo);
  return { findings, owner, repo };
}

/**
 * Run a full GitHub repo scan and print results.
 * @param {string} repoUrl
 * @param {string} [token]
 * @returns {Promise<object[]>} findings
 */
async function runRepoScan(repoUrl, token) {
  printHeader('GitHub Repo Scanner');
  const { findings, owner, repo } = await scanGitHubRepo(repoUrl, token);
  for (const f of findings) printFinding(f);
  printSummary(`Repo Scanner — ${owner}/${repo}`, findings, 0);
  return findings;
}

module.exports = { parseGitHubUrl, fetchRepoData, analyseRepo, scanGitHubRepo, runRepoScan };
