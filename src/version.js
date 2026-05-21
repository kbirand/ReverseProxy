const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const path = require('node:path');
const fs = require('node:fs');

const execFileP = promisify(execFile);
const REPO_DIR = path.join(__dirname, '..');
const GH_REPO = process.env.UPDATE_REPO || 'kbirand/ReverseProxy';
const GH_BRANCH = process.env.UPDATE_BRANCH || 'main';
const CACHE_MS = 60 * 60 * 1000; // re-check GitHub at most hourly (API rate limit)

let cache = { ts: 0, data: null };

async function git(...args) {
  // -c safe.directory=* — the UI runs as 'rproxy' but the checkout is owned by
  // another user; without this git refuses with "dubious ownership".
  const { stdout } = await execFileP(
    'git', ['-c', 'safe.directory=*', '-C', REPO_DIR, ...args], { timeout: 8000 },
  );
  return stdout.trim();
}

async function localInfo() {
  try {
    const sha = await git('rev-parse', 'HEAD');
    const branch = await git('rev-parse', '--abbrev-ref', 'HEAD');
    let version = null;
    let lastCommit = null;
    try {
      version = JSON.parse(fs.readFileSync(path.join(REPO_DIR, 'package.json'), 'utf8')).version;
    } catch { /* ignore */ }
    try {
      lastCommit = await git('log', '-1', '--format=%cI');
    } catch { /* ignore */ }
    return { git: true, sha, short: sha.slice(0, 7), branch, version, last_commit: lastCommit };
  } catch {
    return { git: false }; // not a git checkout — version check unavailable
  }
}

async function remoteCompare(localSha) {
  const headers = { 'User-Agent': 'rproxy-update-check', Accept: 'application/vnd.github+json' };
  const cmp = await fetch(
    `https://api.github.com/repos/${GH_REPO}/compare/${localSha}...${GH_BRANCH}`,
    { headers, signal: AbortSignal.timeout(8000) },
  );
  if (cmp.status === 404) {
    // local commit isn't on GitHub — just report the latest remote commit.
    const r = await fetch(`https://api.github.com/repos/${GH_REPO}/commits/${GH_BRANCH}`,
      { headers, signal: AbortSignal.timeout(8000) });
    if (!r.ok) throw new Error(`GitHub API ${r.status}`);
    const c = await r.json();
    return {
      unknown_base: true,
      latest: { sha: (c.sha || '').slice(0, 7), message: firstLine(c.commit && c.commit.message) },
    };
  }
  if (!cmp.ok) throw new Error(`GitHub API ${cmp.status}`);
  const d = await cmp.json();
  return {
    status: d.status, // identical | ahead | behind | diverged
    new_commits: d.ahead_by || 0,
    commits: (d.commits || []).slice(-25).reverse().map((c) => ({
      sha: (c.sha || '').slice(0, 7),
      message: firstLine(c.commit && c.commit.message),
      date: c.commit && c.commit.author && c.commit.author.date,
    })),
  };
}

function firstLine(s) {
  return (s || '').split('\n')[0].slice(0, 140);
}

async function checkUpdate(force = false) {
  if (!force && cache.data && Date.now() - cache.ts < CACHE_MS) {
    return { ...cache.data, cached: true };
  }
  const local = await localInfo();
  let remote = null;
  let error = null;
  if (local.git) {
    try { remote = await remoteCompare(local.sha); } catch (e) { error = e.message; }
  } else {
    error = 'not a git checkout';
  }

  let updateAvailable = false;
  if (remote) {
    updateAvailable = remote.unknown_base
      ? remote.latest.sha !== local.short
      : (remote.status === 'ahead' || remote.status === 'diverged');
  }

  const data = {
    repo: GH_REPO,
    branch: GH_BRANCH,
    local,
    remote,
    update_available: updateAvailable,
    error,
    checked_at: Date.now(),
  };
  cache = { ts: Date.now(), data };
  return { ...data, cached: false };
}

module.exports = { checkUpdate, REPO_DIR };
