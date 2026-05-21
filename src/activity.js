// Suspicion scoring for a per-IP activity rollup row.
//
// Pure function — given the aggregate counts for one client IP, returns the
// flags that tripped and an overall `suspicious` boolean. Kept transparent on
// purpose: the UI shows the flag names so a human can judge.
//
// Row shape (from db.activityRollup): { client_ip, total, first_seen,
// last_seen, c4xx, c5xx, c404, probes, hosts, last_ua }.

const THRESHOLDS = {
  probePaths: 1,      // any hit on a known probe path
  notFound: 20,       // 404s -> path scanning
  errorRatio: 0.6,    // share of 4xx among >= errorMin requests
  errorMin: 15,
  hostSweep: 8,       // distinct hostnames touched
  highVolume: 500,    // requests in the window
};

function scoreActivity(row) {
  const flags = [];
  const total = row.total || 0;

  if ((row.probes || 0) >= THRESHOLDS.probePaths) flags.push('probe-paths');
  if ((row.c404 || 0) >= THRESHOLDS.notFound) flags.push('path-scanning');
  if (total >= THRESHOLDS.errorMin && (row.c4xx || 0) / total > THRESHOLDS.errorRatio) {
    flags.push('high-error-rate');
  }
  if ((row.hosts || 0) >= THRESHOLDS.hostSweep) flags.push('host-sweep');
  if (total >= THRESHOLDS.highVolume) flags.push('high-volume');

  return { flags, suspicious: flags.length > 0 };
}

module.exports = { scoreActivity, THRESHOLDS };
