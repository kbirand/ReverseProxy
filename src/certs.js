const tls = require('node:tls');

function probeCert(hostname, opts = {}) {
  const host = opts.host || '127.0.0.1';
  const port = opts.port || 443;
  const timeoutMs = opts.timeoutMs || 3000;

  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };

    const socket = tls.connect({
      host,
      port,
      servername: hostname,
      rejectUnauthorized: false,
      ALPNProtocols: ['http/1.1'],
    }, () => {
      const cert = socket.getPeerCertificate();
      socket.end();
      if (!cert || !cert.valid_to) {
        finish({ error: 'no_cert' });
        return;
      }
      const notBefore = new Date(cert.valid_from).getTime();
      const notAfter = new Date(cert.valid_to).getTime();
      const now = Date.now();
      const msPerDay = 1000 * 60 * 60 * 24;
      const daysRemaining = Math.floor((notAfter - now) / msPerDay);
      const issuerO = (cert.issuer && cert.issuer.O) || '';
      const issuerCN = (cert.issuer && cert.issuer.CN) || '';
      const issuer = [issuerO, issuerCN].filter(Boolean).join(' · ') || 'unknown';
      finish({
        subject_cn: (cert.subject && cert.subject.CN) || hostname,
        issuer,
        not_before: notBefore,
        not_after: notAfter,
        days_remaining: daysRemaining,
        serial: cert.serialNumber || null,
      });
    });

    socket.setTimeout(timeoutMs);
    socket.on('timeout', () => { socket.destroy(); finish({ error: 'timeout' }); });
    socket.on('error', (e) => { finish({ error: e.code || e.message }); });
  });
}

async function probeAll(rules, opts) {
  const targets = rules.filter((r) => r.enabled && r.tls_mode !== 'http');
  const results = await Promise.all(targets.map(async (rule) => {
    const probe = await probeCert(rule.hostname, opts);
    return { hostname: rule.hostname, tls_mode: rule.tls_mode, rule_id: rule.id, ...probe };
  }));
  return results;
}

module.exports = { probeCert, probeAll };
