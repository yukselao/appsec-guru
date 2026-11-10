(function ($, WT) {
  'use strict';
  let watchId = null, timer = null;
  const COMMON = {21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
    443: 'https', 445: 'smb', 3000: 'http-alt', 3306: 'mysql', 3389: 'rdp', 5432: 'postgres', 5900: 'vnc',
    6379: 'redis', 8080: 'http-proxy', 8443: 'https-alt', 9200: 'elastic', 27017: 'mongodb'};

  function render(r) {
    $('#psState').html(WT.statusBadge(r.status) + (r.active ? ' <span class="spinner-border spinner-border-sm text-primary"></span>' : ''));
    $('#psCancel').prop('disabled', !r.active);
    const total = (r.results || []).reduce((n, h) => n + h.ports.length, 0);
    $('#psExport').prop('disabled', !total);
    $('#psStats').html(
      `<div><span class="badge text-bg-primary">${total}</span> open ports</div>` +
      `<div class="small text-body-secondary">target ${WT.esc(r.target)}${r.ports ? ' · ports ' + WT.esc(r.ports) : ' · default'}</div>` +
      (r.error ? `<div class="w-100"><div class="alert alert-danger py-1 mb-0 small">${WT.esc(r.error)}</div></div>` : ''));
    if (!(r.results || []).length) {
      $('#psResults').html(`<div class="empty">${r.active ? 'Scanning…' : (r.status === 'completed' ? 'No open ports found (or the target is unreachable from the scanner container).' : '—')}</div>`);
      return;
    }
    $('#psResults').html(r.results.map(h => `<div class="mb-3"><div class="fw-semibold mono mb-2">${WT.esc(h.host)} <span class="text-body-secondary">· ${h.ports.length} open</span></div>
      <div class="d-flex flex-wrap gap-2">${h.ports.map(p => `<span class="badge rounded-pill text-bg-light border port-chip">${p}${COMMON[p] ? ' <span class="text-body-secondary">' + COMMON[p] + '</span>' : ''}</span>`).join('')}</div></div>`).join(''));
  }
  function watch(id) { watchId = id; clearInterval(timer); const tick = () => WT.get('/portscan/' + id).then(r => { render(r); if (!r.active) { clearInterval(timer); runs(); } }); tick(); timer = setInterval(tick, 2000); }
  function runs() {
    WT.get('/portscan?limit=30').then(r => {
      $('#psRuns').html(r.runs.length ? r.runs.map(x => `<li class="list-group-item d-flex align-items-center gap-2 ${x.id === watchId ? 'active-row' : ''}">
        <a href="#" data-open="${x.id}" class="text-truncate">${WT.esc(x.target)}</a>${WT.statusBadge(x.status)}
        <span class="badge text-bg-light border ms-auto">${(x.stats || {}).open_ports ?? 0}</span>
        <button class="btn btn-sm btn-link text-danger p-0" data-del="${x.id}" ${x.active ? 'disabled' : ''}>✕</button></li>`).join('')
        : '<li class="list-group-item empty">No scans yet.</li>');
    });
  }
  $('#psForm').on('submit', function (e) {
    e.preventDefault();
    const body = {target: $('#psTarget').val().trim(), ports: $('#psPorts').val().trim(), full: $('#psFull').prop('checked')};
    if (!body.target) { WT.warn('Enter a target'); return; }
    $('#psGo').prop('disabled', true);
    WT.post('/portscan', body).then(r => { WT.ok('Port scan #' + r.run_id + ' started'); watch(r.run_id); runs(); }).catch(e => WT.fail(e)).always(() => $('#psGo').prop('disabled', false));
  });
  $('#psCancel').on('click', () => { if (watchId) WT.post('/portscan/' + watchId + '/cancel').then(() => WT.ok('Cancel requested')); });
  $('#psExport').on('click', () => { if (!watchId) return; WT.get('/portscan/' + watchId).then(r => {
    const txt = (r.results || []).map(h => h.host + '\t' + h.ports.join(',')).join('\n');
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([txt], {type: 'text/plain'})); a.download = `ports-${r.target}.txt`; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }); });
  $(document).on('click', '[data-open]', function (e) { e.preventDefault(); watch(parseInt($(this).data('open'), 10)); });
  $(document).on('click', '[data-del]', function () { const id = $(this).data('del'); if (!confirm('Delete scan #' + id + '?')) return; WT.api('DELETE', '/portscan/' + id).then(() => { if (watchId === id) { clearInterval(timer); watchId = null; } WT.ok('Deleted'); runs(); }).catch(e => WT.fail(e)); });

  const t = new URLSearchParams(location.search).get('target'); if (t) $('#psTarget').val(t);
  runs();
})(jQuery, window.WT);
