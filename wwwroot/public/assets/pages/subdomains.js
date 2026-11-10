(function ($, WT) {
  'use strict';
  let watchId = null, timer = null;
  const CODE = s => { s = String(s || ''); return s[0] === '2' ? 'success' : s[0] === '3' ? 'primary' : s === '403' || s === '401' ? 'warning' : s[0] === '5' ? 'dark' : 'secondary'; };

  function stages(stage, status) {
    const steps = [['subfinder', 'Enumerate'], ['dnsx', 'Resolve'], ['httpx', 'Probe HTTP']];
    const done = {subfinder: 1, dnsx: 2, httpx: 3};
    const cur = stage ? done[stage] : (status === 'completed' ? 4 : 0);
    return steps.map((s, i) => `<span class="recon-stage ${i + 1 < cur || status === 'completed' ? 'done' : (stage === s[0] ? 'active' : '')}">${s[1]}</span>`).join('<span class="recon-arrow">→</span>');
  }

  function render(r) {
    $('#sdState').html(WT.statusBadge(r.status) + (r.active ? ' <span class="spinner-border spinner-border-sm text-primary"></span>' : ''));
    $('#sdCancel').prop('disabled', !r.active);
    $('#sdExport').prop('disabled', !(r.results || []).length);
    $('#sdStages').html(stages(r.stage, r.status));
    const st = r.stats || {};
    $('#sdStats').html(
      `<div><span class="badge text-bg-primary">${st.subdomains ?? (r.subdomains || []).length}</span> subdomains</div>` +
      (st.resolved != null ? `<div><span class="badge text-bg-secondary">${st.resolved}</span> resolved</div>` : '') +
      (st.live_http != null ? `<div><span class="badge text-bg-success">${st.live_http}</span> live HTTP</div>` : '') +
      (r.error ? `<div class="w-100"><div class="alert alert-danger py-1 mb-0 small">${WT.esc(r.error)}</div></div>` : ''));
    const q = ($('#sdSearch').val() || '').toLowerCase(), f = $('#sdFilter').val();
    let rows = r.results && r.results.length ? r.results : (r.subdomains || []).map(h => ({host: h}));
    rows = rows.filter(x => (!q || x.host.toLowerCase().includes(q)) && (f !== 'live' || (x.http && x.http.length)) && (f !== 'resolved' || x.resolved));
    $('#sdResults').html(rows.length ? rows.map(x => {
      const http = (x.http || []).map(h => `<a href="${WT.esc(h.url)}" target="_blank" rel="noopener"><span class="badge text-bg-${CODE(h.status)}">${h.status || '?'}</span></a>`).join(' ');
      const tt = (x.http || []).map(h => [h.title, (h.tech || []).join(', ')].filter(Boolean).join(' · ')).filter(Boolean).join(' | ');
      return `<tr><td class="mono">${WT.esc(x.host)}</td>
        <td class="small">${WT.esc((x.a || []).join(', ') || (x.cname || []).join(', ') || '')}</td>
        <td>${http || (x.resolved ? '<span class="text-body-secondary small">no HTTP</span>' : '')}</td>
        <td class="small">${WT.esc(tt)}</td></tr>`;
    }).join('') : `<tr><td colspan="4" class="empty px-3">${r.active ? 'Working…' : 'No subdomains found.'}</td></tr>`);
  }

  function watch(id) { watchId = id; clearInterval(timer); const tick = () => WT.get('/subdomains/' + id).then(r => { render(r); if (!r.active) { clearInterval(timer); runs(); } }); tick(); timer = setInterval(tick, 2500); }
  function runs() {
    WT.get('/subdomains?limit=30').then(r => {
      $('#sdRuns').html(r.runs.length ? r.runs.map(x => `<li class="list-group-item d-flex align-items-center gap-2 ${x.id === watchId ? 'active-row' : ''}">
        <a href="#" data-open="${x.id}" class="text-truncate">${WT.esc(x.domain)}</a>${WT.statusBadge(x.status)}
        <span class="badge text-bg-light border ms-auto">${(x.stats || {}).subdomains ?? 0}</span>
        <button class="btn btn-sm btn-link text-danger p-0" data-del="${x.id}" ${x.active ? 'disabled' : ''}>✕</button></li>`).join('')
        : '<li class="list-group-item empty">No runs yet.</li>');
    });
  }

  $('#sdForm').on('submit', function (e) {
    e.preventDefault();
    const body = {domain: $('#sdDomain').val().trim(), resolve: $('#sdResolve').prop('checked'), probe_http: $('#sdHttp').prop('checked'), timeout: parseInt($('#sdTimeout').val() || '300', 10)};
    if (!body.domain) { WT.warn('Enter a domain'); return; }
    $('#sdGo').prop('disabled', true);
    WT.post('/subdomains', body).then(r => { WT.ok('Discovery #' + r.run_id + ' started'); watch(r.run_id); runs(); }).catch(e => WT.fail(e)).always(() => $('#sdGo').prop('disabled', false));
  });
  $('#sdSearch, #sdFilter').on('input change', () => { if (watchId) WT.get('/subdomains/' + watchId).then(render); });
  $('#sdCancel').on('click', () => { if (watchId) WT.post('/subdomains/' + watchId + '/cancel').then(() => WT.ok('Cancel requested')); });
  $('#sdExport').on('click', () => { if (!watchId) return; WT.get('/subdomains/' + watchId).then(r => {
    const txt = (r.results || []).map(x => [x.host, (x.a || []).join(','), (x.http || []).map(h => h.url + ' [' + h.status + ']').join(' ')].join('\t')).join('\n');
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([txt], {type: 'text/plain'})); a.download = `subdomains-${r.domain}.txt`; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }); });
  $(document).on('click', '[data-open]', function (e) { e.preventDefault(); watch(parseInt($(this).data('open'), 10)); });
  $(document).on('click', '[data-del]', function () { const id = $(this).data('del'); if (!confirm('Delete run #' + id + '?')) return; WT.api('DELETE', '/subdomains/' + id).then(() => { if (watchId === id) { clearInterval(timer); watchId = null; } WT.ok('Deleted'); runs(); }).catch(e => WT.fail(e)); });

  const d = new URLSearchParams(location.search).get('domain'); if (d) $('#sdDomain').val(d);
  runs();
})(jQuery, window.WT);
