(function ($, WT) {
  'use strict';
  let watchId = null, timer = null, lastActive = null;
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

  const url = WT.runUrl('subdomains', id => watch(id), () => stop());
  function stop() {
    clearInterval(timer); watchId = null;
    $('#sdState, #sdStats, #sdStages').empty(); $('#sdCancel, #sdExport').prop('disabled', true);
    $('#sdResults').html('<tr><td colspan="4" class="empty px-3">Start a discovery or open one from the history.</td></tr>');
    runs();
  }
  function watch(id) {
    watchId = id; clearInterval(timer);
    const tick = first => WT.get('/subdomains/' + id).then(r => {
      if (id !== watchId) return;
      render(r); if (!r.active) clearInterval(timer);
      if (first || r.active !== lastActive || r.active) runs();
      lastActive = r.active;
    }).catch(e => { if (id !== watchId) return; url.clear(); stop(); WT.fail(e, 'Run #' + id); });
    tick(true); timer = setInterval(tick, 2500);
  }
  function runs() {
    return WT.get('/subdomains?limit=200').then(r => {
      $('#sdRuns').html(r.runs.length ? r.runs.map(x => { const st = x.stats || {};
        return `<li class="list-group-item ${x.id === watchId ? 'active-row' : ''}">
        <div class="d-flex align-items-center gap-2">
          <a href="/subdomains/${x.id}" data-open="${x.id}" class="text-truncate" title="Run #${x.id}">${WT.esc(x.domain)}</a>${WT.statusBadge(x.status)}
          ${x.error ? `<span class="badge text-bg-warning" title="${WT.esc(x.error)}">!</span>` : ''}
          <button class="btn btn-sm btn-link text-danger p-0 ms-auto" data-del="${x.id}" aria-label="Delete run #${x.id}" ${x.active ? 'disabled' : ''}>✕</button></div>
        <div class="text-body-secondary">#${x.id} · ${WT.dt(x.created_at)} · ${x.finished_at || x.active ? WT.dur(x.created_at, x.finished_at) : '-'}</div>
        <div class="text-body-secondary">${st.subdomains ?? 0} found${st.resolved != null ? ` · ${st.resolved} resolved` : ''}${st.live_http != null && (x.options || {}).probe_http ? ` · ${st.live_http} live` : ''}</div></li>`; }).join('')
        : '<li class="list-group-item empty">No runs yet.</li>');
      $('#sdRunsCount').text(r.runs.length);
      return r.runs;
    });
  }

  $('#sdForm').on('submit', function (e) {
    e.preventDefault();
    const body = {domain: $('#sdDomain').val().trim(), resolve: $('#sdResolve').prop('checked'), probe_http: $('#sdHttp').prop('checked'), timeout: parseInt($('#sdTimeout').val(), 10) || null};
    if (!body.domain) { WT.warn('Enter a domain'); return; }
    $('#sdGo').prop('disabled', true);
    WT.post('/subdomains', body).then(r => { WT.ok('Discovery #' + r.run_id + ' started'); url.push(r.run_id); watch(r.run_id); }).catch(e => WT.fail(e)).always(() => $('#sdGo').prop('disabled', false));
  });
  $('#sdSearch, #sdFilter').on('input change', () => { if (watchId) WT.get('/subdomains/' + watchId).then(render); });
  $('#sdCancel').on('click', () => { if (watchId) WT.post('/subdomains/' + watchId + '/cancel').then(() => WT.ok('Cancel requested')); });
  $('#sdExport').on('click', () => { if (!watchId) return; WT.get('/subdomains/' + watchId).then(r => {
    const txt = (r.results || []).map(x => [x.host, (x.a || []).join(','), (x.http || []).map(h => h.url + ' [' + h.status + ']').join(' ')].join('\t')).join('\n');
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([txt], {type: 'text/plain'})); a.download = `subdomains-${r.domain}.txt`; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }); });
  $(document).on('click', '[data-open]', function (e) { e.preventDefault(); const id = parseInt($(this).data('open'), 10); url.push(id); watch(id); });
  $(document).on('click', '[data-del]', function () { const id = $(this).data('del'); if (!confirm('Delete run #' + id + '?')) return; WT.api('DELETE', '/subdomains/' + id).then(() => { WT.ok('Deleted'); if (watchId === id) { url.clear(); stop(); } else runs(); }).catch(e => WT.fail(e)); });

  const d = new URLSearchParams(location.search).get('domain'); if (d) $('#sdDomain').val(d);
  WT.get('/settings').then(r => { $('#sdTimeout').attr('placeholder', r.settings['recon.stage_timeout']); }).catch(() => {});
  // open the run in the address, else the one that is running now
  if (url.current()) watch(url.current());
  else runs().then(list => { const on = list.find(x => x.active); if (on && !watchId) watch(on.id); });
})(jQuery, window.WT);
