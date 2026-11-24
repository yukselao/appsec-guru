(function ($, WT) {
  'use strict';
  let watchId = null, timer = null, lastActive = null;
  const S = {target: ''};
  const SEV_ORDER = {Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4};
  const logClass = l => /^\$ |^\[api\]/.test(l) ? 'l-DEBUG' : /\[(FTL|FATAL|ERR)\]/i.test(l) ? 'l-ERROR' : l.startsWith('{') ? 'l-json' : '';
  const live = WT.liveLog('nuclei', {modal: '#nuLogModal', view: '#nuLogView', state: '#nuLogState', scroll: '#nuLogScroll', title: '#nuLogTitle', lineClass: logClass});
  const url = WT.runUrl('nuclei', id => watch(id), () => stop());

  function render(r) {
    S.target = r.target || '';
    $('#nuState').html(WT.statusBadge(r.status) + (r.active ? ' <span class="spinner-border spinner-border-sm text-primary"></span>' : ''));
    $('#nuLogOpen').toggleClass('d-none', !(r.active || r.has_log)).attr('data-nulog', r.id);
    $('#nuCancel').prop('disabled', !r.active);
    const res = r.results || [];
    $('#nuExport').prop('disabled', !res.length);
    const by = (r.stats || {}).by_severity || {};
    $('#nuStats').html(
      `<div><span class="badge text-bg-primary">${res.length}</span> findings</div>` +
      `<div class="small text-body-secondary">${WT.esc(r.target)}</div>` +
      ['Critical', 'High', 'Medium', 'Low', 'Info'].filter(k => by[k]).map(k => `<div>${WT.sevBadge(k)} ${by[k]}</div>`).join('') +
      (r.error ? `<div class="w-100"><div class="alert alert-danger py-1 mb-0 small">${WT.esc(r.error)}</div></div>` : ''));
    const q = ($('#nuSearch').val() || '').toLowerCase();
    const rows = res.slice().sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9))
      .filter(f => !q || (f.name + ' ' + f.template + ' ' + f.matched_at).toLowerCase().includes(q));
    $('#nuResults').html(rows.length ? rows.map(f => `<tr>
      <td>${WT.sevBadge(f.severity)}</td><td>${WT.esc(f.name) || '<span class="text-body-secondary">—</span>'}</td>
      <td class="mono small">${WT.esc(f.template)}</td>
      <td class="small"><a href="${WT.esc(f.matched_at)}" target="_blank" rel="noopener">${WT.esc(f.matched_at)}</a></td></tr>`).join('')
      : `<tr><td colspan="4" class="empty px-3">${r.active ? 'Scanning…' : (r.status === 'completed' ? 'No findings.' : '—')}</td></tr>`);
  }

  function watch(id) {
    watchId = id; clearInterval(timer);
    const tick = first => WT.get('/nuclei/' + id).then(r => {
      if (id !== watchId) return;
      render(r); if (!r.active) clearInterval(timer);
      if (first || r.active !== lastActive || r.active) runs();
      lastActive = r.active;
    }).catch(e => { if (id !== watchId) return; url.clear(); stop(); WT.fail(e, 'Run #' + id); });
    tick(true); timer = setInterval(tick, 2500);
  }
  function stop() {
    clearInterval(timer); watchId = null;
    $('#nuState, #nuStats').empty(); $('#nuCancel, #nuExport').prop('disabled', true); $('#nuLogOpen').addClass('d-none');
    $('#nuResults').html('<tr><td colspan="4" class="empty px-3">Start a scan or open one from the history.</td></tr>');
    runs();
  }
  function runs() {
    return WT.get('/nuclei?limit=200').then(r => {
      $('#nuRuns').html(r.runs.length ? r.runs.map(x => `<li class="list-group-item ${x.id === watchId ? 'active-row' : ''}">
        <div class="d-flex align-items-center gap-2">
          <a href="/nuclei/${x.id}" data-open="${x.id}" class="text-truncate" title="${WT.esc(x.target)}">${WT.esc(x.target)}</a>${WT.statusBadge(x.status)}
          ${x.active || x.has_log ? `<a href="#" class="small" data-nulog="${x.id}">Log</a>` : ''}
          <button class="btn btn-sm btn-link text-danger p-0 ms-auto" data-del="${x.id}" ${x.active ? 'disabled' : ''}>✕</button></div>
        <div class="text-body-secondary">#${x.id} · ${WT.dt(x.created_at)} · ${x.finished_at || x.active ? WT.dur(x.created_at, x.finished_at) : '-'} · ${x.findings ?? 0} findings</div></li>`).join('')
        : '<li class="list-group-item empty">No scans yet.</li>');
      $('#nuRunsCount').text(r.runs.length);
      return r.runs;
    });
  }

  $('#nuForm').on('submit', function (e) {
    e.preventDefault();
    const body = {target: $('#nuTarget').val().trim(), tags: $('#nuTags').val().trim(),
      severity: $('.nuSev:checked').map((i, el) => el.value).get()};
    if (!body.target) { WT.warn('Enter a target URL'); return; }
    $('#nuGo').prop('disabled', true);
    WT.post('/nuclei', body).then(r => { WT.ok('Scan #' + r.run_id + ' started'); url.push(r.run_id); watch(r.run_id); })
      .catch(e => WT.fail(e)).always(() => $('#nuGo').prop('disabled', false));
  });
  $('#nuSearch').on('input', () => { if (watchId) WT.get('/nuclei/' + watchId).then(render); });
  $('#nuCancel').on('click', () => { if (watchId) WT.post('/nuclei/' + watchId + '/cancel').then(() => WT.ok('Cancel requested')); });
  $('#nuExport').on('click', () => { if (!watchId) return; WT.get('/nuclei/' + watchId).then(r => {
    const txt = (r.results || []).map(f => `${f.severity}\t${f.template}\t${f.matched_at}`).join('\n');
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([txt], {type: 'text/plain'})); a.download = `nuclei-${watchId}.txt`; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }); });
  $(document).on('click', '[data-nulog]', function (e) { e.preventDefault(); live.open(parseInt($(this).data('nulog'), 10), '#' + $(this).data('nulog') + (S.target ? ' · ' + S.target : '')); });
  $(document).on('click', '[data-open]', function (e) { e.preventDefault(); const id = parseInt($(this).data('open'), 10); url.push(id); watch(id); });
  $(document).on('click', '[data-del]', function () { const id = $(this).data('del'); if (!confirm('Delete run #' + id + '?')) return; WT.api('DELETE', '/nuclei/' + id).then(() => { WT.ok('Deleted'); if (watchId === id) { url.clear(); stop(); } else runs(); }).catch(e => WT.fail(e)); });

  const t = new URLSearchParams(location.search).get('target'); if (t) $('#nuTarget').val(t);
  if (url.current()) watch(url.current());
  else runs().then(list => { const on = list.find(x => x.active); if (on && !watchId) watch(on.id); });
})(jQuery, window.WT);
