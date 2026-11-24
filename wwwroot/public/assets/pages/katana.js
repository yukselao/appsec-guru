(function ($, WT) {
  'use strict';
  let watchId = null, timer = null, lastActive = null;
  const S = {target: ''};
  const CODE = s => { s = String(s || ''); return s[0] === '2' ? 'success' : s[0] === '3' ? 'primary' : s === '403' || s === '401' ? 'warning' : s[0] === '5' ? 'dark' : 'secondary'; };
  const logClass = l => /^\$ |^\[api\]/.test(l) ? 'l-DEBUG' : /\[(FTL|FATAL|ERR)\]/i.test(l) ? 'l-ERROR' : l.startsWith('{') ? 'l-json' : '';
  const live = WT.liveLog('katana', {modal: '#kaLogModal', view: '#kaLogView', state: '#kaLogState', scroll: '#kaLogScroll', title: '#kaLogTitle', lineClass: logClass});
  const url = WT.runUrl('katana', id => watch(id), () => stop());

  function render(r) {
    S.target = r.target || '';
    $('#kaState').html(WT.statusBadge(r.status) + (r.active ? ' <span class="spinner-border spinner-border-sm text-primary"></span>' : ''));
    $('#kaLogOpen').toggleClass('d-none', !(r.active || r.has_log)).attr('data-kalog', r.id);
    $('#kaCancel').prop('disabled', !r.active);
    const res = r.results || [];
    $('#kaExport').prop('disabled', !res.length);
    const st = r.stats || {};
    $('#kaStats').html(
      `<div><span class="badge text-bg-primary">${st.urls ?? res.length}</span> endpoints</div>` +
      (st.hosts != null ? `<div><span class="badge text-bg-secondary">${st.hosts}</span> hosts</div>` : '') +
      `<div class="small text-body-secondary">${WT.esc(r.target)}</div>` +
      (r.error ? `<div class="w-100"><div class="alert alert-danger py-1 mb-0 small">${WT.esc(r.error)}</div></div>` : ''));
    const q = ($('#kaSearch').val() || '').toLowerCase();
    const rows = res.filter(u => !q || (u.url || '').toLowerCase().includes(q));
    $('#kaResults').html(rows.length ? rows.map(u => `<tr>
      <td><span class="badge text-bg-light border">${WT.esc(u.method)}</span></td>
      <td class="mono small"><a href="${WT.esc(u.url)}" target="_blank" rel="noopener">${WT.esc(u.url)}</a></td>
      <td>${u.status ? `<span class="badge text-bg-${CODE(u.status)}">${WT.esc(u.status)}</span>` : ''}</td></tr>`).join('')
      : `<tr><td colspan="3" class="empty px-3">${r.active ? 'Crawling…' : (r.status === 'completed' ? 'No endpoints.' : '—')}</td></tr>`);
  }

  function watch(id) {
    watchId = id; clearInterval(timer);
    const tick = first => WT.get('/katana/' + id).then(r => {
      if (id !== watchId) return;
      render(r); if (!r.active) clearInterval(timer);
      if (first || r.active !== lastActive || r.active) runs();
      lastActive = r.active;
    }).catch(e => { if (id !== watchId) return; url.clear(); stop(); WT.fail(e, 'Run #' + id); });
    tick(true); timer = setInterval(tick, 2500);
  }
  function stop() {
    clearInterval(timer); watchId = null;
    $('#kaState, #kaStats').empty(); $('#kaCancel, #kaExport').prop('disabled', true); $('#kaLogOpen').addClass('d-none');
    $('#kaResults').html('<tr><td colspan="3" class="empty px-3">Start a crawl or open one from the history.</td></tr>');
    runs();
  }
  function runs() {
    return WT.get('/katana?limit=200').then(r => {
      $('#kaRuns').html(r.runs.length ? r.runs.map(x => `<li class="list-group-item ${x.id === watchId ? 'active-row' : ''}">
        <div class="d-flex align-items-center gap-2">
          <a href="/katana/${x.id}" data-open="${x.id}" class="text-truncate" title="${WT.esc(x.target)}">${WT.esc(x.target)}</a>${WT.statusBadge(x.status)}
          ${x.active || x.has_log ? `<a href="#" class="small" data-kalog="${x.id}">Log</a>` : ''}
          <button class="btn btn-sm btn-link text-danger p-0 ms-auto" data-del="${x.id}" ${x.active ? 'disabled' : ''}>✕</button></div>
        <div class="text-body-secondary">#${x.id} · ${WT.dt(x.created_at)} · ${x.finished_at || x.active ? WT.dur(x.created_at, x.finished_at) : '-'} · ${x.urls ?? 0} endpoints</div></li>`).join('')
        : '<li class="list-group-item empty">No crawls yet.</li>');
      $('#kaRunsCount').text(r.runs.length);
      return r.runs;
    });
  }

  $('#kaForm').on('submit', function (e) {
    e.preventDefault();
    const body = {target: $('#kaTarget').val().trim(), depth: $('#kaDepth').val().trim(),
      scope: $('#kaScope').val(), known_files: $('#kaKnown').prop('checked'), js_crawl: $('#kaJs').prop('checked')};
    if (!body.target) { WT.warn('Enter a target URL'); return; }
    $('#kaGo').prop('disabled', true);
    WT.post('/katana', body).then(r => { WT.ok('Crawl #' + r.run_id + ' started'); url.push(r.run_id); watch(r.run_id); })
      .catch(e => WT.fail(e)).always(() => $('#kaGo').prop('disabled', false));
  });
  $('#kaSearch').on('input', () => { if (watchId) WT.get('/katana/' + watchId).then(render); });
  $('#kaCancel').on('click', () => { if (watchId) WT.post('/katana/' + watchId + '/cancel').then(() => WT.ok('Cancel requested')); });
  $('#kaExport').on('click', () => { if (!watchId) return; WT.get('/katana/' + watchId).then(r => {
    const txt = (r.results || []).map(u => `${u.method}\t${u.status}\t${u.url}`).join('\n');
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([txt], {type: 'text/plain'})); a.download = `katana-${watchId}.txt`; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }); });
  $(document).on('click', '[data-kalog]', function (e) { e.preventDefault(); live.open(parseInt($(this).data('kalog'), 10), '#' + $(this).data('kalog') + (S.target ? ' · ' + S.target : '')); });
  $(document).on('click', '[data-open]', function (e) { e.preventDefault(); const id = parseInt($(this).data('open'), 10); url.push(id); watch(id); });
  $(document).on('click', '[data-del]', function () { const id = $(this).data('del'); if (!confirm('Delete run #' + id + '?')) return; WT.api('DELETE', '/katana/' + id).then(() => { WT.ok('Deleted'); if (watchId === id) { url.clear(); stop(); } else runs(); }).catch(e => WT.fail(e)); });

  const t = new URLSearchParams(location.search).get('target'); if (t) $('#kaTarget').val(t);
  if (url.current()) watch(url.current());
  else runs().then(list => { const on = list.find(x => x.active); if (on && !watchId) watch(on.id); });
})(jQuery, window.WT);
