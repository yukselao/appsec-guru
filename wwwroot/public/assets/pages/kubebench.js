(function ($, WT) {
  'use strict';
  let watchId = null, timer = null, lastActive = null, cur = null;
  const logClass = l => /^\$ |^\[api\]/.test(l) ? 'l-DEBUG' : /fail|error|panic/i.test(l) ? 'l-ERROR' : '';
  const live = WT.liveLog('kubebench', {modal: '#kbLogModal', view: '#kbLogView', state: '#kbLogState', scroll: '#kbLogScroll', title: '#kbLogTitle', lineClass: logClass});
  const url = WT.runUrl('kubebench', id => watch(id), () => stop());
  const stCls = {PASS: 'text-bg-success', FAIL: 'text-bg-danger', WARN: 'text-bg-warning', INFO: 'text-bg-secondary'};
  const stBadge = s => `<span class="badge ${stCls[s] || 'text-bg-light'}">${WT.esc(s)}</span>`;

  function readForm() {
    return {benchmark: $('#kbBench').val(), targets: $('.kbT:checked').map((i, el) => el.value).get()};
  }
  function updateCli() { const b = readForm(); $('#kbCli').text('kube-bench run --targets ' + (b.targets.join(',') || 'master,node') + ' --benchmark ' + b.benchmark + ' --json'); }
  const empty = m => `<div class="empty px-3">${m}</div>`;

  function drawTable() {
    if (!cur) { $('#kbTable').html(empty('—')); return; }
    const fs = $('#kbFilter').val(), q = ($('#kbSearch').val() || '').toLowerCase();
    const rows = (cur.checks || []).filter(c => (!fs || c.status === fs) && (!q || (c.id + ' ' + c.desc + ' ' + c.section).toLowerCase().includes(q)));
    $('#kbTable').html(rows.length ? `<table class="table table-sm table-hover align-middle mb-0">
      <thead class="position-sticky top-0"><tr><th>Status</th><th>#</th><th>Node</th><th>Check</th><th>Remediation</th></tr></thead>
      <tbody>${rows.map(c => `<tr>
        <td>${stBadge(c.status)}</td><td class="mono small">${WT.esc(c.id)}</td><td class="small">${WT.esc(c.node)}</td>
        <td class="small">${WT.esc(c.desc)}</td>
        <td class="small text-body-secondary">${c.remediation ? WT.esc(c.remediation.slice(0, 120)) : ''}</td></tr>`).join('')}</tbody></table>`
      : empty('No checks match.'));
  }
  function render(r) {
    cur = r.results || null;
    const st = r.stats || {};
    $('#kbState').html(WT.statusBadge(r.status) + (r.active ? ' <span class="spinner-border spinner-border-sm text-primary"></span>' : ''));
    $('#kbLabel').text([r.benchmark, r.targets].filter(Boolean).join(' · '));
    $('#kbLogOpen').toggleClass('d-none', !(r.active || r.has_log)).attr('data-kblog', r.id);
    $('#kbCancel').prop('disabled', !r.active);
    $('#kbExport').prop('disabled', !cur);
    const card = (l, n, cls) => `<div class="col"><div class="card stat-card h-100"><div class="card-body py-2 text-center"><div class="value ${cls || ''}">${n == null ? '—' : n}</div><div class="label small">${l}</div></div></div></div>`;
    $('#kbCards').html(card('Pass', st.pass, 'text-success') + card('Fail', st.fail, 'text-danger') +
      card('Warn', st.warn, 'text-warning') + card('Info', st.info) + card('Total', st.total) +
      card('Pass rate', st.pass_rate == null ? '—' : st.pass_rate + '%') +
      (r.error ? `<div class="col-12"><div class="alert alert-danger py-1 mb-0 small">${WT.esc(r.error)}</div></div>` : ''));
    if (!cur && r.active) $('#kbTable').html(empty('Running… open the log to follow progress.'));
    else drawTable();
  }

  function watch(id) {
    watchId = id; clearInterval(timer);
    const tick = first => WT.get('/kubebench/' + id).then(r => {
      if (id !== watchId) return;
      render(r); if (!r.active) clearInterval(timer);
      if (first || r.active !== lastActive || r.active) runs();
      lastActive = r.active;
    }).catch(e => { if (id !== watchId) return; url.clear(); stop(); WT.fail(e, 'Run #' + id); });
    tick(true); timer = setInterval(tick, 2500);
  }
  function stop() {
    clearInterval(timer); watchId = null; cur = null;
    $('#kbState, #kbCards, #kbLabel').empty(); $('#kbCancel, #kbExport').prop('disabled', true); $('#kbLogOpen').addClass('d-none');
    $('#kbTable').html(empty('Run a benchmark or open one from the history.'));
    runs();
  }
  function runs() {
    return WT.get('/kubebench?limit=200').then(r => {
      $('#kbRuns').html(r.runs.length ? r.runs.map(x => { const st = x.stats || {};
        return `<li class="list-group-item ${x.id === watchId ? 'active-row' : ''}">
        <div class="d-flex align-items-center gap-2">
          <a href="/kubebench/${x.id}" data-open="${x.id}">${WT.esc(x.benchmark)}</a>${WT.statusBadge(x.status)}
          ${x.active || x.has_log ? `<a href="#" class="small" data-kblog="${x.id}">Log</a>` : ''}
          <button class="btn btn-sm btn-link text-danger p-0 ms-auto" data-del="${x.id}" ${x.active ? 'disabled' : ''}>✕</button></div>
        <div class="text-body-secondary">#${x.id} · ${WT.dt(x.created_at)} · ${st.fail ?? 0} fail · ${st.warn ?? 0} warn</div></li>`; }).join('')
        : '<li class="list-group-item empty">No runs yet.</li>');
      $('#kbRunsCount').text(r.runs.length);
      return r.runs;
    });
  }

  $('#kbForm').on('change', updateCli);
  $('#kbFilter, #kbSearch').on('input change', drawTable);
  $('#kbForm').on('submit', function (e) {
    e.preventDefault();
    const body = readForm();
    if (!body.targets.length) { WT.warn('Select at least one target'); return; }
    $('#kbGo').prop('disabled', true);
    WT.post('/kubebench', body).then(r => { WT.ok('Run #' + r.run_id + ' started'); url.push(r.run_id); watch(r.run_id); })
      .catch(e => WT.fail(e)).always(() => $('#kbGo').prop('disabled', false));
  });
  $('#kbCancel').on('click', () => { if (watchId) WT.post('/kubebench/' + watchId + '/cancel').then(() => WT.ok('Cancel requested')); });
  $('#kbExport').on('click', () => { if (!watchId) return; WT.get('/kubebench/' + watchId).then(r => {
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([JSON.stringify(r.results, null, 2)], {type: 'application/json'})); a.download = `kubebench-${watchId}.json`; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }); });
  $(document).on('click', '[data-kblog]', function (e) { e.preventDefault(); live.open(parseInt($(this).data('kblog'), 10), '#' + $(this).data('kblog')); });
  $(document).on('click', '[data-open]', function (e) { e.preventDefault(); const id = parseInt($(this).data('open'), 10); url.push(id); watch(id); });
  $(document).on('click', '[data-del]', function () { const id = $(this).data('del'); if (!confirm('Delete run #' + id + '?')) return; WT.api('DELETE', '/kubebench/' + id).then(() => { WT.ok('Deleted'); if (watchId === id) { url.clear(); stop(); } else runs(); }).catch(e => WT.fail(e)); });

  updateCli();
  if (url.current()) watch(url.current());
  else runs().then(list => { const on = list.find(x => x.active); if (on && !watchId) watch(on.id); });
})(jQuery, window.WT);
