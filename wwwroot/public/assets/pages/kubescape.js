(function ($, WT) {
  'use strict';
  let watchId = null, timer = null, lastActive = null, cur = null;
  const logClass = l => /^\$ |^\[api\]/.test(l) ? 'l-DEBUG' : /error|fail/i.test(l) ? 'l-ERROR' : '';
  const live = WT.liveLog('kubescape', {modal: '#ksLogModal', view: '#ksLogView', state: '#ksLogState', scroll: '#ksLogScroll', title: '#ksLogTitle', lineClass: logClass});
  const url = WT.runUrl('kubescape', id => watch(id), () => stop());
  const SAMPLE = 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: insecure-demo\n  namespace: default\nspec:\n  hostNetwork: true\n  hostPID: true\n  containers:\n    - name: app\n      image: nginx:latest\n      securityContext:\n        privileged: true\n        runAsUser: 0\n        allowPrivilegeEscalation: true\n';
  const scoreCls = s => s >= 80 ? 'text-success' : s >= 50 ? 'text-warning' : 'text-danger';

  function sizeNote() {
    const b = new Blob([$('#ksManifest').val()]).size;
    $('#ksSize').text(b.toLocaleString() + ' bytes · limit 512 KB').toggleClass('text-danger', b > 512 * 1024);
  }
  function readForm() {
    return {name: $('#ksName').val().trim() || 'manifest', manifest: $('#ksManifest').val(),
      frameworks: $('.ksFw:checked').map((i, el) => el.value).get()};
  }
  const empty = m => `<div class="empty px-3">${m}</div>`;

  function drawTable() {
    if (!cur) { $('#ksTable').html(empty('—')); return; }
    const q = ($('#ksSearch').val() || '').toLowerCase();
    const rows = (cur.controls || []).filter(c => !q || (c.name + ' ' + c.id + ' ' + c.category).toLowerCase().includes(q));
    $('#ksTable').html(rows.length ? `<table class="table table-sm table-hover align-middle mb-0">
      <thead class="position-sticky top-0"><tr><th>Severity</th><th>Control</th><th>ID</th><th>Category</th><th>Failed resources</th></tr></thead>
      <tbody>${rows.map(c => `<tr>
        <td>${WT.sevBadge(c.severity)}</td>
        <td class="small"><a href="${WT.esc(c.url)}" target="_blank" rel="noopener">${WT.esc(c.name)}</a></td>
        <td class="mono small">${WT.esc(c.id)}</td><td class="small">${WT.esc(c.category)}</td>
        <td><span class="badge text-bg-light border">${c.failed_resources}</span></td></tr>`).join('')}</tbody></table>`
      : empty('No failed controls — manifest passed every selected control. 🎉'));
  }
  function render(r) {
    cur = r.results || null;
    const st = r.stats || {}, by = st.by_severity || {}, score = r.score != null ? r.score : (st.score || 0);
    $('#ksState').html(WT.statusBadge(r.status) + (r.active ? ' <span class="spinner-border spinner-border-sm text-primary"></span>' : ''));
    $('#ksLabel').text(r.name || '');
    $('#ksLogOpen').toggleClass('d-none', !(r.active || r.has_log)).attr('data-kslog', r.id);
    $('#ksCancel').prop('disabled', !r.active);
    $('#ksExport').prop('disabled', !cur);
    const gauge = `<div class="col-auto"><div class="card stat-card h-100"><div class="card-body py-2 text-center" style="min-width:110px">
      <div class="value ${scoreCls(score)}" style="font-size:2rem">${r.status === 'completed' ? score : '—'}</div><div class="label small">Compliance score</div></div></div></div>`;
    const card = (l, n, cls) => `<div class="col"><div class="card stat-card h-100"><div class="card-body py-2 text-center"><div class="value ${cls || ''}">${n || 0}</div><div class="label small">${l}</div></div></div></div>`;
    $('#ksTop').html(gauge +
      `<div class="col"><div class="card stat-card h-100"><div class="card-body py-2 text-center"><div class="value">${by.Critical || 0}</div><div class="label">${WT.sevBadge('Critical')}</div></div></div></div>` +
      `<div class="col"><div class="card stat-card h-100"><div class="card-body py-2 text-center"><div class="value">${by.High || 0}</div><div class="label">${WT.sevBadge('High')}</div></div></div></div>` +
      `<div class="col"><div class="card stat-card h-100"><div class="card-body py-2 text-center"><div class="value">${by.Medium || 0}</div><div class="label">${WT.sevBadge('Medium')}</div></div></div></div>` +
      card('Failed controls', st.failed_controls, 'text-danger') + card('Passed', st.passed_controls, 'text-success') +
      card('Resources failed', st.failed_resources) +
      (r.error ? `<div class="col-12"><div class="alert alert-danger py-1 mb-0 small">${WT.esc(r.error)}</div></div>` : ''));
    $('#ksFwRow').html((cur && cur.frameworks || []).map(f => `<span class="badge rounded-pill ${scoreCls(f.score).replace('text-', 'text-bg-')}">${WT.esc(f.name)}: ${f.score}</span>`).join(''));
    if (!cur && r.active) $('#ksTable').html(empty('Scanning… open the log to follow progress.'));
    else drawTable();
  }

  function watch(id) {
    watchId = id; clearInterval(timer);
    const tick = first => WT.get('/kubescape/' + id).then(r => {
      if (id !== watchId) return;
      render(r); if (!r.active) clearInterval(timer);
      if (first || r.active !== lastActive || r.active) runs();
      lastActive = r.active;
    }).catch(e => { if (id !== watchId) return; url.clear(); stop(); WT.fail(e, 'Scan #' + id); });
    tick(true); timer = setInterval(tick, 2500);
  }
  function stop() {
    clearInterval(timer); watchId = null; cur = null;
    $('#ksState, #ksTop, #ksFwRow, #ksLabel').empty(); $('#ksCancel, #ksExport').prop('disabled', true); $('#ksLogOpen').addClass('d-none');
    $('#ksTable').html(empty('Scan a manifest or open one from the history.'));
    runs();
  }
  function runs() {
    return WT.get('/kubescape?limit=200').then(r => {
      $('#ksRuns').html(r.runs.length ? r.runs.map(x => { const st = x.stats || {};
        return `<li class="list-group-item ${x.id === watchId ? 'active-row' : ''}">
        <div class="d-flex align-items-center gap-2">
          <a href="/kubescape/${x.id}" data-open="${x.id}" class="text-truncate" title="${WT.esc(x.name)}">${WT.esc(x.name)}</a>${WT.statusBadge(x.status)}
          ${x.score != null ? `<span class="badge ${x.score >= 80 ? 'text-bg-success' : x.score >= 50 ? 'text-bg-warning' : 'text-bg-danger'}">${x.score}</span>` : ''}
          ${x.active || x.has_log ? `<a href="#" class="small" data-kslog="${x.id}">Log</a>` : ''}
          <button class="btn btn-sm btn-link text-danger p-0 ms-auto" data-del="${x.id}" ${x.active ? 'disabled' : ''}>✕</button></div>
        <div class="text-body-secondary">#${x.id} · ${WT.dt(x.created_at)} · ${st.failed_controls ?? 0} failed controls</div></li>`; }).join('')
        : '<li class="list-group-item empty">No scans yet.</li>');
      $('#ksRunsCount').text(r.runs.length);
      return r.runs;
    });
  }

  $('#ksManifest').on('input', sizeNote);
  $('#ksSample').on('click', () => { $('#ksManifest').val(SAMPLE); sizeNote(); });
  $('#ksFile').on('change', function () { const f = this.files[0]; if (!f) return; const rd = new FileReader(); rd.onload = e => { $('#ksManifest').val(e.target.result); $('#ksName').val(f.name); sizeNote(); }; rd.readAsText(f); });
  $('#ksSearch').on('input', drawTable);
  $('#ksForm').on('submit', function (e) {
    e.preventDefault();
    const body = readForm();
    if (!body.manifest.trim()) { WT.warn('Paste or load a manifest'); return; }
    if (!body.frameworks.length) { WT.warn('Select at least one framework'); return; }
    $('#ksGo').prop('disabled', true);
    WT.post('/kubescape', body).then(r => { WT.ok('Scan #' + r.run_id + ' started'); url.push(r.run_id); watch(r.run_id); })
      .catch(e => WT.fail(e)).always(() => $('#ksGo').prop('disabled', false));
  });
  $('#ksCancel').on('click', () => { if (watchId) WT.post('/kubescape/' + watchId + '/cancel').then(() => WT.ok('Cancel requested')); });
  $('#ksExport').on('click', () => { if (!watchId) return; WT.get('/kubescape/' + watchId).then(r => {
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([JSON.stringify(r.results, null, 2)], {type: 'application/json'})); a.download = `kubescape-${watchId}.json`; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }); });
  $(document).on('click', '[data-kslog]', function (e) { e.preventDefault(); live.open(parseInt($(this).data('kslog'), 10), '#' + $(this).data('kslog')); });
  $(document).on('click', '[data-open]', function (e) { e.preventDefault(); const id = parseInt($(this).data('open'), 10); url.push(id); watch(id); });
  $(document).on('click', '[data-del]', function () { const id = $(this).data('del'); if (!confirm('Delete scan #' + id + '?')) return; WT.api('DELETE', '/kubescape/' + id).then(() => { WT.ok('Deleted'); if (watchId === id) { url.clear(); stop(); } else runs(); }).catch(e => WT.fail(e)); });

  sizeNote();
  if (url.current()) watch(url.current());
  else runs().then(list => { const on = list.find(x => x.active); if (on && !watchId) watch(on.id); });
})(jQuery, window.WT);
