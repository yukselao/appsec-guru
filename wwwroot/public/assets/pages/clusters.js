(function ($, WT) {
  'use strict';
  let watchId = null, timer = null, lastActive = null, cur = null, editId = null;
  const esc = WT.esc;
  const logClass = l => /^\$ |^\[api\]/.test(l) ? 'l-DEBUG' : /error|fail|unauthorized|refused/i.test(l) ? 'l-ERROR' : '';
  const live = WT.liveLog('cluster-scans', {modal: '#clLogModal', view: '#clLogView', state: '#clLogState', scroll: '#clLogScroll', title: '#clLogTitle', lineClass: logClass});
  const kind = () => $('input[name=clkind]:checked').val();
  const scoreCls = s => s >= 80 ? 'text-success' : s >= 50 ? 'text-warning' : 'text-danger';
  const stCls = {PASS: 'text-bg-success', FAIL: 'text-bg-danger', WARN: 'text-bg-warning', INFO: 'text-bg-secondary'};
  const empty = m => `<div class="empty px-3">${m}</div>`;

  // ---------------- cluster registration
  function resetForm() { editId = null; $('#clForm')[0].reset(); $('#clNew').addClass('d-none'); $('#clSave').text('Register'); }
  function clusters() {
    return WT.get('/clusters').then(d => {
      const cs = d.clusters || [];
      $('#clCount').text(cs.length);
      $('#clList').html(cs.length ? cs.map(c => `<li class="list-group-item">
        <div class="d-flex align-items-center gap-2">
          <span class="fw-semibold text-truncate" title="${esc(c.context)}">${esc(c.name)}</span>
          <span class="ms-auto"></span>
          <a href="#" class="small" data-cltest="${c.id}">Test</a>
          <a href="#" class="small text-danger" data-cldel="${c.id}">✕</a></div>
        <div class="mono text-body-secondary text-truncate">${esc(c.server)}</div>
        <div class="small d-none" data-clteststate="${c.id}"></div></li>`).join('')
        : '<li class="list-group-item empty">No clusters registered.</li>');
      const opts = cs.map(c => `<option value="${c.id}">${esc(c.name)}</option>`).join('');
      const keep = $('#clPick').val();
      $('#clPick').html(opts || '<option value="">— register a cluster first —</option>');
      if (keep) $('#clPick').val(keep);
      $('#clGo').prop('disabled', !cs.length);
      return cs;
    });
  }

  // ---------------- option forms
  function drawOpts() {
    const k = kind();
    if (k === 'posture') {
      $('#clOpts').html(`<label class="form-label small mb-1">Frameworks</label><div class="d-flex flex-wrap gap-2">
        ${[['nsa', 'NSA', 1], ['mitre', 'MITRE', 1], ['cis-v1.10.0', 'CIS v1.10', 0], ['allcontrols', 'All controls', 0]].map(([v, l, c]) =>
          `<div class="form-check"><input class="form-check-input clFw" type="checkbox" value="${v}" id="clfw-${v}" ${c ? 'checked' : ''}><label class="form-check-label small" for="clfw-${v}">${l}</label></div>`).join('')}</div>`);
    } else if (k === 'node-bench') {
      $('#clOpts').html(`<label class="form-label small mb-1">Benchmark</label>
        <select class="form-select form-select-sm" id="clBench" style="max-width:260px">
          ${['cis-1.9', 'cis-1.10', 'cis-1.8', 'cis-1.7'].map(b => `<option value="${b}">CIS Kubernetes ${b.replace('cis-', 'v')}</option>`).join('')}</select>
        <div class="small text-body-secondary mt-1">Runs kube-bench as a Job on a node and reads its report.</div>`);
    } else {
      $('#clOpts').html('<div class="small text-body-secondary">Lists images of all running workloads; scan any with Trivy.</div>');
    }
  }

  // ---------------- result renderers
  function card(l, n, cls) { return `<div class="col"><div class="card stat-card h-100"><div class="card-body py-2 text-center"><div class="value ${cls || ''}">${n == null ? '—' : n}</div><div class="label small">${l}</div></div></div></div>`; }

  function renderPosture(r) {
    const st = r.stats || {}, by = st.by_severity || {}, score = st.score || 0;
    $('#clCards').html(
      `<div class="col-auto"><div class="card stat-card h-100"><div class="card-body py-2 text-center" style="min-width:110px"><div class="value ${scoreCls(score)}" style="font-size:2rem">${r.status === 'completed' ? score : '—'}</div><div class="label small">Compliance</div></div></div></div>` +
      card('Failed controls', st.failed_controls, 'text-danger') + card('Passed', st.passed_controls, 'text-success') +
      card('Critical', by.Critical, 'text-danger') + card('High', by.High, 'text-warning') +
      card('Resources failed', st.failed_resources));
    const q = ($('#clSearch').val() || '').toLowerCase();
    const rows = ((cur && cur.controls) || []).filter(c => !q || (c.name + ' ' + c.id + ' ' + c.category).toLowerCase().includes(q));
    $('#clResult').html(rows.length ? `<table class="table table-sm table-hover align-middle mb-0">
      <thead class="position-sticky top-0"><tr><th>Severity</th><th>Control</th><th>ID</th><th>Category</th><th>Failed res.</th></tr></thead>
      <tbody>${rows.map(c => `<tr><td>${WT.sevBadge(c.severity)}</td>
        <td class="small"><a href="${esc(c.url)}" target="_blank" rel="noopener">${esc(c.name)}</a></td>
        <td class="mono small">${esc(c.id)}</td><td class="small">${esc(c.category)}</td>
        <td><span class="badge text-bg-light border">${c.failed_resources}</span></td></tr>`).join('')}</tbody></table>`
      : (r.status === 'completed' ? empty('No failed controls. 🎉') : empty('Scanning…')));
  }
  function renderInventory(r) {
    const st = r.stats || {};
    $('#clCards').html(card('Images', st.images) + card('Pods', st.pods) + card('Namespaces', st.namespaces));
    const q = ($('#clSearch').val() || '').toLowerCase();
    const rows = ((cur && cur.images) || []).filter(i => !q || i.image.toLowerCase().includes(q));
    $('#clResult').html(rows.length ? `<table class="table table-sm table-hover align-middle mb-0">
      <thead class="position-sticky top-0"><tr><th>Image</th><th>Pods</th><th>Namespaces</th><th></th></tr></thead>
      <tbody>${rows.map(i => `<tr><td class="mono small">${esc(i.image)}</td>
        <td><span class="badge text-bg-light border">${i.pod_count}</span></td>
        <td class="small">${i.namespaces.map(n => esc(n)).join(', ')}</td>
        <td class="text-end"><button class="btn btn-sm btn-primary py-0" data-clscan="${esc(i.image)}">Scan</button></td></tr>`).join('')}</tbody></table>`
      : (r.status === 'completed' ? empty('No running workloads found.') : empty('Collecting…')));
  }
  function renderNodeBench(r) {
    const st = r.stats || {};
    $('#clCards').html(card('Pass', st.pass, 'text-success') + card('Fail', st.fail, 'text-danger') + card('Warn', st.warn, 'text-warning') +
      card('Total', st.total) + card('Pass rate', st.pass_rate == null ? '—' : st.pass_rate + '%'));
    const q = ($('#clSearch').val() || '').toLowerCase(), fs = '';
    const rows = ((cur && cur.checks) || []).filter(c => !q || ((c.id || '') + ' ' + (c.desc || '')).toLowerCase().includes(q));
    $('#clResult').html(rows.length ? `<table class="table table-sm table-hover align-middle mb-0">
      <thead class="position-sticky top-0"><tr><th>Status</th><th>#</th><th>Check</th><th>Remediation</th></tr></thead>
      <tbody>${rows.map(c => `<tr><td><span class="badge ${stCls[c.status] || 'text-bg-light'}">${esc(c.status)}</span></td>
        <td class="mono small">${esc(c.id)}</td><td class="small">${esc(c.desc)}</td>
        <td class="small text-body-secondary">${c.remediation ? esc(c.remediation.slice(0, 110)) : ''}</td></tr>`).join('')}</tbody></table>`
      : (r.status === 'completed' ? empty('No checks returned.') : empty('Benchmarking the node…')));
  }
  function render(r) {
    cur = r.results || null;
    $('#clState').html(WT.statusBadge(r.status) + (r.active ? ' <span class="spinner-border spinner-border-sm text-primary"></span>' : ''));
    $('#clLabel').text([r.cluster_name, r.kind].filter(Boolean).join(' · '));
    $('#clLogOpen').toggleClass('d-none', !(r.active || r.has_log)).attr('data-cllog', r.id);
    $('#clCancel').prop('disabled', !r.active);
    if (r.error) { $('#clCards').html(`<div class="col-12"><div class="alert alert-danger py-1 mb-0 small">${esc(r.error)}</div></div>`); $('#clResult').html(empty('—')); return; }
    if (r.kind === 'posture') renderPosture(r);
    else if (r.kind === 'image-inventory') renderInventory(r);
    else if (r.kind === 'node-bench') renderNodeBench(r);
  }

  // ---------------- watch / history
  function watch(id) {
    watchId = id; clearInterval(timer);
    const tick = first => WT.get('/cluster-scans/' + id).then(r => {
      if (id !== watchId) return;
      render(r); if (!r.active) clearInterval(timer);
      if (first || r.active !== lastActive || r.active) runs();
      lastActive = r.active;
    }).catch(e => { if (id !== watchId) return; stop(); WT.fail(e, 'Scan #' + id); });
    tick(true); timer = setInterval(tick, 2500);
  }
  function stop() { clearInterval(timer); watchId = null; cur = null; $('#clState,#clCards,#clLabel').empty(); $('#clCancel').prop('disabled', true); $('#clLogOpen').addClass('d-none'); $('#clResult').html(empty('Register a cluster, pick a scan, and Start.')); runs(); }
  function runs() {
    return WT.get('/cluster-scans?limit=200').then(r => {
      $('#clRuns').html(r.runs.length ? r.runs.map(x => { const st = x.stats || {};
        let m = x.kind === 'posture' ? `score ${st.score ?? '—'}, ${st.failed_controls ?? 0} failed` : x.kind === 'node-bench' ? `${st.fail ?? 0} fail · ${st.warn ?? 0} warn` : `${st.images ?? 0} images`;
        return `<li class="list-group-item ${x.id === watchId ? 'active-row' : ''}">
        <div class="d-flex align-items-center gap-2">
          <a href="#" data-clopen="${x.id}">${esc(x.cluster_name || 'cluster')}</a>
          <span class="badge text-bg-light border">${esc(x.kind)}</span>${WT.statusBadge(x.status)}
          ${x.active || x.has_log ? `<a href="#" class="small" data-cllog="${x.id}">Log</a>` : ''}
          <button class="btn btn-sm btn-link text-danger p-0 ms-auto" data-cldelrun="${x.id}" ${x.active ? 'disabled' : ''}>✕</button></div>
        <div class="text-body-secondary">#${x.id} · ${WT.dt(x.created_at)} · ${m}</div></li>`; }).join('')
        : '<li class="list-group-item empty">No cluster scans yet.</li>');
      $('#clRunsCount').text(r.runs.length);
      return r.runs;
    });
  }

  // ---------------- events
  $('#clFile').on('change', function () { const f = this.files[0]; if (!f) return; const rd = new FileReader(); rd.onload = e => { $('#clKube').val(e.target.result); }; rd.readAsText(f); });
  $('#clForm').on('submit', function (e) {
    e.preventDefault();
    const body = {name: $('#clName').val().trim(), kubeconfig: $('#clKube').val()};
    if (!body.kubeconfig.trim()) { WT.warn('Paste a kubeconfig'); return; }
    $('#clSave').prop('disabled', true);
    WT.post('/clusters', body).then(r => { WT.ok('Registered ' + (r.server || '')); resetForm(); clusters(); })
      .catch(e => WT.fail(e)).always(() => $('#clSave').prop('disabled', false));
  });
  $('#clNew').on('click', resetForm);
  $('input[name=clkind]').on('change', drawOpts);
  $('#clSearch').on('input', () => { if (watchId) WT.get('/cluster-scans/' + watchId).then(render); });
  $('#clGo').on('click', function () {
    const cid = $('#clPick').val(); if (!cid) { WT.warn('Pick a cluster'); return; }
    const body = {kind: kind()};
    if (kind() === 'posture') { body.frameworks = $('.clFw:checked').map((i, el) => el.value).get(); if (!body.frameworks.length) { WT.warn('Pick a framework'); return; } }
    if (kind() === 'node-bench') body.benchmark = $('#clBench').val();
    $('#clGo').prop('disabled', true);
    WT.post('/clusters/' + cid + '/scan', body).then(r => { WT.ok('Scan #' + r.run_id + ' started'); watch(r.run_id); })
      .catch(e => WT.fail(e)).always(() => $('#clGo').prop('disabled', false));
  });
  $('#clCancel').on('click', () => { if (watchId) WT.post('/cluster-scans/' + watchId + '/cancel').then(() => WT.ok('Cancel requested')); });

  $(document).on('click', '[data-cltest]', function (e) {
    e.preventDefault(); const id = $(this).data('cltest'); const $s = $(`[data-clteststate="${id}"]`).removeClass('d-none').html('<span class="text-body-secondary">testing…</span>');
    WT.get('/clusters/' + id + '/test').then(r => $s.html(r.ok ? `<span class="text-success">✓ ${esc(r.version || 'connected')} (${esc(r.platform || '')})</span>` : `<span class="text-danger">✕ ${esc(r.error || '')}</span><div class="text-body-secondary">${esc(r.hint || '')}</div>`)).catch(() => $s.html('<span class="text-danger">✕ error</span>'));
  });
  $(document).on('click', '[data-cldel]', function (e) { e.preventDefault(); const id = $(this).data('cldel'); if (!confirm('Delete this cluster registration?')) return; WT.api('DELETE', '/clusters/' + id).then(() => { WT.ok('Deleted'); clusters(); }).catch(e => WT.fail(e)); });
  $(document).on('click', '[data-cllog]', function (e) { e.preventDefault(); live.open(parseInt($(this).data('cllog'), 10), '#' + $(this).data('cllog')); });
  $(document).on('click', '[data-clopen]', function (e) { e.preventDefault(); watch(parseInt($(this).data('clopen'), 10)); });
  $(document).on('click', '[data-cldelrun]', function () { const id = $(this).data('cldelrun'); if (!confirm('Delete scan #' + id + '?')) return; WT.api('DELETE', '/cluster-scans/' + id).then(() => { WT.ok('Deleted'); if (watchId === id) stop(); else runs(); }).catch(e => WT.fail(e)); });
  $(document).on('click', '[data-clscan]', function () { const img = $(this).attr('data-clscan'); if (!watchId) return; WT.post('/cluster-scans/' + watchId + '/scan-image', {image: img}).then(r => { WT.ok('Trivy scan #' + r.run_id + ' started'); setTimeout(() => { window.location.href = '/trivy-scan/' + r.run_id; }, 600); }).catch(e => WT.fail(e)); });

  resetForm(); drawOpts(); clusters(); runs();
})(jQuery, window.WT);
