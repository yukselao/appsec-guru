(function ($, WT) {
  'use strict';
  let watchId = null, timer = null, lastActive = null, cur = null;
  const logClass = l => /^\$ |^\[api\]/.test(l) ? 'l-DEBUG' : /error|fail|fatal/i.test(l) ? 'l-ERROR' : '';
  const live = WT.liveLog('trivyconfig', {modal: '#icLogModal', view: '#icLogView', state: '#icLogState', scroll: '#icLogScroll', title: '#icLogTitle', lineClass: logClass});
  const url = WT.runUrl('iac-scan', id => watch(id), () => stop());
  const SAMPLES = {
    dockerfile: 'FROM ubuntu:latest\nRUN apt-get update && apt-get install -y curl\nADD http://example.com/app.tar /app\nUSER root\nCMD ["/app/run"]\n',
    kubernetes: 'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: nginx:latest\n          securityContext:\n            privileged: true\n            runAsNonRoot: false\n',
    compose: 'services:\n  web:\n    image: nginx:latest\n    privileged: true\n    ports:\n      - "80:80"\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n',
    terraform: 'resource "aws_s3_bucket" "b" {\n  bucket = "demo"\n  acl    = "public-read"\n}\n\nresource "aws_security_group_rule" "all" {\n  type        = "ingress"\n  from_port   = 0\n  to_port     = 0\n  protocol    = "-1"\n  cidr_blocks = ["0.0.0.0/0"]\n}\n'
  };
  const defName = {dockerfile: 'Dockerfile', kubernetes: 'manifest.yaml', compose: 'docker-compose.yml', terraform: 'main.tf'};

  function kind() { return $('.icK:checked').val() || 'dockerfile'; }
  function sizeNote() {
    const b = new Blob([$('#icContent').val()]).size;
    $('#icSize').text(b.toLocaleString() + ' bytes · limit 512 KB').toggleClass('text-danger', b > 512 * 1024);
  }
  const empty = m => `<div class="empty px-3">${m}</div>`;

  function drawTable() {
    if (!cur) { $('#icTable').html(empty('—')); return; }
    const fs = $('#icFilter').val(), q = ($('#icSearch').val() || '').toLowerCase();
    const rows = (cur.findings || []).filter(f => (!fs || f.severity === fs) &&
      (!q || ((f.id || '') + ' ' + (f.title || '') + ' ' + (f.message || '')).toLowerCase().includes(q)));
    $('#icTable').html(rows.length ? `<table class="table table-sm table-hover align-middle mb-0">
      <thead class="position-sticky top-0"><tr><th>Severity</th><th>ID</th><th>Check</th><th>Line</th><th>Resolution</th></tr></thead>
      <tbody>${rows.map(f => `<tr>
        <td>${WT.sevBadge(f.severity)}</td>
        <td class="mono small">${f.url ? `<a href="${WT.esc(f.url)}" target="_blank" rel="noopener">${WT.esc(f.id)}</a>` : WT.esc(f.id)}</td>
        <td class="small"><div>${WT.esc(f.title)}</div>${f.message ? `<div class="text-body-secondary">${WT.esc(f.message)}</div>` : ''}</td>
        <td class="mono small">${f.start_line ? WT.esc('' + f.start_line) : ''}</td>
        <td class="small text-body-secondary">${f.resolution ? WT.esc(f.resolution) : ''}</td></tr>`).join('')}</tbody></table>`
      : empty('No misconfigurations match. 🎉'));
  }
  function render(r) {
    cur = r.results || null;
    const st = r.stats || {}, by = st.by_severity || {};
    $('#icState').html(WT.statusBadge(r.status) + (r.active ? ' <span class="spinner-border spinner-border-sm text-primary"></span>' : ''));
    $('#icLabel').text([r.name, st.detected || r.kind].filter(Boolean).join(' · '));
    $('#icLogOpen').toggleClass('d-none', !(r.active || r.has_log)).attr('data-iclog', r.id);
    $('#icCancel').prop('disabled', !r.active);
    $('#icExport').prop('disabled', !cur);
    const card = (l, n, cls) => `<div class="col"><div class="card stat-card h-100"><div class="card-body py-2 text-center"><div class="value ${cls || ''}">${n == null ? 0 : n}</div><div class="label small">${l}</div></div></div></div>`;
    $('#icCards').html(card('Total', st.total, '') + card('Critical', by.Critical, 'text-danger') + card('High', by.High, 'text-warning') +
      card('Medium', by.Medium) + card('Low', by.Low) +
      (r.error ? `<div class="col-12"><div class="alert alert-danger py-1 mb-0 small">${WT.esc(r.error)}</div></div>` : ''));
    if (!cur && r.active) $('#icTable').html(empty('Scanning… open the log to follow progress.'));
    else drawTable();
  }

  function watch(id) {
    watchId = id; clearInterval(timer);
    const tick = first => WT.get('/trivyconfig/' + id).then(r => {
      if (id !== watchId) return;
      render(r); if (!r.active) clearInterval(timer);
      if (first || r.active !== lastActive || r.active) runs();
      lastActive = r.active;
    }).catch(e => { if (id !== watchId) return; url.clear(); stop(); WT.fail(e, 'Scan #' + id); });
    tick(true); timer = setInterval(tick, 2500);
  }
  function stop() {
    clearInterval(timer); watchId = null; cur = null;
    $('#icState, #icCards, #icLabel').empty(); $('#icCancel, #icExport').prop('disabled', true); $('#icLogOpen').addClass('d-none');
    $('#icTable').html(empty('Scan a configuration or open one from the history.'));
    runs();
  }
  function runs() {
    return WT.get('/trivyconfig?limit=200').then(r => {
      $('#icRuns').html(r.runs.length ? r.runs.map(x => { const st = x.stats || {};
        return `<li class="list-group-item ${x.id === watchId ? 'active-row' : ''}">
        <div class="d-flex align-items-center gap-2">
          <a href="/iac-scan/${x.id}" data-open="${x.id}" class="text-truncate" title="${WT.esc(x.name)}">${WT.esc(x.name)}</a>${WT.statusBadge(x.status)}
          <span class="badge text-bg-light border">${WT.esc(x.kind)}</span>
          ${x.active || x.has_log ? `<a href="#" class="small" data-iclog="${x.id}">Log</a>` : ''}
          <button class="btn btn-sm btn-link text-danger p-0 ms-auto" data-del="${x.id}" ${x.active ? 'disabled' : ''}>✕</button></div>
        <div class="text-body-secondary">#${x.id} · ${WT.dt(x.created_at)} · ${st.total ?? 0} misconfig · ${st.critical ?? 0} crit · ${st.high ?? 0} high</div></li>`; }).join('')
        : '<li class="list-group-item empty">No scans yet.</li>');
      $('#icRunsCount').text(r.runs.length);
      return r.runs;
    });
  }

  $('#icContent').on('input', sizeNote);
  $('.icK').on('change', function () { $('#icName').val(defName[kind()]); });
  $('#icSample').on('click', () => { $('#icContent').val(SAMPLES[kind()]); $('#icName').val(defName[kind()]); sizeNote(); });
  $('#icFile').on('change', function () { const f = this.files[0]; if (!f) return; const rd = new FileReader(); rd.onload = e => { $('#icContent').val(e.target.result); $('#icName').val(f.name); sizeNote(); }; rd.readAsText(f); });
  $('#icFilter, #icSearch').on('input change', drawTable);
  $('#icForm').on('submit', function (e) {
    e.preventDefault();
    const content = $('#icContent').val();
    if (!content.trim()) { WT.warn('Paste or load a configuration'); return; }
    $('#icGo').prop('disabled', true);
    WT.post('/trivyconfig', {kind: kind(), name: $('#icName').val().trim(), content: content})
      .then(r => { WT.ok('Scan #' + r.run_id + ' started'); url.push(r.run_id); watch(r.run_id); })
      .catch(e => WT.fail(e)).always(() => $('#icGo').prop('disabled', false));
  });
  $('#icCancel').on('click', () => { if (watchId) WT.post('/trivyconfig/' + watchId + '/cancel').then(() => WT.ok('Cancel requested')); });
  $('#icExport').on('click', () => { if (!watchId) return; WT.get('/trivyconfig/' + watchId).then(r => {
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([JSON.stringify(r.results, null, 2)], {type: 'application/json'})); a.download = `iac-${watchId}.json`; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }); });
  $(document).on('click', '[data-iclog]', function (e) { e.preventDefault(); live.open(parseInt($(this).data('iclog'), 10), '#' + $(this).data('iclog')); });
  $(document).on('click', '[data-open]', function (e) { e.preventDefault(); const id = parseInt($(this).data('open'), 10); url.push(id); watch(id); });
  $(document).on('click', '[data-del]', function () { const id = $(this).data('del'); if (!confirm('Delete scan #' + id + '?')) return; WT.api('DELETE', '/trivyconfig/' + id).then(() => { WT.ok('Deleted'); if (watchId === id) { url.clear(); stop(); } else runs(); }).catch(e => WT.fail(e)); });

  sizeNote();
  if (url.current()) watch(url.current());
  else runs().then(list => { const on = list.find(x => x.active); if (on && !watchId) watch(on.id); });
})(jQuery, window.WT);
