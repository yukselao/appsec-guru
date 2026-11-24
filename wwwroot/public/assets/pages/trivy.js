(function ($, WT) {
  'use strict';
  let watchId = null, timer = null, lastActive = null, tab = 'vuln', cur = null;
  const S = {target: ''};
  const SEV_ORDER = {Critical: 0, High: 1, Medium: 2, Low: 3, Unknown: 4};
  const logClass = l => /^\$ |^\[api\]/.test(l) ? 'l-DEBUG' : /FATAL|failed|error/i.test(l) ? 'l-ERROR' : '';
  const live = WT.liveLog('trivy', {modal: '#tvLogModal', view: '#tvLogView', state: '#tvLogState', scroll: '#tvLogScroll', title: '#tvLogTitle', lineClass: logClass});
  const url = WT.runUrl('trivy-scan', id => watch(id), () => stop());

  const PROFILES = {
    quick:         {scanners: ['vuln'], sev: ['CRITICAL', 'HIGH'], unfixed: true, allpkgs: false},
    full:          {scanners: ['vuln'], sev: [], unfixed: false, allpkgs: false},
    misconfig:     {scanners: ['misconfig'], sev: [], unfixed: false, allpkgs: false},
    secret:        {scanners: ['secret'], sev: [], unfixed: false, allpkgs: false},
    sbom:          {scanners: ['vuln'], sev: [], unfixed: false, allpkgs: true},
    comprehensive: {scanners: ['vuln', 'secret', 'misconfig'], sev: [], unfixed: false, allpkgs: true}
  };
  function applyProfile(name) {
    const pf = PROFILES[name]; if (!pf) { updateCli(); return; }
    $('.tvScan').each(function () { this.checked = pf.scanners.includes(this.value); });
    $('.tvSev').each(function () { this.checked = pf.sev.includes(this.value); });
    $('#tvIgnoreUnfixed').prop('checked', pf.unfixed); $('#tvAllPkgs').prop('checked', pf.allpkgs);
    updateCli();
  }

  function readForm() {
    return {target: $('#tvTarget').val().trim(), profile: $('#tvProfile').val(),
      scanners: $('.tvScan:checked').map((i, el) => el.value).get(),
      severity: $('.tvSev:checked').map((i, el) => el.value).get(),
      ignore_unfixed: $('#tvIgnoreUnfixed').prop('checked'), list_all_pkgs: $('#tvAllPkgs').prop('checked'),
      timeout: $('#tvTo').val()};
  }
  const q = v => /[\s'"$;&|<>()]/.test(v) ? "'" + String(v).replace(/'/g, "'\\''") + "'" : v;
  function cliCmd(b) {
    const a = ['trivy', 'image', q(b.target || '<image>'), '--scanners', (b.scanners.join(',') || 'vuln'), '--timeout', (b.timeout || 10) + 'm'];
    if (b.severity.length && b.severity.length < 5) a.push('--severity', b.severity.join(','));
    if (b.ignore_unfixed) a.push('--ignore-unfixed');
    if (b.list_all_pkgs) a.push('--list-all-pkgs');
    a.push('--format', 'json');
    return a.join(' ');
  }
  function updateCli() { $('#tvCli').text(cliCmd(readForm())); }

  function tableFor(which, res, query) {
    const f = s => !query || JSON.stringify(s).toLowerCase().includes(query);
    if (which === 'vuln') {
      const rows = (res.vulnerabilities || []).slice().sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)).filter(f);
      return rows.length ? `<table class="table table-sm table-hover align-middle mb-0"><thead class="position-sticky top-0"><tr><th>Severity</th><th>CVE</th><th>Package</th><th>Installed</th><th>Fixed</th><th>CVSS</th><th>Title</th></tr></thead><tbody>${rows.map(v => `<tr>
        <td>${WT.sevBadge(v.severity)}</td><td class="mono small"><a href="${WT.esc(v.url)}" target="_blank" rel="noopener">${WT.esc(v.cve)}</a></td>
        <td class="small">${WT.esc(v.pkg)}</td><td class="mono small">${WT.esc(v.installed)}</td>
        <td class="mono small">${v.fixed ? `<span class="text-success">${WT.esc(v.fixed)}</span>` : '<span class="text-body-secondary">—</span>'}</td>
        <td class="small">${WT.esc(v.cvss || '')}</td><td class="small">${WT.esc(v.title)}</td></tr>`).join('')}</tbody></table>` : empty('No vulnerabilities.');
    }
    if (which === 'secret') {
      const rows = (res.secrets || []).filter(f);
      return rows.length ? `<table class="table table-sm table-hover align-middle mb-0"><thead class="position-sticky top-0"><tr><th>Severity</th><th>Category</th><th>Rule</th><th>File</th><th>Line</th></tr></thead><tbody>${rows.map(s => `<tr>
        <td>${WT.sevBadge(s.severity)}</td><td class="small">${WT.esc(s.category)}</td><td class="mono small">${WT.esc(s.rule)}</td>
        <td class="mono small">${WT.esc(s.file)}</td><td class="small">${WT.esc(s.line)}</td></tr>`).join('')}</tbody></table>` : empty('No secrets detected.');
    }
    if (which === 'misconfig') {
      const rows = (res.misconfigurations || []).slice().sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)).filter(f);
      return rows.length ? `<table class="table table-sm table-hover align-middle mb-0"><thead class="position-sticky top-0"><tr><th>Severity</th><th>ID</th><th>Title</th><th>Message</th></tr></thead><tbody>${rows.map(m => `<tr>
        <td>${WT.sevBadge(m.severity)}</td><td class="mono small"><a href="${WT.esc(m.url)}" target="_blank" rel="noopener">${WT.esc(m.id)}</a></td>
        <td class="small">${WT.esc(m.title)}</td><td class="small">${WT.esc(m.message)}</td></tr>`).join('')}</tbody></table>` : empty('No misconfigurations.');
    }
    const rows = (res.packages || []).filter(f);
    return rows.length ? `<table class="table table-sm table-hover align-middle mb-0"><thead class="position-sticky top-0"><tr><th>Package</th><th>Version</th><th>Type</th><th>Licenses</th></tr></thead><tbody>${rows.map(p => `<tr>
      <td class="small">${WT.esc(p.name)}</td><td class="mono small">${WT.esc(p.version)}</td><td class="small">${WT.esc(p.type)}</td>
      <td class="small">${WT.esc((p.licenses || []).join(', '))}</td></tr>`).join('')}</tbody></table>` : empty('No packages (enable Full package inventory).');
  }
  const empty = m => `<div class="empty px-3">${m}</div>`;

  function drawTable() {
    if (!cur) { $('#tvTable').html(empty('—')); return; }
    $('#tvTable').html(tableFor(tab, cur, ($('#tvSearch').val() || '').toLowerCase()));
  }
  function render(r) {
    S.target = r.target || ''; cur = r.results || null;
    $('#tvState').html(WT.statusBadge(r.status) + (r.active ? ' <span class="spinner-border spinner-border-sm text-primary"></span>' : ''));
    $('#tvImage').text(r.target ? r.target + (r.digest ? ' · ' + r.digest.slice(0, 19) : '') : '');
    $('#tvLogOpen').toggleClass('d-none', !(r.active || r.has_log)).attr('data-tvlog', r.id);
    $('#tvCancel').prop('disabled', !r.active);
    const st = r.stats || {}, by = st.by_severity || {};
    $('#tvExport').prop('disabled', !(cur && (st.vulnerabilities || st.secrets || st.misconfigurations || st.packages)));
    const card = (lbl, n, cls) => `<div class="col"><div class="card stat-card h-100"><div class="card-body py-2 text-center"><div class="value ${cls || ''}">${n || 0}</div><div class="label small">${lbl}</div></div></div></div>`;
    $('#tvCards').html(
      ['Critical', 'High', 'Medium', 'Low'].map(k => `<div class="col"><div class="card stat-card h-100"><div class="card-body py-2 text-center"><div class="value">${by[k] || 0}</div><div class="label">${WT.sevBadge(k)}</div></div></div></div>`).join('') +
      card('Fixable', st.fixable, 'text-success') + card('Secrets', st.secrets) + card('Misconfig', st.misconfigurations) +
      (r.error ? `<div class="col-12"><div class="alert alert-danger py-1 mb-0 small">${WT.esc(r.error)}</div></div>` : ''));
    $('#tvcVuln').text(st.vulnerabilities || 0); $('#tvcSecret').text(st.secrets || 0);
    $('#tvcMis').text(st.misconfigurations || 0); $('#tvcPkg').text(st.packages || 0);
    if (!cur && r.active) $('#tvTable').html(empty('Scanning… open the log to follow progress.'));
    else drawTable();
  }

  function watch(id) {
    watchId = id; clearInterval(timer);
    const tick = first => WT.get('/trivy/' + id).then(r => {
      if (id !== watchId) return;
      render(r); if (!r.active) clearInterval(timer);
      if (first || r.active !== lastActive || r.active) runs();
      lastActive = r.active;
    }).catch(e => { if (id !== watchId) return; url.clear(); stop(); WT.fail(e, 'Scan #' + id); });
    tick(true); timer = setInterval(tick, 2500);
  }
  function stop() {
    clearInterval(timer); watchId = null; cur = null;
    $('#tvState, #tvCards, #tvImage').empty(); $('#tvCancel, #tvExport').prop('disabled', true); $('#tvLogOpen').addClass('d-none');
    $('#tvTable').html(empty('Start a scan or open one from the history.'));
    runs();
  }
  function runs() {
    return WT.get('/trivy?limit=200').then(r => {
      $('#tvRuns').html(r.runs.length ? r.runs.map(x => { const st = x.stats || {};
        return `<li class="list-group-item ${x.id === watchId ? 'active-row' : ''}">
        <div class="d-flex align-items-center gap-2">
          <a href="/trivy-scan/${x.id}" data-open="${x.id}" class="text-truncate mono" title="${WT.esc(x.target)}">${WT.esc(x.target)}</a>${WT.statusBadge(x.status)}
          ${x.active || x.has_log ? `<a href="#" class="small" data-tvlog="${x.id}">Log</a>` : ''}
          <button class="btn btn-sm btn-link text-danger p-0 ms-auto" data-del="${x.id}" ${x.active ? 'disabled' : ''}>✕</button></div>
        <div class="text-body-secondary">#${x.id} · ${WT.dt(x.created_at)} · ${st.vulnerabilities ?? 0} vulns${st.secrets ? ' · ' + st.secrets + ' secrets' : ''}${st.misconfigurations ? ' · ' + st.misconfigurations + ' misconfig' : ''}</div></li>`; }).join('')
        : '<li class="list-group-item empty">No scans yet.</li>');
      $('#tvRunsCount').text(r.runs.length);
      return r.runs;
    });
  }

  $('#tvProfile').on('change', function () { applyProfile(this.value); });
  $('#tvForm').on('input change', ':input', updateCli);
  $('#tvCopy').on('click', () => { navigator.clipboard.writeText($('#tvCli').text()).then(() => WT.ok('Command copied')); });
  $('#tvTabs').on('click', '[data-tab]', function () { tab = $(this).data('tab'); $('#tvTabs .nav-link').removeClass('active'); $(this).addClass('active'); drawTable(); });
  $('#tvSearch').on('input', drawTable);
  $('#tvForm').on('submit', function (e) {
    e.preventDefault();
    const body = readForm();
    if (!body.target) { WT.warn('Enter an image reference'); return; }
    $('#tvGo').prop('disabled', true);
    WT.post('/trivy', body).then(r => { WT.ok('Scan #' + r.run_id + ' started'); url.push(r.run_id); watch(r.run_id); })
      .catch(e => WT.fail(e)).always(() => $('#tvGo').prop('disabled', false));
  });
  $('#tvCancel').on('click', () => { if (watchId) WT.post('/trivy/' + watchId + '/cancel').then(() => WT.ok('Cancel requested')); });
  $('#tvExport').on('click', () => { if (!watchId) return; WT.get('/trivy/' + watchId).then(r => {
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([JSON.stringify(r.results, null, 2)], {type: 'application/json'})); a.download = `trivy-${watchId}.json`; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }); });
  $(document).on('click', '[data-tvlog]', function (e) { e.preventDefault(); live.open(parseInt($(this).data('tvlog'), 10), '#' + $(this).data('tvlog') + (S.target ? ' · ' + S.target : '')); });
  $(document).on('click', '[data-open]', function (e) { e.preventDefault(); const id = parseInt($(this).data('open'), 10); url.push(id); watch(id); });
  $(document).on('click', '[data-del]', function () { const id = $(this).data('del'); if (!confirm('Delete scan #' + id + '?')) return; WT.api('DELETE', '/trivy/' + id).then(() => { WT.ok('Deleted'); if (watchId === id) { url.clear(); stop(); } else runs(); }).catch(e => WT.fail(e)); });

  const t = new URLSearchParams(location.search).get('target'); if (t) $('#tvTarget').val(t);
  applyProfile('full'); updateCli();
  if (url.current()) watch(url.current());
  else runs().then(list => { const on = list.find(x => x.active); if (on && !watchId) watch(on.id); });
})(jQuery, window.WT);
