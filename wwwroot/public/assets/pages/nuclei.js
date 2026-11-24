(function ($, WT) {
  'use strict';
  let watchId = null, timer = null, lastActive = null;
  const S = {target: ''};
  const SEV_ORDER = {Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4};
  const CAT_TAGS = {cve: 'cve', misconfig: 'misconfig', exposure: 'exposure', tech: 'tech', ssl: 'ssl',
    headers: 'headers', disclosure: 'disclosure', dns: 'dns', cloud: 'cloud', edb: 'edb', api: 'api'};
  const logClass = l => /^\$ |^\[api\]/.test(l) ? 'l-DEBUG' : /\[(FTL|FATAL|ERR)\]/i.test(l) ? 'l-ERROR' : l.startsWith('{') ? 'l-json' : '';
  const live = WT.liveLog('nuclei', {modal: '#nuLogModal', view: '#nuLogView', state: '#nuLogState', scroll: '#nuLogScroll', title: '#nuLogTitle', lineClass: logClass});
  const url = WT.runUrl('nuclei', id => watch(id), () => stop());

  const PROFILES = {
    quick:         {sev: ['critical', 'high'], cats: ['cve', 'misconfig', 'exposure'], prot: ['http'], as: false, rl: 150, c: 25, bs: 25, to: 10, retries: 1},
    standard:      {sev: ['critical', 'high', 'medium'], cats: ['cve', 'misconfig', 'exposure', 'tech', 'ssl', 'headers'], prot: ['http'], as: false, rl: 150, c: 25, bs: 25, to: 10, retries: 1},
    comprehensive: {sev: [], cats: [], prot: [], as: true, rl: 150, c: 50, bs: 25, to: 10, retries: 1}
  };
  function applyProfile(name) {
    const pf = PROFILES[name]; if (!pf) return;
    $('.nuSev').each(function () { this.checked = pf.sev.includes(this.value); });
    $('.nuCat').each(function () { this.checked = pf.cats.includes(this.value); });
    $('.nuProt').each(function () { this.checked = pf.prot.includes(this.value); });
    $('#nuAs').prop('checked', pf.as); $('#nuRl').val(pf.rl); $('#nuC').val(pf.c); $('#nuBs').val(pf.bs); $('#nuTo').val(pf.to); $('#nuRetries').val(pf.retries);
    updateCli();
  }

  function readForm() {
    const cats = $('.nuCat:checked').map((i, el) => el.value).get();
    const free = $('#nuTags').val().trim();
    const tags = [];
    cats.forEach(c => (CAT_TAGS[c] || '').split(',').forEach(t => { if (t && !tags.includes(t)) tags.push(t); }));
    free.split(',').map(s => s.trim()).filter(Boolean).forEach(t => { if (!tags.includes(t)) tags.push(t); });
    return {target: $('#nuTarget').val().trim(), profile: $('input[name=nuProfile]:checked').val(),
      severity: $('.nuSev:checked').map((i, el) => el.value).get(), categories: cats, tags: free,
      exclude_tags: $('#nuEtags').val().trim(), protocols: $('.nuProt:checked').map((i, el) => el.value).get(),
      automatic_scan: $('#nuAs').prop('checked'), disable_unsigned: $('#nuDut').prop('checked'),
      rate_limit: $('#nuRl').val(), concurrency: $('#nuC').val(), bulk_size: $('#nuBs').val(),
      timeout: $('#nuTo').val(), retries: $('#nuRetries').val(), headers: $('#nuHeaders').val(), _tags: tags};
  }
  const q = v => /[\s'"$;&|<>()]/.test(v) ? "'" + String(v).replace(/'/g, "'\\''") + "'" : v;
  function cliCmd(b) {
    const a = ['nuclei', '-u', q(b.target || '<target>'), '-rl', b.rate_limit, '-timeout', b.timeout,
      '-c', b.concurrency, '-bs', b.bulk_size, '-retries', b.retries, '-duc', '-ni', '-stats', '-stats-interval', '15'];
    if (b.severity.length && b.severity.length < 5) a.push('-s', b.severity.join(','));
    if (b._tags.length) a.push('-tags', b._tags.join(','));
    if (b.exclude_tags) a.push('-etags', b.exclude_tags);
    if (b.protocols.length) a.push('-pt', b.protocols.join(','));
    if (b.automatic_scan) a.push('-as');
    if (b.disable_unsigned) a.push('-dut');
    (b.headers || '').split('\n').map(s => s.trim()).filter(Boolean).forEach(h => a.push('-H', q(h)));
    a.push('-jsonl');
    return a.join(' ');
  }
  function updateCli() { $('#nuCli').text(cliCmd(readForm())); }

  function render(r) {
    S.target = r.target || '';
    $('#nuState').html(WT.statusBadge(r.status) + (r.active ? ' <span class="spinner-border spinner-border-sm text-primary"></span>' : ''));
    $('#nuLogOpen').toggleClass('d-none', !(r.active || r.has_log)).attr('data-nulog', r.id);
    $('#nuCancel').prop('disabled', !r.active);
    const res = r.results || [];
    $('#nuExport').prop('disabled', !res.length);
    const by = (r.stats || {}).by_severity || {};
    const card = (lbl, n, k) => `<div class="col"><div class="card stat-card h-100"><div class="card-body py-2 text-center"><div class="value">${n || 0}</div><div class="label">${WT.sevBadge(lbl)}</div></div></div></div>`;
    $('#nuCards').html(['Critical', 'High', 'Medium', 'Low', 'Info'].map(k => card(k, by[k])).join('') +
      `<div class="col"><div class="card stat-card h-100"><div class="card-body py-2 text-center"><div class="value">${res.length}</div><div class="label small text-body-secondary">Total</div></div></div></div>` +
      (r.error ? `<div class="col-12"><div class="alert alert-danger py-1 mb-0 small">${WT.esc(r.error)}</div></div>` : ''));
    const query = ($('#nuSearch').val() || '').toLowerCase();
    const rows = res.slice().sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9))
      .filter(f => !query || (f.name + ' ' + f.template + ' ' + f.matched_at).toLowerCase().includes(query));
    $('#nuResults').html(rows.length ? rows.map(f => `<tr>
      <td>${WT.sevBadge(f.severity)}</td><td>${WT.esc(f.name) || '<span class="text-body-secondary">—</span>'}</td>
      <td class="mono small">${WT.esc(f.template)}</td><td class="small">${WT.esc(f.type)}</td>
      <td class="small"><a href="${WT.esc(f.matched_at)}" target="_blank" rel="noopener">${WT.esc(f.matched_at)}</a></td></tr>`).join('')
      : `<tr><td colspan="5" class="empty px-3">${r.active ? 'Scanning…' : (r.status === 'completed' ? 'No findings.' : '—')}</td></tr>`);
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
    $('#nuState, #nuCards').empty(); $('#nuCancel, #nuExport').prop('disabled', true); $('#nuLogOpen').addClass('d-none');
    $('#nuResults').html('<tr><td colspan="5" class="empty px-3">Start a scan or open one from the history.</td></tr>');
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

  $(document).on('change', 'input[name=nuProfile]', function () { applyProfile(this.value); });
  $('#nuForm').on('input change', ':input', updateCli);
  $('#nuCopy').on('click', () => { navigator.clipboard.writeText($('#nuCli').text()).then(() => WT.ok('Command copied')); });
  $('#nuForm').on('submit', function (e) {
    e.preventDefault();
    const body = readForm(); delete body._tags;
    if (!body.target) { WT.warn('Enter a target URL'); return; }
    $('#nuGo').prop('disabled', true);
    WT.post('/nuclei', body).then(r => { WT.ok('Scan #' + r.run_id + ' started'); url.push(r.run_id); watch(r.run_id); })
      .catch(e => WT.fail(e)).always(() => $('#nuGo').prop('disabled', false));
  });
  $('#nuSearch').on('input', () => { if (watchId) WT.get('/nuclei/' + watchId).then(render); });
  $('#nuCancel').on('click', () => { if (watchId) WT.post('/nuclei/' + watchId + '/cancel').then(() => WT.ok('Cancel requested')); });
  $('#nuExport').on('click', () => { if (!watchId) return; WT.get('/nuclei/' + watchId).then(r => {
    const txt = (r.results || []).map(f => `${f.severity}\t${f.template}\t${f.type}\t${f.matched_at}`).join('\n');
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([txt], {type: 'text/plain'})); a.download = `nuclei-${watchId}.txt`; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }); });
  $(document).on('click', '[data-nulog]', function (e) { e.preventDefault(); live.open(parseInt($(this).data('nulog'), 10), '#' + $(this).data('nulog') + (S.target ? ' · ' + S.target : '')); });
  $(document).on('click', '[data-open]', function (e) { e.preventDefault(); const id = parseInt($(this).data('open'), 10); url.push(id); watch(id); });
  $(document).on('click', '[data-del]', function () { const id = $(this).data('del'); if (!confirm('Delete run #' + id + '?')) return; WT.api('DELETE', '/nuclei/' + id).then(() => { WT.ok('Deleted'); if (watchId === id) { url.clear(); stop(); } else runs(); }).catch(e => WT.fail(e)); });

  const t = new URLSearchParams(location.search).get('target'); if (t) $('#nuTarget').val(t);
  applyProfile('standard'); updateCli();
  if (url.current()) watch(url.current());
  else runs().then(list => { const on = list.find(x => x.active); if (on && !watchId) watch(on.id); });
})(jQuery, window.WT);
