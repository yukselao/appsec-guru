(function ($, WT) {
  'use strict';
  let watchId = null, timer = null, lastActive = null;
  const S = {target: ''};
  const TECH_ORDER = 'rbtf';
  const logClass = l => /^\$ |^\[api\]/.test(l) ? 'l-DEBUG' : /\[(CRITICAL|ERROR)\]/.test(l) ? 'l-ERROR' : '';
  const live = WT.liveLog('commix', {modal: '#cxLogModal', view: '#cxLogView', state: '#cxLogState', scroll: '#cxLogScroll', title: '#cxLogTitle', lineClass: logClass});
  const url = WT.runUrl('commix', id => watch(id), () => stop());

  const PROFILES = {
    quick:    {level: 1, timeout: 30, delay: 0, retries: 3, tech: ['r', 'b']},
    standard: {level: 1, timeout: 30, delay: 0, retries: 3, tech: ['r', 'b', 't', 'f']}
  };
  function applyProfile(name) {
    const pf = PROFILES[name]; if (!pf) return;
    $('#cxLevel').val(pf.level); $('#cxTo').val(pf.timeout); $('#cxDelay').val(pf.delay); $('#cxRetries').val(pf.retries);
    $('.cxTech').each(function () { this.checked = pf.tech.includes(this.value); });
    updateCli();
  }

  function technique() { return TECH_ORDER.split('').filter(k => $('.cxTech[value="' + k + '"]').prop('checked')).join(''); }
  function readForm() {
    return {target: $('#cxTarget').val().trim(), data: $('#cxData').val().trim(), cookie: $('#cxCookie').val().trim(),
      headers: $('#cxHeaders').val(), level: $('#cxLevel').val(), technique: technique(),
      timeout: $('#cxTo').val(), delay: $('#cxDelay').val(), retries: $('#cxRetries').val(),
      proxy: $('#cxProxy').val().trim(), flush_session: $('#cxFlush').prop('checked'), profile: $('input[name=cxProfile]:checked').val()};
  }
  const q = v => /[\s'"$;&|<>()]/.test(v) ? "'" + String(v).replace(/'/g, "'\\''") + "'" : v;
  function cliCmd(b) {
    const a = ['commix', '--batch', '-u', q(b.target || '<target>'), '--level', b.level, '--timeout', b.timeout, '--retries', b.retries];
    if (b.data) a.push('--data', q(b.data));
    if (b.cookie) a.push('--cookie', q(b.cookie));
    (b.headers || '').split('\n').map(s => s.trim()).filter(Boolean).forEach(h => a.push('-H', q(h)));
    if (b.technique) a.push('--technique', b.technique);
    if (b.delay && Number(b.delay) > 0) a.push('--delay', b.delay);
    if (b.proxy) a.push('--proxy', b.proxy);
    if (b.flush_session) a.push('--flush-session');
    return a.join(' ');
  }
  function updateCli() { $('#cxCli').text(cliCmd(readForm())); }

  function summary(r) {
    const d = r.results || {}, inj = d.injections || [];
    const head = d.vulnerable
      ? '<span class="badge text-bg-danger">vulnerable</span>'
      : (r.active ? '<span class="badge text-bg-warning">testing…</span>' : (r.status === 'completed' ? '<span class="badge text-bg-success">no injection found</span>' : '<span class="badge text-bg-secondary">—</span>'));
    let h = `<div class="d-flex flex-wrap gap-3 align-items-center mb-3">${head}
      <div class="small text-body-secondary mono">${WT.esc(r.target)}</div>
      ${d.os ? `<div><span class="text-body-secondary small">OS</span> <b>${WT.esc(d.os)}</b></div>` : ''}
      ${d.vulnerable ? '<span class="badge text-bg-light border">CWE-78</span>' : ''}
      <a href="#" class="small ms-auto" data-cxlog="${r.id}">Open live log &#8599;</a></div>`;
    if (r.error) h += `<div class="alert alert-danger py-2 small">${WT.esc(r.error)}</div>`;
    if (inj.length) {
      h += inj.map(p => `<div class="card mb-2"><div class="card-body py-2">
        <div class="mb-1"><span class="fw-semibold mono">${WT.esc(p.parameter)}</span> <span class="badge text-bg-light border">${WT.esc(p.place)}</span> <span class="badge text-bg-dark">${WT.esc(p.type)}</span></div>
        ${p.payload ? `<div class="mono small text-body-secondary text-break">${WT.esc(p.payload)}</div>` : ''}
      </div></div>`).join('');
    }
    if (!inj.length && !r.error) h += `<div class="empty">${r.active ? 'Assessing… open the live log to follow progress.' : (r.status === 'completed' ? 'No command injection detected.' : '—')}</div>`;
    $('#cxSummary').html(h);
  }
  function render(r) {
    S.target = r.target || '';
    $('#cxState').html(WT.statusBadge(r.status) + (r.active ? ' <span class="spinner-border spinner-border-sm text-primary"></span>' : ''));
    $('#cxLogOpen').toggleClass('d-none', !(r.active || r.has_log)).attr('data-cxlog', r.id);
    $('#cxCancel').prop('disabled', !r.active);
    summary(r);
  }
  function watch(id) {
    watchId = id; clearInterval(timer);
    const tick = first => WT.get('/commix/' + id).then(r => {
      if (id !== watchId) return;
      render(r); if (!r.active) clearInterval(timer);
      if (first || r.active !== lastActive || r.active) runs();
      lastActive = r.active;
    }).catch(e => { if (id !== watchId) return; url.clear(); stop(); WT.fail(e, 'Run #' + id); });
    tick(true); timer = setInterval(tick, 2500);
  }
  function stop() {
    clearInterval(timer); watchId = null;
    $('#cxState').empty(); $('#cxCancel').prop('disabled', true); $('#cxLogOpen').addClass('d-none');
    $('#cxSummary').html('<div class="empty">Start an assessment or open one from the history.</div>');
    runs();
  }
  function runs() {
    return WT.get('/commix?limit=200').then(r => {
      $('#cxRuns').html(r.runs.length ? r.runs.map(x => { const vuln = (x.stats || {}).vulnerable;
        return `<li class="list-group-item ${x.id === watchId ? 'active-row' : ''}">
        <div class="d-flex align-items-center gap-2">
          <a href="/commix/${x.id}" data-open="${x.id}" class="text-truncate" title="${WT.esc(x.target)}">${WT.esc(x.target)}</a>${WT.statusBadge(x.status)}
          ${vuln ? '<span class="badge text-bg-danger">vuln</span>' : ''}
          ${x.active || x.has_log ? `<a href="#" class="small" data-cxlog="${x.id}">Log</a>` : ''}
          <button class="btn btn-sm btn-link text-danger p-0 ms-auto" data-del="${x.id}" ${x.active ? 'disabled' : ''}>✕</button></div>
        <div class="text-body-secondary">#${x.id} · ${WT.dt(x.created_at)} · ${x.finished_at || x.active ? WT.dur(x.created_at, x.finished_at) : '-'}</div></li>`; }).join('')
        : '<li class="list-group-item empty">No assessments yet.</li>');
      $('#cxRunsCount').text(r.runs.length);
      return r.runs;
    });
  }

  $(document).on('change', 'input[name=cxProfile]', function () { applyProfile(this.value); });
  $('#cxForm').on('input change', ':input', updateCli);
  $('#cxCopy').on('click', () => { navigator.clipboard.writeText($('#cxCli').text()).then(() => WT.ok('Command copied')); });
  $('#cxForm').on('submit', function (e) {
    e.preventDefault();
    const body = readForm();
    if (!body.target) { WT.warn('Enter a target URL'); return; }
    $('#cxGo').prop('disabled', true);
    WT.post('/commix', body).then(r => { WT.ok('Assessment #' + r.run_id + ' started'); url.push(r.run_id); watch(r.run_id); live.open(r.run_id, '#' + r.run_id); })
      .catch(e => WT.fail(e)).always(() => $('#cxGo').prop('disabled', false));
  });
  $('#cxCancel').on('click', () => { if (watchId) WT.post('/commix/' + watchId + '/cancel').then(() => WT.ok('Cancel requested')); });
  $(document).on('click', '[data-cxlog]', function (e) { e.preventDefault(); live.open(parseInt($(this).data('cxlog'), 10), '#' + $(this).data('cxlog') + (S.target ? ' · ' + S.target : '')); });
  $(document).on('click', '[data-open]', function (e) { e.preventDefault(); const id = parseInt($(this).data('open'), 10); url.push(id); watch(id); });
  $(document).on('click', '[data-del]', function () { const id = $(this).data('del'); if (!confirm('Delete run #' + id + '?')) return; WT.api('DELETE', '/commix/' + id).then(() => { WT.ok('Deleted'); if (watchId === id) { url.clear(); stop(); } else runs(); }).catch(e => WT.fail(e)); });

  const t = new URLSearchParams(location.search).get('target'); if (t) $('#cxTarget').val(t);
  applyProfile('standard'); updateCli();
  if (url.current()) watch(url.current());
  else runs().then(list => { const on = list.find(x => x.active); if (on && !watchId) watch(on.id); });
})(jQuery, window.WT);
