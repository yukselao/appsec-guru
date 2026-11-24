(function ($, WT) {
  'use strict';
  let watchId = null, timer = null, lastActive = null;
  const S = {target: ''};
  const TECH_ORDER = 'BEUSTQ';
  const logClass = l => /^\$ |^\[api\]/.test(l) ? 'l-DEBUG' : /\[(CRITICAL|ERROR)\]/.test(l) ? 'l-ERROR' : '';
  const live = WT.liveLog('sqlmap', {modal: '#sqLogModal', view: '#sqLogView', state: '#sqLogState', scroll: '#sqLogScroll', title: '#sqLogTitle', lineClass: logClass});
  const url = WT.runUrl('sqlmap', id => watch(id), () => stop());

  const PROFILES = {
    quick:    {level: 1, risk: 1, threads: 1, timeout: 30, delay: 0, retries: 2, tech: ['B', 'E', 'U']},
    standard: {level: 2, risk: 1, threads: 1, timeout: 30, delay: 0, retries: 2, tech: ['B', 'E', 'U', 'T']}
  };
  function applyProfile(name) {
    const pf = PROFILES[name]; if (!pf) return;
    $('#sqLevel').val(pf.level); $('#sqRisk').val(pf.risk); $('#sqThreads').val(pf.threads);
    $('#sqTo').val(pf.timeout); $('#sqDelay').val(pf.delay); $('#sqRetries').val(pf.retries);
    $('.sqTech').each(function () { this.checked = pf.tech.includes(this.value); });
    updateCli();
  }

  function technique() { return TECH_ORDER.split('').filter(k => $('.sqTech[value="' + k + '"]').prop('checked')).join(''); }
  function readForm() {
    return {target: $('#sqTarget').val().trim(), method: $('#sqMethod').val(), data: $('#sqData').val().trim(),
      cookie: $('#sqCookie').val().trim(), headers: $('#sqHeaders').val(),
      auth_type: $('#sqAuthType').val(), auth_cred: $('#sqAuthCred').val().trim(),
      level: $('#sqLevel').val(), risk: $('#sqRisk').val(), dbms: $('#sqDbms').val(), technique: technique(),
      threads: $('#sqThreads').val(), timeout: $('#sqTo').val(), delay: $('#sqDelay').val(), retries: $('#sqRetries').val(),
      proxy: $('#sqProxy').val().trim(), flush_session: $('#sqFlush').prop('checked'), profile: $('input[name=sqProfile]:checked').val()};
  }
  const q = v => /[\s'"$;&|<>()]/.test(v) ? "'" + String(v).replace(/'/g, "'\\''") + "'" : v;
  function cliCmd(b) {
    const a = ['sqlmap', '--batch', '--disable-coloring', '-u', q(b.target || '<target>'),
      '--level', b.level, '--risk', b.risk, '--threads', b.threads, '--timeout', b.timeout, '--retries', b.retries];
    if (b.method && b.method !== 'GET') a.push('--method', b.method);
    if (b.data) a.push('--data', q(b.data));
    if (b.cookie) a.push('--cookie', q(b.cookie));
    (b.headers || '').split('\n').map(s => s.trim()).filter(Boolean).forEach(h => a.push('-H', q(h)));
    if (b.auth_type && b.auth_cred) a.push('--auth-type', b.auth_type, '--auth-cred', q(b.auth_cred));
    if (b.dbms) a.push('--dbms', q(b.dbms));
    if (b.technique) a.push('--technique', b.technique);
    if (b.delay && Number(b.delay) > 0) a.push('--delay', b.delay);
    if (b.proxy) a.push('--proxy', b.proxy);
    if (b.flush_session) a.push('--flush-session');
    return a.join(' ');
  }
  function updateCli() { $('#sqCli').text(cliCmd(readForm())); }

  function summary(r) {
    const d = r.results || {}, inj = d.injections || [];
    const head = d.vulnerable
      ? '<span class="badge text-bg-danger">vulnerable</span>'
      : (r.active ? '<span class="badge text-bg-warning">testing…</span>' : (r.status === 'completed' ? '<span class="badge text-bg-success">no injection found</span>' : '<span class="badge text-bg-secondary">—</span>'));
    let h = `<div class="d-flex flex-wrap gap-3 align-items-center mb-3">${head}
      <div class="small text-body-secondary mono">${WT.esc(r.target)}</div>
      ${d.dbms ? `<div><span class="text-body-secondary small">DBMS</span> <b>${WT.esc(d.dbms)}</b></div>` : ''}
      ${d.vulnerable ? '<span class="badge text-bg-light border">CWE-89</span>' : ''}
      <a href="#" class="small ms-auto" data-sqlog="${r.id}">Open live log &#8599;</a></div>`;
    if (r.error) h += `<div class="alert alert-danger py-2 small">${WT.esc(r.error)}</div>`;
    if (inj.length) {
      h += inj.map(p => `<div class="card mb-2"><div class="card-body py-2">
        <div class="mb-1"><span class="fw-semibold mono">${WT.esc(p.parameter)}</span> <span class="badge text-bg-light border">${WT.esc(p.place)}</span></div>
        ${(p.types || []).map(t => `<div class="small mb-1"><span class="badge text-bg-dark">${WT.esc(t.type)}</span> ${WT.esc(t.title)}${t.payload ? `<div class="mono text-body-secondary text-break">${WT.esc(t.payload)}</div>` : ''}</div>`).join('')}
      </div></div>`).join('');
    }
    if ((d.databases || []).length) {
      h += `<div class="card"><div class="card-header py-2">Databases <span class="badge text-bg-secondary">${d.databases.length}</span></div>
        <div class="card-body py-2 d-flex flex-wrap gap-2">${d.databases.map(x => `<span class="badge rounded-pill text-bg-light border">${WT.esc(x)}</span>`).join('')}</div></div>`;
    }
    if (!inj.length && !r.error) h += `<div class="empty">${r.active ? 'Assessing… open the live log to follow progress.' : (r.status === 'completed' ? 'No SQL injection detected.' : '—')}</div>`;
    $('#sqSummary').html(h);
  }
  function render(r) {
    S.target = r.target || '';
    $('#sqState').html(WT.statusBadge(r.status) + (r.active ? ' <span class="spinner-border spinner-border-sm text-primary"></span>' : ''));
    $('#sqLogOpen').toggleClass('d-none', !(r.active || r.has_log)).attr('data-sqlog', r.id);
    $('#sqCancel').prop('disabled', !r.active);
    summary(r);
  }
  function watch(id) {
    watchId = id; clearInterval(timer);
    const tick = first => WT.get('/sqlmap/' + id).then(r => {
      if (id !== watchId) return;
      render(r); if (!r.active) clearInterval(timer);
      if (first || r.active !== lastActive || r.active) runs();
      lastActive = r.active;
    }).catch(e => { if (id !== watchId) return; url.clear(); stop(); WT.fail(e, 'Run #' + id); });
    tick(true); timer = setInterval(tick, 2500);
  }
  function stop() {
    clearInterval(timer); watchId = null;
    $('#sqState').empty(); $('#sqCancel').prop('disabled', true); $('#sqLogOpen').addClass('d-none');
    $('#sqSummary').html('<div class="empty">Start an assessment or open one from the history.</div>');
    runs();
  }
  function runs() {
    return WT.get('/sqlmap?limit=200').then(r => {
      $('#sqRuns').html(r.runs.length ? r.runs.map(x => { const vuln = (x.stats || {}).vulnerable;
        return `<li class="list-group-item ${x.id === watchId ? 'active-row' : ''}">
        <div class="d-flex align-items-center gap-2">
          <a href="/sqlmap/${x.id}" data-open="${x.id}" class="text-truncate" title="${WT.esc(x.target)}">${WT.esc(x.target)}</a>${WT.statusBadge(x.status)}
          ${vuln ? '<span class="badge text-bg-danger">vuln</span>' : ''}
          ${x.active || x.has_log ? `<a href="#" class="small" data-sqlog="${x.id}">Log</a>` : ''}
          <button class="btn btn-sm btn-link text-danger p-0 ms-auto" data-del="${x.id}" ${x.active ? 'disabled' : ''}>✕</button></div>
        <div class="text-body-secondary">#${x.id} · ${WT.dt(x.created_at)} · ${x.finished_at || x.active ? WT.dur(x.created_at, x.finished_at) : '-'}</div></li>`; }).join('')
        : '<li class="list-group-item empty">No assessments yet.</li>');
      $('#sqRunsCount').text(r.runs.length);
      return r.runs;
    });
  }

  $(document).on('change', 'input[name=sqProfile]', function () { applyProfile(this.value); });
  $('#sqAuthType').on('change', function () { const on = !!this.value; $('#sqAuthCred').prop('disabled', !on); updateCli(); });
  $('#sqForm').on('input change', ':input', updateCli);
  $('#sqCopy').on('click', () => { navigator.clipboard.writeText($('#sqCli').text()).then(() => WT.ok('Command copied')); });
  $('#sqForm').on('submit', function (e) {
    e.preventDefault();
    const body = readForm();
    if (!body.target) { WT.warn('Enter a target URL'); return; }
    $('#sqGo').prop('disabled', true);
    WT.post('/sqlmap', body).then(r => { WT.ok('Assessment #' + r.run_id + ' started'); url.push(r.run_id); watch(r.run_id); live.open(r.run_id, '#' + r.run_id); })
      .catch(e => WT.fail(e)).always(() => $('#sqGo').prop('disabled', false));
  });
  $('#sqCancel').on('click', () => { if (watchId) WT.post('/sqlmap/' + watchId + '/cancel').then(() => WT.ok('Cancel requested')); });
  $(document).on('click', '[data-sqlog]', function (e) { e.preventDefault(); live.open(parseInt($(this).data('sqlog'), 10), '#' + $(this).data('sqlog') + (S.target ? ' · ' + S.target : '')); });
  $(document).on('click', '[data-open]', function (e) { e.preventDefault(); const id = parseInt($(this).data('open'), 10); url.push(id); watch(id); });
  $(document).on('click', '[data-del]', function () { const id = $(this).data('del'); if (!confirm('Delete run #' + id + '?')) return; WT.api('DELETE', '/sqlmap/' + id).then(() => { WT.ok('Deleted'); if (watchId === id) { url.clear(); stop(); } else runs(); }).catch(e => WT.fail(e)); });

  const t = new URLSearchParams(location.search).get('target'); if (t) $('#sqTarget').val(t);
  applyProfile('standard'); updateCli();
  if (url.current()) watch(url.current());
  else runs().then(list => { const on = list.find(x => x.active); if (on && !watchId) watch(on.id); });
})(jQuery, window.WT);
