(function ($, WT) {
  'use strict';
  const LAST = 7;
  const PRESETS = {
    'auth-inj': ['Authentication & Session', 'Injection'],
    inj: ['Injection'],
    xss: ['Cross Site Scripting', 'HTTP Security Header'],
  };
  const st = {step: 1, policies: [], families: [], policy: null, picked: new Set(), creds: [], reports: [], watch: null};

  // ---- credential + report rows (SC-style) ----
  function credTypeLabel(t) {
    if (t === 'webAuthentication') return 'Web Authentication';
    return String(t || '').replace(/([A-Z])/g, ' $1').replace(/^./, c => c.toUpperCase()).trim();
  }
  function credTypes() { return [...new Set(st.creds.map(c => c.type))]; }
  function fillCredId($row) {
    const t = $row.find('.credType').val();
    const list = st.creds.filter(c => c.type === t);
    $row.find('.credId').html(list.map(c => `<option value="${WT.esc(c.id)}">${WT.esc(c.name)}</option>`).join(''));
  }
  function addCredRow(selType, selId) {
    const types = credTypes();
    if (!types.length) { WT.warn('No credentials defined on Security Center'); return; }
    const $row = $(`<div class="cred-row row g-2 align-items-end mb-2">
      <div class="col-sm-5"><select class="form-select form-select-sm credType">${types.map(t => `<option value="${WT.esc(t)}">${WT.esc(credTypeLabel(t))}</option>`).join('')}</select></div>
      <div class="col-sm-5"><select class="form-select form-select-sm credId"></select></div>
      <div class="col-sm-2"><button type="button" class="btn btn-sm btn-outline-danger w-100 credDel">Remove</button></div></div>`);
    $('#fCreds').append($row);
    if (selType) $row.find('.credType').val(selType);
    fillCredId($row);
    if (selId != null) $row.find('.credId').val(String(selId));
  }
  function collectCreds() { return $('#fCreds .credId').map((i, el) => parseInt(el.value, 10)).get().filter(Boolean); }
  function addReportRow(selId) {
    if (!st.reports.length) { WT.warn('No report definitions on Security Center'); return; }
    const $row = $(`<div class="rep-row row g-2 align-items-end mb-2">
      <div class="col-sm-10"><select class="form-select form-select-sm repId">${st.reports.map(r => `<option value="${WT.esc(r.id)}">${WT.esc(r.name)}</option>`).join('')}</select></div>
      <div class="col-sm-2"><button type="button" class="btn btn-sm btn-outline-danger w-100 repDel">Remove</button></div></div>`);
    $('#fReports').append($row);
    if (selId != null) $row.find('.repId').val(String(selId));
  }
  function collectReports() { return $('#fReports .repId').map((i, el) => parseInt(el.value, 10)).get().filter(Boolean); }

  // ------------------------------------------------------------- navigation
  function go(n) {
    if (n > st.step) { for (let s = st.step; s < n; s++) if (!valid(s)) return; }
    st.step = Math.max(1, Math.min(LAST, n));
    $('.wizard-pane').removeClass('active').filter(`[data-pane="${st.step}"]`).addClass('active');
    $('#wzSteps li').each(function () { const s = $(this).data('step'); $(this).toggleClass('active', s === st.step).toggleClass('done', s < st.step); });
    $('#wzBack').prop('disabled', st.step === 1);
    $('#wzNext').toggleClass('d-none', st.step === LAST);
    $('#wzLaunch').toggleClass('d-none', st.step !== LAST);
    if (st.step === LAST) review();
    window.scrollTo({top: 0, behavior: 'smooth'});
  }
  function valid(s) {
    if (s === 1 && !/^https?:\/\/\S+$/.test($('#fUrl').val().trim())) { WT.warn('Enter a target URL that starts with http:// or https://'); $('#fUrl').focus(); return false; }
    if (s === 2 && !st.policy) { WT.warn('Pick a source policy'); return false; }
    if (s === 4 && scope() === 'custom' && !/^\d{2}:\d{2}:\d{2}$/.test($('#fTimeout').val())) { WT.warn('Time limit must look like 01:00:00'); return false; }
    return true;
  }

  // ----------------------------------------------------------------- state
  const debugMode = () => $('input[name=debug]:checked').val();
  const scope = () => $('input[name=scope]:checked').val();
  function body() {
    const set = $('#fSet').val().split('\n').map(s => s.trim()).filter(Boolean);
    if (scope() === 'custom') set.push('was[scope]page_limit=' + ($('#fPages').val() || 300), 'was_timeout=' + $('#fTimeout').val(),
      'was[plugin][rate_limiter]requests_per_second=' + ($('#fRps').val() || 25));
    return {url: $('#fUrl').val().trim(), name: $('#fName').val().trim(), policy: st.policy ? st.policy.id : null,
      families: [...st.picked], fast: scope() === 'fast', debug: debugMode(), keep: $('#fKeep').prop('checked'),
      repo: $('#fRepo').val() ? parseInt($('#fRepo').val(), 10) : null, zone: $('#fZone').val() ? parseInt($('#fZone').val(), 10) : null,
      credentials: collectCreds(), reports: collectReports(),
      max_scan_time: $('#fMaxTime').val(), inactivity_hours: parseInt($('#fInactivity').val(), 10),
      remove_unresponsive: $('#fRemoveUnresp').prop('checked'),
      sensor_id: $('#fSensor').val() || null, set};
  }
  function famNames(ids) { return (ids || []).map(id => (st.families.find(f => f.id === id) || {}).name || id); }
  function summary() {
    const b = body();
    const fam = b.families.length ? b.families.join(', ') : (st.policy ? famNames(st.policy.families).join(', ') + ' (policy)' : '–');
    const rows = [['Target', b.url || '–'], ['Policy', st.policy ? st.policy.id + ' · ' + st.policy.name : '–'], ['Families', fam],
      ['Debug', {both: 'full', host: 'scanner log', sc: 'policy', none: 'off'}[b.debug]], ['Scope', {fast: 'fast', policy: 'policy limits', custom: 'custom'}[scope()]]];
    $('#wzSummary').html(rows.map(([k, v]) => `<li class="list-group-item"><div class="text-body-secondary">${k}</div><div class="fw-semibold text-break">${WT.esc(v)}</div></li>`).join(''));
  }

  // ---------------------------------------------------------------- step 1
  function renderApps() {
    const host = $('#fLabHost').val().trim() || '192.168.1.82';
    $('#appPick').html((window.WT_TESTAPPS || []).map(a => {
      const url = `http://${host}:${a.port}${a.path === '/' ? '' : a.path}`;
      return `<div class="col"><button type="button" class="card h-100 w-100 text-start app-pick" data-url="${WT.esc(url)}"><div class="card-body py-2">
        <div class="fw-semibold">${WT.esc(a.name)}</div><div class="small mono text-body-secondary">${WT.esc(url)}</div>
        <div class="mt-1">${a.tags.slice(0, 3).map(t => `<span class="badge text-bg-light border me-1">${WT.esc(t)}</span>`).join('')}</div></div></button></div>`;
    }).join(''));
  }
  $('#appPick').on('click', '.app-pick', function () { $('#fUrl').val($(this).data('url')).trigger('input'); WT.toast('Target set to ' + $(this).data('url')); });
  $('#fLabHost').on('input', () => { try { localStorage.setItem('wt-labhost', $('#fLabHost').val()); } catch (e) { /* ignore */ } renderApps(); });
  $('#btnReach').on('click', function () {
    const url = $('#fUrl').val().trim();
    if (!/^https?:\/\//.test(url)) { WT.warn('Enter a URL first'); return; }
    const $b = $(this).prop('disabled', true);
    $('#reachOut').html('<span class="text-body-secondary">Testing from the scanner…</span>');
    WT.post('/scanner/reach', {url}).then(r => {
      $('#reachOut').html(r.reachable
        ? `<span class="text-success">✓ Reachable from ${WT.esc(r.from)}: HTTP ${WT.esc(r.http_code)} in ${r.seconds}s (${WT.esc(r.ip)})</span>`
        : `<span class="text-danger">× Not reachable from ${WT.esc(r.from)}. ${WT.esc(r.error)}</span>`);
      r.reachable ? WT.ok('The scanner reaches the target (HTTP ' + r.http_code + ')') : WT.fail('The scanner cannot reach the target');
    }).catch(e => { $('#reachOut').empty(); WT.fail(e); }).always(() => $b.prop('disabled', false));
  });

  // ---------------------------------------------------------------- step 2
  function renderPolicies() {
    $('#polCards').html(st.policies.map(p => `<div class="col"><button type="button" class="card h-100 w-100 text-start pol-card ${st.policy && st.policy.id === p.id ? 'border-primary border-2' : ''}" data-id="${WT.esc(p.id)}">
      <div class="card-body"><div class="d-flex"><span class="fw-semibold">${WT.esc(p.name)}</span><span class="ms-auto small text-body-secondary">#${WT.esc(p.id)}</span></div>
      <div class="small text-body-secondary mb-2">modified ${WT.esc(p.modified)}${p.description ? ' · ' + WT.esc(p.description) : ''}</div>
      <div>${(p.families || []).length === st.families.length && st.families.length ? '<span class="badge text-bg-success">all families</span>'
        : famNames(p.families).map(n => `<span class="badge text-bg-success me-1 mb-1">${WT.esc(n)}</span>`).join('') || '<span class="badge text-bg-light border">no families</span>'}</div>
      <div class="small text-body-secondary mt-2">pages ${WT.esc((p.prefs || {})['was[scope]page_limit'] || '–')} · time ${WT.esc((p.prefs || {}).was_timeout || '–')} · debug ${WT.esc((p.prefs || {}).was_debug_mode || '–')}</div>
      </div></button></div>`).join('') || '<div class="empty">No WAS policies found.</div>');
    $('#polMatrix').html(`<thead><tr><th>Family</th>${st.policies.map(p => `<th class="text-center small">${WT.esc(p.name)}<div class="text-body-secondary fw-normal">#${WT.esc(p.id)}</div></th>`).join('')}</tr></thead>
      <tbody>${st.families.map(f => `<tr><td>${WT.esc(f.name)}</td>${st.policies.map(p => `<td class="text-center">${(p.families || []).includes(f.id) ? '<span class="text-success fw-bold">●</span>' : '<span class="text-body-tertiary">○</span>'}</td>`).join('')}</tr>`).join('')}</tbody>`);
  }
  function selectPolicy(id) {
    st.policy = st.policies.find(p => String(p.id) === String(id)) || null;
    renderPolicies();
    const p = st.policy;
    $('#polDetail').html(p ? `<div class="fw-semibold mb-2">${WT.esc(p.id)} · ${WT.esc(p.name)}</div><table class="table table-sm mb-0">
      ${Object.entries(p.prefs || {}).map(([k, v]) => `<tr><td class="mono">${WT.esc(k)}</td><td>${WT.esc(v)}</td></tr>`).join('')}</table>` : '');
    renderFamilies();
    summary();
  }
  $('#polCards').on('click', '.pol-card', function () { selectPolicy($(this).data('id')); WT.toast('Policy ' + st.policy.name + ' selected'); });

  // ---------------------------------------------------------------- step 3
  function renderFamilies() {
    const inPolicy = new Set(st.policy ? st.policy.families : []);
    $('#famCards').html(st.families.map(f => {
      const on = st.picked.has(f.name);
      return `<div class="col"><label class="card h-100 fam-card ${on ? 'border-success border-2' : ''}"><div class="card-body py-2 d-flex gap-2 align-items-start">
        <input class="form-check-input mt-1" type="checkbox" value="${WT.esc(f.name)}" ${on ? 'checked' : ''}>
        <div><div class="fw-semibold">${WT.esc(f.name)}</div><div class="small text-body-secondary">#${f.id}${inPolicy.has(f.id) ? ' · in the policy' : ''}</div></div></div></label></div>`;
    }).join(''));
    $('#famNote').text(st.picked.size ? `${st.picked.size} families selected. The scan runs with a copy of the policy that has only these.`
      : 'No family selected: the policy families run.');
  }
  $('#famCards').on('change', 'input', function () { this.checked ? st.picked.add(this.value) : st.picked.delete(this.value); renderFamilies(); summary(); });
  $('[data-preset]').on('click', function () {
    const k = $(this).data('preset');
    if (k === 'none' || k === 'policy') st.picked = new Set();
    else if (k === 'all') st.picked = new Set(st.families.map(f => f.name));
    else st.picked = new Set(PRESETS[k]);
    renderFamilies(); summary();
  });

  // ---------------------------------------------------------------- step 4
  $('input[name=scope]').on('change', () => { $('#customScope').toggleClass('d-none', scope() !== 'custom'); summary(); });
  $('input[name=debug]').on('change', summary);

  // ---------------------------------------------------------------- step 5
  function review() {
    const b = body();
    const debug = {none: 'off', sc: 'policy (was_debug_mode)', host: 'scanner host (service restarts)', both: 'policy and scanner host'}[b.debug];
    $('#wzReview').html(`<table class="table table-sm align-middle mb-0"><tbody>
      <tr><th class="w-25">Target</th><td>${WT.esc(b.url)}</td></tr>
      <tr><th>Scan name</th><td>${WT.esc(b.name || 'automatic')}</td></tr>
      <tr><th>Source policy</th><td>${WT.esc(st.policy.id)} · ${WT.esc(st.policy.name)}</td></tr>
      <tr><th>Plugin families</th><td>${b.families.length ? b.families.map(f => `<span class="badge text-bg-success me-1">${WT.esc(f)}</span>`).join('') : 'as in the policy'}</td></tr>
      <tr><th>Debug</th><td>${WT.esc(debug)}</td></tr>
      <tr><th>Scope</th><td>${{fast: 'fast (150 pages, 45 min)', policy: 'policy limits', custom: 'custom'}[scope()]}</td></tr>
      <tr><th>Keep on Security Center</th><td>${b.keep ? 'yes' : 'no, delete the scan and the copied policy at the end'}</td></tr>
      <tr><th>Max scan duration</th><td>${b.max_scan_time === 'unlimited' ? 'unlimited' : WT.esc(b.max_scan_time) + ' h'} · inactivity ${WT.esc(b.inactivity_hours)} h</td></tr>
      ${b.credentials.length ? `<tr><th>Credentials</th><td>${b.credentials.map(id => `<span class="badge text-bg-light border me-1">${WT.esc((st.creds.find(c => String(c.id) === String(id)) || {}).name || id)}</span>`).join('')}</td></tr>` : ''}
      ${b.reports.length ? `<tr><th>Reports on completion</th><td>${b.reports.map(id => `<span class="badge text-bg-light border me-1">${WT.esc((st.reports.find(r => String(r.id) === String(id)) || {}).name || id)}</span>`).join('')}</td></tr>` : ''}
      ${b.set.length ? `<tr><th>Policy preferences</th><td class="mono small">${b.set.map(WT.esc).join('<br>')}</td></tr>` : ''}
    </tbody></table>`);
  }
  function follow(runId) {
    clearInterval(st.watch);
    let lastStatus = '';
    const draw = () => WT.get('/scans/' + runId).then(x => {
      if (x.status !== lastStatus) { if (lastStatus) WT.toast(`Run #${x.id}: ${x.status}`, x.status === 'failed' ? 'danger' : 'info'); lastStatus = x.status; }
      $('#wzLaunched').html(`<div class="card border-${x.active ? 'primary' : (x.status === 'completed' ? 'success' : 'secondary')}"><div class="card-body">
        <div class="d-flex flex-wrap align-items-center gap-2"><strong>Run #${x.id}</strong> ${WT.statusBadge(x.status)}
          <span class="small text-body-secondary">SC result ${WT.esc(x.sc_result_id || '–')} · scanner ${x.scan_uuid ? WT.esc(x.scan_uuid.slice(0, 8)) : 'waiting'}</span>
          <span class="ms-auto d-flex gap-2">${x.scan_uuid && x.active ? `<a class="btn btn-sm btn-primary" href="/logs?uuid=${encodeURIComponent(x.scan_uuid)}">Open live log</a>` : ''}
          <a class="btn btn-sm btn-outline-secondary" href="/scan-results/${x.id}">Run details</a></span></div>
        <ul class="list-unstyled small mono mt-2 mb-0">${x.events.slice(-8).map(e => `<li class="${e.level === 'error' ? 'text-danger' : e.level === 'warn' ? 'text-warning' : ''}">${WT.time(e.ts)} ${WT.esc(e.message)}</li>`).join('')}</ul></div></div>`);
      if (!x.active) clearInterval(st.watch);
    });
    draw();
    st.watch = setInterval(draw, 4000);
  }

  // ----------------------------------------------------------------- events
  $('#wzNext').on('click', () => go(st.step + 1));
  $('#wzBack').on('click', () => go(st.step - 1));
  $('#wzSteps').on('click', 'li', function () { go($(this).data('step')); });
  $('#fAddCred').on('click', () => addCredRow());
  $('#fAddReport').on('click', () => addReportRow());
  $(document).on('click', '.credDel', function () { $(this).closest('.cred-row').remove(); });
  $(document).on('click', '.repDel', function () { $(this).closest('.rep-row').remove(); });
  $(document).on('change', '.credType', function () { fillCredId($(this).closest('.cred-row')); });
  $('#fUrl, #fName').on('input', summary);
  $('#recentTargets').on('click', '[data-target]', function () { $('#fUrl').val($(this).data('target')); summary(); WT.toast('Target set'); });
  $('#wzLaunch').on('click', function () {
    if (!valid(1) || !valid(2) || !valid(4)) return;
    const $b = $(this).prop('disabled', true);
    WT.post('/scans', body()).then(r => { WT.ok('Run #' + r.run_id + ' started'); follow(r.run_id); })
      .catch(err => WT.fail(err)).always(() => $b.prop('disabled', false));
  });

  // ------------------------------------------------------------------- init
  try { $('#fLabHost').val(localStorage.getItem('wt-labhost') || '192.168.1.82'); } catch (e) { $('#fLabHost').val('192.168.1.82'); }
  const qs = new URLSearchParams(location.search);
  if (qs.get('target')) $('#fUrl').val(qs.get('target'));
  renderApps();
  WT.sensorSelect('#fSensor', {hideWhenSingle: false});
  $.when(WT.get('/sc/families'), WT.get('/sc/policies?detail=1')).then((f, p) => {
    st.families = f[0].families; st.policies = p[0].policies;
    renderPolicies(); renderFamilies();
    selectPolicy(qs.get('policy') || (st.policies.find(x => (x.families || []).length < st.families.length) || st.policies[0] || {}).id);
  }).catch(e => WT.fail(e, 'Could not load policies'));
  $.when(WT.get('/sc/repos'), WT.get('/sc/zones'), WT.get('/sc/credentials'), WT.get('/sc/reports')).then((r, z, c, rp) => {
    const repos = r[0].repos || [], zones = z[0].zones || [];
    st.creds = c[0].credentials || []; st.reports = rp[0].reports || [];
    $('#fRepo').html('<option value="">' + (repos.length ? '— auto —' : 'no repositories') + '</option>' +
      repos.map(x => `<option value="${WT.esc(x.id)}">${WT.esc(x.name)}${x.type ? ' · ' + WT.esc(x.type) : ''}</option>`).join(''));
    $('#fZone').html('<option value="">— default scan zone —</option>' +
      zones.map(x => `<option value="${WT.esc(x.id)}">${WT.esc(x.name)}</option>`).join(''));
  }).catch(() => { /* repos/zones/creds/reports are optional; leave the selects with their defaults */ });
  WT.get('/scans?limit=30').then(r => {
    const seen = [...new Set(r.runs.map(x => x.target_url))].slice(0, 10);
    if (seen.length) $('#recentTargets').html(seen.map(u => `<button type="button" class="btn btn-sm btn-outline-secondary" data-target="${WT.esc(u)}">${WT.esc(u)}</button>`).join(''));
  });
  summary();
})(jQuery, window.WT);
