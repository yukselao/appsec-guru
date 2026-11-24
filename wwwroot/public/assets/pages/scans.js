(function ($, WT) {
  'use strict';
  const S = {scans: {}, templates: [], tpl: null, over: {}, folders: [], families: [], policies: [], sensors: [], repos: [], zones: [], creds: [], reports: [], folder: 'all', step: 1, editing: null};
  const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const STEPS = 6;

  const ICO = {
    folder: '<svg class="ic" viewBox="0 0 24 24"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>',
    all: '<svg class="ic" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>',
    inbox: '<svg class="ic" viewBox="0 0 24 24"><path d="M3 12h5l2 3h4l2-3h5"/><path d="M3 12l3-7h12l3 7v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>',
    globe: '<svg class="ic" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18"/></svg>',
    clock: '<svg class="ic" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>',
    shield: '<svg class="ic" viewBox="0 0 24 24"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/></svg>',
    sensor: '<svg class="ic" viewBox="0 0 24 24"><circle cx="12" cy="12" r="2"/><path d="M7 7a7 7 0 0 0 0 10M17 7a7 7 0 0 1 0 10"/></svg>',
    bug: '<svg class="ic" viewBox="0 0 24 24"><path d="M9 7a3 3 0 0 1 6 0M6 12h12M7 9c-2 0-3 1-3 3v2c0 3 3 5 8 5s8-2 8-5v-2c0-2-1-3-3-3"/><path d="M12 9v11"/></svg>',
    play: '<svg class="ic" viewBox="0 0 24 24"><path d="M7 5l12 7-12 7z" fill="currentColor" stroke="none"/></svg>',
    layers: '<svg class="ic" viewBox="0 0 24 24"><path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/></svg>',
  };

  // ------------------------------------------------------------ folder tree
  function tree() {
    $.when(WT.get('/folders'), WT.get('/tenable-was-scans?folder=all')).then((fr, pr) => {
      S.folders = fr[0].folders;
      const counts = {}; pr[0].scans.forEach(p => { counts[p.folder_id] = (counts[p.folder_id] || 0) + 1; });
      const kids = pid => S.folders.filter(f => f.parent_id === pid);
      const node = f => `<div class="folder-node ${S.folder == f.id ? 'active' : ''}" data-folder="${f.id}">
        <span class="fl-name">${ICO.folder} ${WT.esc(f.name)}</span><span class="badge rounded-pill text-bg-light border ms-1">${counts[f.id] || 0}</span>
        <span class="fl-actions"><a href="#" data-ren="${f.id}" title="Rename">✎</a> <a href="#" data-delf="${f.id}" title="Delete">✕</a></span>
        <div class="fl-children">${kids(f.id).map(node).join('')}</div></div>`;
      $('#folderTree').html(
        `<div class="folder-node ${S.folder === 'all' ? 'active' : ''}" data-folder="all"><span class="fl-name">${ICO.all} All scans</span><span class="badge rounded-pill text-bg-light border ms-1">${pr[0].scans.length}</span></div>` +
        kids(null).map(node).join('') +
        `<div class="folder-node ${S.folder === 'unfiled' ? 'active' : ''}" data-folder="unfiled"><span class="fl-name">${ICO.inbox} Unfiled</span><span class="badge rounded-pill text-bg-light border ms-1">${fr[0].unfiled}</span></div>`);
      $('#moveFolder').html(folderOptions());
      profiles();
    }).catch(e => WT.fail(e));
  }

  function profiles() {
    WT.get('/tenable-was-scans?folder=' + S.folder).then(r => {
      r.scans.forEach(p => { S.scans[p.id] = p; });
      $('#profCount').text(r.scans.length);
      const folderName = S.folder === 'all' ? 'All scans' : S.folder === 'unfiled' ? 'Unfiled scans'
        : (S.folders.find(f => f.id == S.folder) || {}).name || 'Scans';
      $('#folderTitle').text(folderName);
      const q = ($('#profSearch').val() || '').toLowerCase();
      const list = r.scans.filter(p => !q || (p.name + ' ' + p.target_url).toLowerCase().includes(q));
      if (!list.length) {
        $('#profCards').html(`<div class="profile-empty text-center py-5">
            <div class="mb-2 text-body-secondary">${ICO.layers}</div>
            <div class="fw-semibold">No scans here</div>
            <div class="small text-body-secondary mb-3">Create a reusable scan: a target, policy, families and a schedule.</div>
            <button class="btn btn-primary btn-sm" id="emptyNew">Create Tenable WAS Scan</button></div>`);
        return;
      }
      $('#profCards').html(`<div class="card"><div class="table-responsive"><table class="table align-middle wt-scan-table mb-0">
        <thead><tr><th style="width:34px"><input type="checkbox" class="form-check-input" id="chkAll" title="Select all"></th><th>Name</th><th>Target</th><th>Policy</th><th>Schedule</th><th>Last run</th><th class="text-end">Actions</th></tr></thead>
        <tbody>${list.map(rowHtml).join('')}</tbody></table></div></div>`);
      updateMoveBar();
    }).catch(e => $('#profErr').html(`<div class="alert alert-danger">${WT.esc(e)}</div>`));
  }

  function folderOptions() {
    const opt = (f, depth) => `<option value="${f.id}">${'— '.repeat(depth)}${WT.esc(f.name)}</option>` +
      S.folders.filter(c => c.parent_id === f.id).map(c => opt(c, depth + 1)).join('');
    return '<option value="">Unfiled</option>' + S.folders.filter(f => !f.parent_id).map(f => opt(f, 0)).join('');
  }
  function updateMoveBar() {
    const $chk = $('.scanchk'), n = $chk.filter(':checked').length, total = $chk.length;
    $('#moveCount').text(n);
    $('#moveBar').toggleClass('d-none', n === 0).toggleClass('d-flex', n > 0);
    $('#chkAll').prop('checked', total > 0 && n === total).prop('indeterminate', n > 0 && n < total);
  }
  function scanPrefs() {
    if ($('#pmScope').val() !== 'custom') return [];
    return ['was[scope]page_limit=' + ($('#pmPages').val() || 10),
      'was_timeout=' + ($('#pmScopeTime').val() || '00:30:00'),
      'was[plugin][rate_limiter]requests_per_second=' + ($('#pmRps').val() || 25)];
  }

  function rowHtml(p) {
    const last = p.last_run;
    const onDemand = (p.schedule || {}).type === 'on_demand' || !p.schedule;
    const schedCls = !p.enabled || onDemand ? 'text-bg-light border' : 'text-bg-primary';
    const accent = !p.enabled ? 'is-off' : (last && last.active ? 'is-running' : 'is-on');
    const lastCell = last
      ? `<a href="/scan-results/${last.id}">#${last.id}</a> ${WT.statusBadge(last.status)}${last.active ? ' <span class="spinner-border spinner-border-sm text-primary"></span>' : ''}${last.findings ? ` · <a href="/scan-results/${last.id}">${last.findings} findings</a>` : ''}`
      : '<span class="text-body-secondary">—</span>';
    return `<tr class="scan-row ${accent}">
      <td><input type="checkbox" class="form-check-input scanchk" value="${p.id}" aria-label="Select ${WT.esc(p.name)}"></td>
      <td style="min-width:150px"><div class="d-flex align-items-center gap-2"><span class="fw-semibold">${WT.esc(p.name)}</span>${p.enabled ? '' : '<span class="badge text-bg-secondary">disabled</span>'}</div>${p.description ? `<div class="small text-body-secondary">${WT.esc(p.description)}</div>` : ''}</td>
      <td><span class="mono small text-truncate d-inline-block align-middle scan-target" title="${WT.esc(p.target_url)}">${WT.esc(p.target_url)}</span></td>
      <td class="small text-nowrap">${policyLabel(p)} <span class="text-body-secondary">· ${famLabel(p)}</span><div class="text-body-secondary">debug ${WT.esc(p.debug_mode === 'none' ? 'off' : p.debug_mode)}</div></td>
      <td class="small text-nowrap"><span class="badge rounded-pill ${schedCls}">${WT.esc(p.schedule_text)}</span>${p.next_run_at ? `<div class="text-body-secondary mt-1">next ${new Date(p.next_run_at).toLocaleString('en-GB', {day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit'})}</div>` : ''}</td>
      <td class="small text-nowrap">${lastCell}</td>
      <td class="text-end text-nowrap">
        <div class="btn-group btn-group-sm" role="group">
          <button class="btn btn-primary" data-run="${p.id}" title="Run now">${ICO.play} Run</button>
          <button class="btn btn-outline-secondary" data-edit="${p.id}">Edit</button>
          <button class="btn btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown" data-bs-popper-config='{"strategy":"fixed"}' aria-expanded="false" aria-label="More actions for ${WT.esc(p.name)}">More</button>
          <ul class="dropdown-menu dropdown-menu-end">
            <li><button class="dropdown-item" type="button" data-toggle="${p.id}">${p.enabled ? 'Disable schedule' : 'Enable schedule'}</button></li>
            <li><button class="dropdown-item" type="button" data-copy="${p.id}">Duplicate</button></li>
            <li><hr class="dropdown-divider"></li>
            <li><button class="dropdown-item text-danger" type="button" data-delp="${p.id}">Delete</button></li>
          </ul>
        </div></td></tr>`;
  }

  function miniRunning() {
    WT.get('/dashboard').then(d => {
      const items = d.sc.map(r => ({name: r.name, status: r.status, uuid: (r._uuids || [])[0]}))
        .concat(d.scans.filter(s => s.has_dir && !d.sc.some(r => (r._uuids || []).includes(s.uuid))).map(s => ({name: s.target, status: 'running', uuid: s.uuid})));
      $('#runningMini').html(items.length ? items.map(i => `<li class="list-group-item d-flex align-items-center gap-2">
        <span class="text-truncate small">${WT.esc(i.name)}</span>${WT.statusBadge(i.status)}
        ${i.uuid ? `<a class="btn btn-sm btn-outline-primary ms-auto py-0" href="/logs?uuid=${encodeURIComponent(i.uuid)}">Log</a>` : ''}</li>`).join('')
        : '<li class="list-group-item empty">No scan running.</li>');
    }).catch(() => {});
  }


  // ------------------------------------------------- custom scan (templates)
  // What each Tenable WAS template is for, in plain words. Keyed by template name.
  const TPL_INFO = {
    'Quick Scan': {tag: 'Fastest', order: 1, text: 'A high-level look at security headers and exposed configuration. Nothing to configure, no login.'},
    'Web App Overview': {tag: 'Fast', order: 2, text: 'Crawls the application and builds a site map. No active attacks are sent.'},
    'Scan': {tag: 'Most thorough', order: 3, text: 'Full crawl plus active vulnerability tests. Tune it with Speed and the checks below.'},
    'SSL_TLS': {tag: 'Fast', order: 4, text: 'Audits only the SSL/TLS setup of the target. Does not crawl.'},
    'Web App Config Audit': {tag: 'Fast', order: 5, text: 'Checks security headers and configuration against best practice.'},
    'API': {tag: '', order: 6, text: 'Tests an API described by an OpenAPI (v2/v3) file URL.'},
    'PCI': {tag: 'Compliance', order: 7, text: 'PCI ASV assessment scan.'},
  };
  // Speed presets only touch the options a template really has.
  const SPEEDS = [
    {id: 'smoke', name: 'Smoke test', text: '10 pages, 10 minutes. Proves the scan works.',
      set: {'was[scope]page_limit': '10', 'was_timeout': '00:10:00', 'was[scope]directory_depth_limit': '3', 'was[scope]dom_depth_limit': '2'}},
    {id: 'fast', name: 'Fast', text: '150 pages, 45 minutes. A good first look.',
      set: {'was[scope]page_limit': '150', 'was_timeout': '00:45:00', 'was[scope]directory_depth_limit': '4', 'was[scope]dom_depth_limit': '3'}},
    {id: 'standard', name: 'Standard', text: 'The template defaults. Full coverage.', set: {}},
  ];
  const SPEED_KEYS = ['was[scope]page_limit', 'was_timeout', 'was[scope]directory_depth_limit', 'was[scope]dom_depth_limit'];
  const FAM_PRESETS = [
    {name: 'All', pick: () => true},
    {name: 'Injection & XSS', pick: n => /injection|cross site scripting|code execution|file inclusion/i.test(n)},
    {name: 'Authentication', pick: n => /authentication|request forgery/i.test(n)},
    {name: 'Headers & TLS', pick: n => /ssl|security header|web servers/i.test(n)},
    {name: 'None', pick: () => false},
  ];

  const isTpl = v => String(v || '').indexOf('template:') === 0;
  const tplById = id => S.templates.find(t => String(t.id) === String(id));
  const tplInputs = t => (t ? t.sections : []).reduce((a, sec) => a.concat(sec.inputs), []);
  const HIDDEN_INPUTS = ['was_openapi_toggle'];
  function policyLabel(p) {
    if (isTpl(p.source_policy_id)) {
      const t = tplById(p.source_policy_id.split(':')[1]);
      return `<span class="badge text-bg-light border">Custom</span> ${WT.esc(t ? t.name : 'template ' + p.source_policy_id.split(':')[1])}`;
    }
    const pol = S.policies.find(x => String(x.id) === String(p.source_policy_id));
    return pol ? `<span title="Policy ${WT.esc(p.source_policy_id)}">${WT.esc(pol.name)}</span>` : WT.esc(p.source_policy_id);
  }
  function famLabel(p) {
    if (p.families.length) return p.families.length + ' families';
    if (!isTpl(p.source_policy_id)) return 'policy families';
    const t = tplById(p.source_policy_id.split(':')[1]);
    return t && !t.plugins ? 'fixed checks' : 'all families';
  }
  const mode = () => $('input[name=pmMode]:checked').val();
  function optVal(inp) { return Object.prototype.hasOwnProperty.call(S.over, inp.id) ? S.over[inp.id] : inp.default; }

  function renderTemplates() {
    if (!S.templates.length) return;
    const list = S.templates.slice().sort((a, b) => ((TPL_INFO[a.name] || {}).order || 99) - ((TPL_INFO[b.name] || {}).order || 99));
    $('#pmTemplates').html(list.map(t => { const i = TPL_INFO[t.name] || {};
      return `<div class="col"><label class="card h-100 opt-card"><div class="card-body d-flex gap-2 py-2">
        <input class="form-check-input mt-1" type="radio" name="pmTpl" value="${WT.esc(t.id)}" ${String(S.tpl) === String(t.id) ? 'checked' : ''}>
        <div><div class="fw-semibold">${WT.esc(t.name)} ${i.tag ? `<span class="badge rounded-pill text-bg-light border fw-normal">${WT.esc(i.tag)}</span>` : ''}</div>
        <div class="small text-body-secondary">${WT.esc(i.text || t.description)}</div></div></div></label></div>`; }).join(''));
  }

  function inputHtml(inp, n) {
    const v = optVal(inp), id = 'po' + n, pref = `data-pref="${WT.esc(inp.id)}"`;
    const tip = inp.tooltip ? ` <a href="#" class="info-dot" tabindex="0" role="button" data-bs-toggle="tooltip" data-bs-html="true" data-bs-title="${WT.esc(WT.esc(inp.tooltip).replace(/\n+/g, '<br>'))}" aria-label="About ${WT.esc(inp.name)}">i</a>` : '';
    const hint = inp.hint ? `<div class="form-text">${WT.esc(inp.hint)}</div>` : '';
    const when = inp.when ? ` data-when="${WT.esc(inp.when.id)}" data-when-val="${WT.esc(inp.when.value)}"` : '';
    if (inp.type === 'checkbox') return `<div class="col-md-6 po-item"${when}><div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="${id}" ${pref} ${v === 'yes' ? 'checked' : ''}>
      <label class="form-check-label" for="${id}">${WT.esc(inp.name)}</label>${tip}</div>${hint}</div>`;
    const lbl = `<label class="form-label small mb-1" for="${id}">${WT.esc(inp.name)}</label>${tip}`;
    if (inp.type === 'dropdown') return `<div class="col-md-6 po-item"${when}>${lbl}<select class="form-select form-select-sm" id="${id}" ${pref}>${inp.options.map(o => `<option value="${WT.esc(o.value)}" ${o.value === v ? 'selected' : ''}>${WT.esc(o.label)}</option>`).join('')}</select>${hint}</div>`;
    if (inp.type === 'textarea') return `<div class="col-12 po-item"${when}>${lbl}<textarea class="form-control form-control-sm mono" rows="2" id="${id}" ${pref}>${WT.esc(v)}</textarea>${hint}</div>`;
    return `<div class="col-md-6 col-lg-4 po-item"${when}>${lbl}<input class="form-control form-control-sm" id="${id}" ${pref} value="${WT.esc(v)}">${hint}</div>`;
  }

  // Draws everything under the template cards for the selected template.
  function renderCustom() {
    renderTemplates();
    const t = tplById(S.tpl), inputs = tplInputs(t);
    const has = k => inputs.some(i => i.id === k);
    // speed
    const speeds = t && SPEED_KEYS.every(has) ? SPEEDS : [];   // only the crawling templates
    $('#pmSpeedWrap').toggleClass('d-none', !speeds.length);
    $('#pmSpeed').html(speeds.map(sp => `<div class="col"><label class="card h-100 opt-card"><div class="card-body d-flex gap-2 py-2">
      <input class="form-check-input mt-1" type="radio" name="pmSpeed" value="${sp.id}"><div><div class="fw-semibold">${sp.name}</div><div class="small text-body-secondary">${sp.text}</div></div></div></label></div>`).join('') +
      (speeds.length ? `<div class="col"><label class="card h-100 opt-card"><div class="card-body d-flex gap-2 py-2">
      <input class="form-check-input mt-1" type="radio" name="pmSpeed" value="own"><div><div class="fw-semibold">Your own limits</div><div class="small text-body-secondary">Set pages and time under Advanced &rarr; Limits below.</div></div></div></label></div>` : ''));
    // families
    $('#pmCFamWrap').toggleClass('d-none', !(t && t.plugins));
    // options
    $('#pmOptsWrap').toggleClass('d-none', !inputs.length);
    let n = 0;
    $('#pmOpts').html((t ? t.sections : []).map((sec, si) => {
      const groups = []; sec.inputs.filter(i => !HIDDEN_INPUTS.includes(i.id)).forEach(i => { let g = groups.find(x => x.name === i.group); if (!g) { g = {name: i.group, items: []}; groups.push(g); } g.items.push(i); });
      return `<div class="accordion-item"><h3 class="accordion-header"><button class="accordion-button collapsed py-2" type="button" data-bs-toggle="collapse" data-bs-target="#pmSec${si}">
        ${WT.esc(sec.name)} <span class="badge text-bg-light border ms-2 fw-normal" data-sec-count="${si}"></span></button></h3>
        <div id="pmSec${si}" class="accordion-collapse collapse" data-sec="${si}"><div class="accordion-body pt-2">${groups.map(g =>
          `${g.name && g.name !== sec.name ? `<div class="text-uppercase small fw-semibold text-body-secondary mt-2 mb-1">${WT.esc(g.name)}</div>` : ''}<div class="row g-2">${g.items.map(i => inputHtml(i, n++)).join('')}</div>`).join('')}</div></div></div>`;
    }).join(''));
    $('#pmOpts [data-bs-toggle="tooltip"]').each((i, el) => bootstrap.Tooltip.getOrCreateInstance(el));
    $('#pmCredNote').toggleClass('d-none', !(mode() === 'custom' && t && !t.credentials));
    syncCustom();
  }

  // Reflects S.over in the dependent bits: conditional fields, counters, the active speed, the note.
  function syncCustom() {
    const t = tplById(S.tpl), inputs = tplInputs(t), byId = {}; inputs.forEach(i => { byId[i.id] = i; });
    $('#pmOpts .po-item[data-when]').each(function () { const p = byId[$(this).data('when')]; $(this).toggleClass('d-none', !p || optVal(p) !== String($(this).data('when-val'))); });
    const changed = inputs.filter(i => optVal(i) !== i.default);
    $('#pmOptsChanged').text(changed.length + ' changed').toggleClass('text-bg-primary', changed.length > 0).toggleClass('text-bg-light border', !changed.length);
    (t ? t.sections : []).forEach((sec, si) => { const c = sec.inputs.filter(i => optVal(i) !== i.default).length; $(`[data-sec-count="${si}"]`).text(c ? c + ' changed' : sec.inputs.filter(i => !HIDDEN_INPUTS.includes(i.id)).length + ' options'); });
    const cur = k => byId[k] ? optVal(byId[k]) : null;
    const match = SPEEDS.find(sp => SPEED_KEYS.every(k => !byId[k] || cur(k) === (sp.set[k] || byId[k].default)));
    $(`input[name=pmSpeed][value="${match ? match.id : 'own'}"]`).prop('checked', true);
    let note = '';
    if (t) {
      const fams = $('.pmCFam:checked').length, all = $('.pmCFam').length;
      note = `On each run AppSec Guru creates a new policy on Security Center from the <b>${WT.esc(t.name)}</b> template` +
        (t.plugins ? `, enables ${fams === all ? 'all plugin families' : fams + ' of ' + all + ' plugin families'}` : '') +
        (changed.length ? `, changes ${changed.length} option${changed.length === 1 ? '' : 's'}` : ', keeps every option at its default') +
        ' and scans with it. None of your saved policies are touched.' +
        (inputs.length ? '' : ' This template has no options to configure.');
    }
    $('#pmCustomNote').html(note).toggleClass('d-none', !note);
  }
  function syncPolicyNote() {
    const n = $('.pmFam:checked').length;
    $('#pmPolicyNote').html(n
      ? `AppSec Guru <b>copies</b> the policy, turns on only the ${n} selected plugin famil${n === 1 ? 'y' : 'ies'} in the copy and scans with the copy. Your saved policy is never changed.`
      : 'No family selected: the policy runs with its own plugin families. Tick families to narrow the scan &mdash; AppSec Guru then scans with a copy of the policy, never the original.');
  }
  function setMode(m) {
    $(`input[name=pmMode][value="${m}"]`).prop('checked', true);
    $('#pmModePolicy').toggleClass('d-none', m !== 'policy'); $('#pmModeCustom').toggleClass('d-none', m !== 'custom');
    // in custom mode the limits live in the template options, not in the Scope select
    $('#pmScopeCol').toggleClass('d-none', m === 'custom');
    $('#pmCustomScope').toggleClass('d-none', m === 'custom' || $('#pmScope').val() !== 'custom');
    if (m === 'custom') { if (!S.tpl && S.templates.length) S.tpl = (S.templates.find(t => t.name === 'Scan') || S.templates[0]).id; renderCustom(); }
    else $('#pmCredNote').addClass('d-none');
  }
  function customPrefs() { return tplInputs(tplById(S.tpl)).filter(i => optVal(i) !== i.default).map(i => i.id + '=' + optVal(i)); }
  function customFamilies() { const $f = $('.pmCFam'); return $f.filter(':checked').length === $f.length ? [] : $f.filter(':checked').map((i, el) => el.value).get(); }

  // --------------------------------------------------------------- wizard
  function schedFields() {
    const t = $('#pmSchedType').val();
    const now = new Date(Date.now() + 3600000).toISOString().slice(0, 16);
    let h = '';
    if (t === 'once') h = `<label class="form-label" for="pmAt">At</label><input class="form-control" id="pmAt" type="datetime-local" value="${now}">`;
    else if (t === 'interval') h = `<label class="form-label" for="pmEvery">Every (hours)</label><input class="form-control" id="pmEvery" type="number" value="6" min="1">`;
    else if (t === 'daily') h = `<label class="form-label" for="pmSchedTime">Time</label><input class="form-control" id="pmSchedTime" type="time" value="02:30">`;
    else if (t === 'weekly') h = `<label class="form-label" for="pmSchedTime">Time</label><input class="form-control mb-2" id="pmSchedTime" type="time" value="02:30">
      <div class="btn-group btn-group-sm d-flex flex-wrap" role="group">${DAYS.map((d, i) => `<input type="checkbox" class="btn-check pmDay" id="d${i}" value="${i}"><label class="btn btn-outline-secondary" for="d${i}">${d}</label>`).join('')}</div>`;
    $('#pmSchedFields').html(h);
    schedPreview();
  }
  function schedule() {
    const t = $('#pmSchedType').val();
    if (t === 'once') return {type: 'once', at: $('#pmAt').val()};
    if (t === 'interval') return {type: 'interval', every_hours: parseFloat($('#pmEvery').val() || '6')};
    if (t === 'daily') return {type: 'daily', time: $('#pmSchedTime').val()};
    if (t === 'weekly') return {type: 'weekly', time: $('#pmSchedTime').val(), days: $('.pmDay:checked').map((i, el) => parseInt(el.value, 10)).get()};
    return {type: 'on_demand'};
  }
  function schedPreview() {
    const s = schedule();
    let txt = 'Runs only when you press Run now.';
    if (s.type === 'once') txt = 'Runs once at ' + (s.at || '').replace('T', ' ') + ', then disables itself.';
    else if (s.type === 'interval') txt = `Runs every ${s.every_hours} hours.`;
    else if (s.type === 'daily') txt = `Runs every day at ${s.time}.`;
    else if (s.type === 'weekly') txt = `Runs ${s.days.length ? 'on ' + s.days.map(d => DAYS[d]).join(', ') : '(pick days)'} at ${s.time}.`;
    $('#pmSchedPreview').text(txt);
  }

  // ---- credential + report rows (SC-style) ----
  function credTypeLabel(t) {
    if (t === 'webAuthentication') return 'Web Authentication';
    return String(t || '').replace(/([A-Z])/g, ' $1').replace(/^./, c => c.toUpperCase()).trim();
  }
  function credTypes() { return [...new Set(S.creds.map(c => c.type))]; }
  function fillCredId($row) {
    const t = $row.find('.credType').val();
    const list = S.creds.filter(c => c.type === t);
    $row.find('.credId').html(list.map(c => `<option value="${WT.esc(c.id)}">${WT.esc(c.name)}</option>`).join(''));
  }
  function addCredRow(selType, selId) {
    const types = credTypes();
    if (!types.length) { WT.warn('No credentials defined on Security Center'); return; }
    const $row = $(`<div class="cred-row row g-2 align-items-end mb-2">
      <div class="col-sm-5"><select class="form-select form-select-sm credType">${types.map(t => `<option value="${WT.esc(t)}">${WT.esc(credTypeLabel(t))}</option>`).join('')}</select></div>
      <div class="col-sm-5"><select class="form-select form-select-sm credId"></select></div>
      <div class="col-sm-2"><button type="button" class="btn btn-sm btn-outline-danger w-100 credDel">Remove</button></div></div>`);
    $('#pmCreds').append($row);
    if (selType) $row.find('.credType').val(selType);
    fillCredId($row);
    if (selId != null) $row.find('.credId').val(String(selId));
  }
  function collectCreds() { return $('#pmCreds .credId').map((i, el) => parseInt(el.value, 10)).get().filter(Boolean); }
  function addReportRow(selId) {
    if (!S.reports.length) { WT.warn('No report definitions on Security Center'); return; }
    const $row = $(`<div class="rep-row row g-2 align-items-end mb-2">
      <div class="col-sm-10"><select class="form-select form-select-sm repId">${S.reports.map(r => `<option value="${WT.esc(r.id)}">${WT.esc(r.name)}</option>`).join('')}</select></div>
      <div class="col-sm-2"><button type="button" class="btn btn-sm btn-outline-danger w-100 repDel">Remove</button></div></div>`);
    $('#pmReports').append($row);
    if (selId != null) $row.find('.repId').val(String(selId));
  }
  function collectReports() { return $('#pmReports .repId').map((i, el) => parseInt(el.value, 10)).get().filter(Boolean); }

  function openWizard(p) {
    S.editing = p ? p.id : null; S.step = 1;
    $('#pmTitle').text(p ? 'Edit Tenable WAS Scan' : 'Create Tenable WAS Scan');
    $('#pmFolder').html('<option value="">Unfiled</option>' + S.folders.map(f => `<option value="${f.id}">${WT.esc(f.name)}</option>`).join(''));
    $('#pmSensor').html(S.sensors.map(s => `<option value="${s.id}">${WT.esc(s.name)}${s.is_default ? ' (default)' : ''}</option>`).join(''));
    $('#pmPolicy').html(S.policies.map(x => `<option value="${WT.esc(x.id)}">${WT.esc(x.id)} · ${WT.esc(x.name)}</option>`).join(''));
    $('#pmCFamilies').html(S.families.map(f => `<div class="col"><div class="form-check"><input class="form-check-input pmCFam" type="checkbox" value="${WT.esc(f.name)}" id="cf${f.id}" checked><label class="form-check-label" for="cf${f.id}">${WT.esc(f.name)}</label></div></div>`).join(''));
    $('#pmCFamPresets').html(FAM_PRESETS.map((x, i) => `<button type="button" class="btn btn-sm btn-outline-secondary py-0" data-fampreset="${i}">${x.name}</button>`).join(''));
    $('#pmFamilies').html(S.families.map(f => `<div class="col"><div class="form-check"><input class="form-check-input pmFam" type="checkbox" value="${WT.esc(f.name)}" id="pf${f.id}"><label class="form-check-label" for="pf${f.id}">${WT.esc(f.name)}</label></div></div>`).join(''));
    $('#pmRepo').html('<option value="">' + ((S.repos || []).length ? '— auto —' : 'no repositories') + '</option>' +
      (S.repos || []).map(r => `<option value="${WT.esc(r.id)}">${WT.esc(r.name)}${r.type ? ' · ' + WT.esc(r.type) : ''}</option>`).join(''));
    $('#pmZone').html('<option value="">— default scan zone —</option>' +
      (S.zones || []).map(z => `<option value="${WT.esc(z.id)}">${WT.esc(z.name)}</option>`).join(''));
    const d = p || {};
    $('#pmName').val(d.name || ''); $('#pmDesc').val(d.description || ''); $('#pmUrl').val(d.target_url || '');
    $('#pmFolder').val(d.folder_id || (S.folder !== 'all' && S.folder !== 'unfiled' ? S.folder : ''));
    $('#pmSensor').val(d.sensor_id || (S.sensors.find(s => s.is_default) || {}).id || '');
    const custom = isTpl(d.source_policy_id);
    $('#pmPolicy').val(custom ? (S.policies[0] || {}).id : d.source_policy_id || (S.policies[0] || {}).id);
    S.tpl = custom ? d.source_policy_id.split(':')[1] : null; S.over = {};
    if (custom) (d.prefs || []).forEach(x => { const i = x.indexOf('='); if (i > 0) S.over[x.slice(0, i)] = x.slice(i + 1); });
    $('#pmDebug').val(d.debug_mode || 'both'); $('#pmScope').val(d.scope || 'fast');
    $('#pmCustomScope').toggleClass('d-none', (d.scope || 'fast') !== 'custom');
    if (!custom && d.scope === 'custom') {
      const pf = {}; (d.prefs || []).forEach(x => { const i = x.indexOf('='); if (i > 0) pf[x.slice(0, i)] = x.slice(i + 1); });
      if (pf['was[scope]page_limit']) $('#pmPages').val(pf['was[scope]page_limit']);
      if (pf['was_timeout']) $('#pmScopeTime').val(pf['was_timeout']);
      if (pf['was[plugin][rate_limiter]requests_per_second']) $('#pmRps').val(pf['was[plugin][rate_limiter]requests_per_second']);
    }
    $('#pmKeep').prop('checked', d.keep_objects !== false); $('#pmRepo').val(d.repo_id || ''); $('#pmZone').val(d.zone_id || '');
    $('#pmMaxTime').val(d.max_scan_time || 'unlimited'); $('#pmInactivity').val(String(d.inactivity_hours || 12));
    $('#pmRemoveUnresp').prop('checked', d.remove_unresponsive !== false);
    $('#pmEnabled').prop('checked', d.enabled !== false); $('#pmRunNow').prop('checked', false);
    if (custom) { if ((d.families || []).length) $('.pmCFam').each(function () { this.checked = d.families.includes(this.value); }); }
    else (d.families || []).forEach(n => $(`.pmFam[value="${CSS.escape(n)}"]`).prop('checked', true));
    setMode(custom ? 'custom' : 'policy'); syncPolicyNote();
    $('#pmCreds').empty(); (d.credential_ids || []).forEach(cid => {
      const c = S.creds.find(x => String(x.id) === String(cid)); addCredRow(c ? c.type : null, cid);
    });
    $('#pmReports').empty(); (d.report_ids || []).forEach(rid => addReportRow(rid));
    const sch = d.schedule || {type: 'on_demand'};
    $('#pmSchedType').val(sch.type || 'on_demand'); schedFields();
    if (sch.type === 'once') $('#pmAt').val(sch.at);
    if (sch.type === 'interval') $('#pmEvery').val(sch.every_hours);
    if (sch.time) $('#pmSchedTime').val(sch.time);
    (sch.days || []).forEach(i => $('#d' + i).prop('checked', true));
    schedPreview();
    goStep(1);
    $('#profModal [data-bs-toggle="tooltip"]').each((i, el) => bootstrap.Tooltip.getOrCreateInstance(el));
    bootstrap.Modal.getOrCreateInstance('#profModal').show();
  }
  function goStep(n) {
    S.step = Math.max(1, Math.min(STEPS, n));
    $('.wizard-pane').removeClass('active').filter(`[data-pane="${S.step}"]`).addClass('active');
    $('#pmSteps li').each(function () { const s = $(this).data('step'); $(this).toggleClass('active', s === S.step).toggleClass('done', s < S.step); });
    $('#pmBack').prop('disabled', S.step === 1);
    $('#pmNext').toggleClass('d-none', S.step === STEPS);
    $('#pmSave').toggleClass('d-none', S.step !== STEPS);
  }
  function profBody() {
    const custom = mode() === 'custom';
    return {name: $('#pmName').val().trim(), description: $('#pmDesc').val().trim(), folder_id: $('#pmFolder').val() || null,
      target_url: $('#pmUrl').val().trim(), sensor_id: $('#pmSensor').val() || null,
      source_policy_id: custom ? 'template:' + S.tpl : $('#pmPolicy').val(),
      families: custom ? customFamilies() : $('.pmFam:checked').map((i, el) => el.value).get(),
      debug_mode: $('#pmDebug').val(), scope: custom ? 'policy' : $('#pmScope').val(),
      keep_objects: $('#pmKeep').prop('checked'), repo_id: $('#pmRepo').val() || null, zone_id: $('#pmZone').val() || null,
      credential_ids: collectCreds(), report_ids: collectReports(),
      max_scan_time: $('#pmMaxTime').val(), inactivity_hours: parseInt($('#pmInactivity').val(), 10),
      remove_unresponsive: $('#pmRemoveUnresp').prop('checked'),
      prefs: custom ? customPrefs() : scanPrefs(), schedule: schedule(),
      enabled: $('#pmEnabled').prop('checked'), run_now: $('#pmRunNow').prop('checked')};
  }

  // --------------------------------------------------------------- events
  $(document).on('click', '[data-folder]', function () { S.folder = $(this).data('folder'); tree(); });
  $('#newFolder').on('click', () => { const n = prompt('Folder name'); if (n) WT.post('/folders', {name: n}).then(() => { WT.ok('Folder created'); tree(); }).catch(e => WT.fail(e)); });
  $(document).on('click', '[data-ren]', function (e) { e.preventDefault(); e.stopPropagation(); const id = $(this).data('ren'); const n = prompt('New name'); if (n) WT.api('PUT', '/folders/' + id, {name: n}).then(() => tree()).catch(x => WT.fail(x)); });
  $(document).on('click', '[data-delf]', function (e) { e.preventDefault(); e.stopPropagation(); const id = $(this).data('delf'); if (confirm('Delete folder? Scans inside move to Unfiled.')) WT.api('DELETE', '/folders/' + id).then(() => { S.folder = 'all'; tree(); }).catch(x => WT.fail(x)); });
  $('#newProfile').on('click', () => openWizard(null));
  $('#profCards').on('click', '#emptyNew', () => openWizard(null));
  // Edit opens straight from the row already on screen; the API is only a fallback.
  $(document).on('click', '[data-edit]', function (e) {
    e.preventDefault();
    const id = $(this).data('edit'), cached = S.scans[id];
    const open = p => { try { openWizard(p); } catch (err) { console.error(err); WT.fail('Could not open the editor: ' + err.message); } };
    if (cached) { open(cached); return; }
    WT.get('/tenable-was-scans/' + id).then(open).catch(x => WT.fail(x));
  });
  $(document).on('click', '[data-run]', function () {
    const id = $(this).data('run');
    WT.post('/tenable-was-scans/' + id + '/run').then(r => { WT.ok('Run #' + r.run_id + ' started'); location.href = '/scan-results/' + r.run_id; }).catch(e => WT.fail(e));
  });
  $(document).on('click', '[data-toggle]', function () { WT.post('/tenable-was-scans/' + $(this).data('toggle') + '/toggle').then(r => { WT.ok(r.enabled ? 'Enabled' : 'Disabled'); profiles(); }).catch(e => WT.fail(e)); });
  $(document).on('click', '[data-copy]', function () { WT.post('/tenable-was-scans/' + $(this).data('copy') + '/copy').then(() => { WT.ok('Copied'); tree(); }).catch(e => WT.fail(e)); });
  $(document).on('click', '[data-delp]', function () { const id = $(this).data('delp'); if (confirm('Delete scan #' + id + '? Its past runs are kept.')) WT.api('DELETE', '/tenable-was-scans/' + id).then(() => { WT.ok('Deleted'); tree(); }).catch(e => WT.fail(e)); });
  $('#pmNext').on('click', () => goStep(S.step + 1));
  $('#pmBack').on('click', () => goStep(S.step - 1));
  $('#pmSteps').on('click', 'li', function () { goStep($(this).data('step')); });
  $('#pmFamNone').on('click', () => { $('.pmFam').prop('checked', false); syncPolicyNote(); });
  $(document).on('change', '.pmFam', syncPolicyNote);
  $(document).on('change', 'input[name=pmMode]', function () { setMode(this.value); });
  $(document).on('change', 'input[name=pmTpl]', function () { S.tpl = this.value; S.over = {}; $('.pmCFam').prop('checked', true); renderCustom(); });
  $(document).on('change', 'input[name=pmSpeed]', function () {
    const sp = SPEEDS.find(x => x.id === this.value), inputs = tplInputs(tplById(S.tpl));
    if (!sp) { $('#pmOpts .accordion-collapse').last().each((i, el) => bootstrap.Collapse.getOrCreateInstance(el, {toggle: false}).show()); return; }
    SPEED_KEYS.forEach(k => { if (!inputs.some(i => i.id === k)) return; if (sp.set[k]) S.over[k] = sp.set[k]; else delete S.over[k]; });
    renderCustom();
  });
  $(document).on('input change', '#pmOpts [data-pref]', function () {
    S.over[$(this).data('pref')] = this.type === 'checkbox' ? (this.checked ? 'yes' : 'no') : this.value; syncCustom();
  });
  $('#pmOptsReset').on('click', () => { S.over = {}; renderCustom(); });
  $(document).on('click', '[data-fampreset]', function () { const f = FAM_PRESETS[$(this).data('fampreset')]; $('.pmCFam').each(function () { this.checked = !!f.pick(this.value); }); syncCustom(); });
  $(document).on('change', '.pmCFam', syncCustom);
  $('#pmAddCred').on('click', () => addCredRow());
  $('#pmAddReport').on('click', () => addReportRow());
  $(document).on('click', '.credDel', function () { $(this).closest('.cred-row').remove(); });
  $(document).on('click', '.repDel', function () { $(this).closest('.rep-row').remove(); });
  $(document).on('change', '.credType', function () { fillCredId($(this).closest('.cred-row')); });
  $('#pmScope').on('change', function () { $('#pmCustomScope').toggleClass('d-none', this.value !== 'custom' || mode() === 'custom'); });
  // ---- bulk move ----
  $(document).on('change', '.scanchk', updateMoveBar);
  $(document).on('change', '#chkAll', function () { $('.scanchk').prop('checked', this.checked); updateMoveBar(); });
  $('#moveClear').on('click', () => { $('.scanchk, #chkAll').prop('checked', false); updateMoveBar(); });
  $('#moveBtn').on('click', function () {
    const ids = $('.scanchk:checked').map((i, el) => parseInt(el.value, 10)).get();
    if (!ids.length) return;
    WT.post('/tenable-was-scans/move', {ids, folder_id: $('#moveFolder').val() || null})
      .then(r => { WT.ok(`Moved ${r.moved} scan${r.moved === 1 ? '' : 's'}`); tree(); }).catch(e => WT.fail(e));
  });
  $('#pmSchedType').on('change', schedFields);
  $(document).on('input change', '#pmSchedFields :input, .pmDay', schedPreview);
  $('#pmSave').on('click', function () {
    const b = profBody();
    if (!b.name) { WT.warn('Give the scan a name'); goStep(1); return; }
    if (mode() === 'custom') {
      const t = tplById(S.tpl);
      if (!t) { WT.warn('Pick a template'); goStep(2); return; }
      if (t.plugins && !$('.pmCFam:checked').length) { WT.warn('Pick at least one plugin family'); goStep(2); return; }
      const need = tplInputs(t).find(i => i.id === 'was[scope]openapi_file_url');
      if (need && !optVal(need)) { WT.warn('The API template needs an OpenAPI file URL (Scope options)'); goStep(2); return; }
    } else if (!b.source_policy_id) { WT.warn('Pick a policy'); goStep(2); return; }
    if (!b.target_url) { WT.warn('Enter the target URL'); goStep(4); return; }
    const req = S.editing ? WT.api('PUT', '/tenable-was-scans/' + S.editing, b) : WT.post('/tenable-was-scans', b);
    req.then(r => { WT.ok('Scan saved'); bootstrap.Modal.getInstance('#profModal').hide();
      if (r.run_id) { location.href = '/scan-results/' + r.run_id; return; } tree(); }).catch(e => WT.fail(e));
  });
  $('#refreshProf').on('click', () => { tree(); miniRunning(); });
  $('#profSearch').on('input', profiles);

  $.when(WT.get('/sc/families'), WT.get('/sc/policies'), WT.get('/sensors'), WT.get('/sc/repos'), WT.get('/sc/zones'),
         WT.get('/sc/credentials'), WT.get('/sc/reports')).then((f, p, s, r, z, c, rp) => {
    S.families = f[0].families; S.policies = p[0].policies; S.sensors = s[0].sensors;
    S.repos = r[0].repos || []; S.zones = z[0].zones || [];
    S.creds = c[0].credentials || []; S.reports = rp[0].reports || []; tree();
  }).catch(e => WT.fail(e, 'Could not load scan references'));
  WT.get('/sc/templates').then(r => { S.templates = r.templates || [];
    if ($('#profModal').hasClass('show') && mode() === 'custom') setMode('custom');
    if (Object.keys(S.scans).length) profiles();
  }).catch(e => { $('#pmTemplates').html(`<div class="col-12"><div class="alert alert-warning mb-0 small">Templates could not be loaded: ${WT.esc(e)}</div></div>`); });
  miniRunning();   // no timer: the page loads once and again only on Refresh
})(jQuery, window.WT);
