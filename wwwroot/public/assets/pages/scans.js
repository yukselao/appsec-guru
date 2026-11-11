(function ($, WT) {
  'use strict';
  const S = {folders: [], families: [], policies: [], sensors: [], folder: 'all', step: 1, editing: null};
  const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

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
    $.when(WT.get('/folders'), WT.get('/profiles?folder=all')).then((fr, pr) => {
      S.folders = fr[0].folders;
      const counts = {}; pr[0].profiles.forEach(p => { counts[p.folder_id] = (counts[p.folder_id] || 0) + 1; });
      const kids = pid => S.folders.filter(f => f.parent_id === pid);
      const node = f => `<div class="folder-node ${S.folder == f.id ? 'active' : ''}" data-folder="${f.id}">
        <span class="fl-name">${ICO.folder} ${WT.esc(f.name)}</span><span class="badge rounded-pill text-bg-light border ms-1">${counts[f.id] || 0}</span>
        <span class="fl-actions"><a href="#" data-ren="${f.id}" title="Rename">✎</a> <a href="#" data-delf="${f.id}" title="Delete">✕</a></span>
        <div class="fl-children">${kids(f.id).map(node).join('')}</div></div>`;
      $('#folderTree').html(
        `<div class="folder-node ${S.folder === 'all' ? 'active' : ''}" data-folder="all"><span class="fl-name">${ICO.all} All profiles</span><span class="badge rounded-pill text-bg-light border ms-1">${pr[0].profiles.length}</span></div>` +
        kids(null).map(node).join('') +
        `<div class="folder-node ${S.folder === 'unfiled' ? 'active' : ''}" data-folder="unfiled"><span class="fl-name">${ICO.inbox} Unfiled</span><span class="badge rounded-pill text-bg-light border ms-1">${fr[0].unfiled}</span></div>`);
      profiles();
    }).catch(e => WT.fail(e));
  }

  function profiles() {
    WT.get('/profiles?folder=' + S.folder).then(r => {
      $('#profCount').text(r.profiles.length);
      const folderName = S.folder === 'all' ? 'All scan profiles' : S.folder === 'unfiled' ? 'Unfiled profiles'
        : (S.folders.find(f => f.id == S.folder) || {}).name || 'Profiles';
      $('#folderTitle').text(folderName);
      const q = ($('#profSearch').val() || '').toLowerCase();
      const list = r.profiles.filter(p => !q || (p.name + ' ' + p.target_url).toLowerCase().includes(q));
      $('#profCards').html(list.length ? list.map(card).join('')
        : `<div class="col-12"><div class="profile-empty text-center py-5">
            <div class="mb-2 text-body-secondary">${ICO.layers}</div>
            <div class="fw-semibold">No scan profiles here</div>
            <div class="small text-body-secondary mb-3">Create a reusable scan: a target, policy, families and a schedule.</div>
            <button class="btn btn-primary btn-sm" id="emptyNew">New scan profile</button></div></div>`);
    }).catch(e => $('#profErr').html(`<div class="alert alert-danger">${WT.esc(e)}</div>`));
  }

  function card(p) {
    const last = p.last_run;
    const sensor = (S.sensors.find(s => s.id === p.sensor_id) || {}).name || 'default sensor';
    const onDemand = (p.schedule || {}).type === 'on_demand' || !p.schedule;
    const schedCls = !p.enabled ? 'text-bg-light border' : onDemand ? 'text-bg-light border' : 'sched-on';
    const accent = !p.enabled ? 'is-off' : (last && last.active ? 'is-running' : 'is-on');
    const meta = (icon, label, val) => `<div class="pm-item">${icon}<div><div class="pm-k">${label}</div><div class="pm-v">${val}</div></div></div>`;
    return `<div class="col"><div class="card profile-card h-100 ${accent}">
      <div class="card-body">
        <div class="d-flex align-items-start gap-2 mb-2">
          <div class="min-w-0">
            <div class="d-flex align-items-center gap-2"><h3 class="h6 mb-0 text-truncate">${WT.esc(p.name)}</h3>
              ${p.enabled ? '' : '<span class="badge text-bg-secondary">disabled</span>'}</div>
            ${p.description ? `<div class="small text-body-secondary text-truncate">${WT.esc(p.description)}</div>` : ''}
          </div>
          <span class="badge rounded-pill ${schedCls} ms-auto text-nowrap">${ICO.clock} ${WT.esc(p.schedule_text)}</span>
        </div>
        <a class="profile-target d-flex align-items-center gap-1 text-truncate" href="/create-scan?target=${encodeURIComponent(p.target_url)}" title="${WT.esc(p.target_url)}">${ICO.globe}<span class="mono text-truncate">${WT.esc(p.target_url)}</span></a>
        <div class="pm-grid mt-3">
          ${meta(ICO.shield, 'Policy', WT.esc(p.source_policy_id) + ' · ' + (p.families.length ? p.families.length + ' families' : 'policy families'))}
          ${meta(ICO.sensor, 'Sensor', WT.esc(sensor))}
          ${meta(ICO.bug, 'Debug', WT.esc(p.debug_mode === 'none' ? 'off' : p.debug_mode))}
          ${meta(ICO.clock, p.next_run_at ? 'Next run' : 'Last run',
            p.next_run_at ? WT.dt(p.next_run_at)
              : (last ? `<a href="/scan-results/${last.id}">#${last.id}</a> ${WT.statusBadge(last.status)}` : '—'))}
        </div>
        ${last ? `<div class="small text-body-secondary mt-2">Last run <a href="/scan-results/${last.id}">#${last.id}</a> ${WT.statusBadge(last.status)}${last.active ? ' <span class="spinner-border spinner-border-sm text-primary"></span>' : ''}${last.findings ? ' · ' + last.findings + ' findings' : ''}</div>` : ''}
      </div>
      <div class="card-footer d-flex flex-wrap align-items-center gap-2">
        <button class="btn btn-sm btn-primary" data-run="${p.id}">${ICO.play} Run now</button>
        <button class="btn btn-sm btn-outline-secondary" data-edit="${p.id}">Edit</button>
        <button class="btn btn-sm btn-outline-secondary" data-toggle="${p.id}">${p.enabled ? 'Disable' : 'Enable'}</button>
        <button class="btn btn-sm btn-outline-secondary" data-copy="${p.id}">Copy</button>
        <button class="btn btn-sm btn-outline-danger ms-auto" data-delp="${p.id}">Delete</button>
      </div></div></div>`;
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

  // --------------------------------------------------------------- wizard
  function schedFields() {
    const t = $('#pmSchedType').val();
    const now = new Date(Date.now() + 3600000).toISOString().slice(0, 16);
    let h = '';
    if (t === 'once') h = `<label class="form-label" for="pmAt">At</label><input class="form-control" id="pmAt" type="datetime-local" value="${now}">`;
    else if (t === 'interval') h = `<label class="form-label" for="pmEvery">Every (hours)</label><input class="form-control" id="pmEvery" type="number" value="6" min="1">`;
    else if (t === 'daily') h = `<label class="form-label" for="pmTime">Time</label><input class="form-control" id="pmTime" type="time" value="02:30">`;
    else if (t === 'weekly') h = `<label class="form-label" for="pmTime">Time</label><input class="form-control mb-2" id="pmTime" type="time" value="02:30">
      <div class="btn-group btn-group-sm d-flex flex-wrap" role="group">${DAYS.map((d, i) => `<input type="checkbox" class="btn-check pmDay" id="d${i}" value="${i}"><label class="btn btn-outline-secondary" for="d${i}">${d}</label>`).join('')}</div>`;
    $('#pmSchedFields').html(h);
    schedPreview();
  }
  function schedule() {
    const t = $('#pmSchedType').val();
    if (t === 'once') return {type: 'once', at: $('#pmAt').val()};
    if (t === 'interval') return {type: 'interval', every_hours: parseFloat($('#pmEvery').val() || '6')};
    if (t === 'daily') return {type: 'daily', time: $('#pmTime').val()};
    if (t === 'weekly') return {type: 'weekly', time: $('#pmTime').val(), days: $('.pmDay:checked').map((i, el) => parseInt(el.value, 10)).get()};
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

  function openWizard(p) {
    S.editing = p ? p.id : null; S.step = 1;
    $('#pmTitle').text(p ? 'Edit scan profile' : 'New scan profile');
    $('#pmFolder').html('<option value="">Unfiled</option>' + S.folders.map(f => `<option value="${f.id}">${WT.esc(f.name)}</option>`).join(''));
    $('#pmSensor').html(S.sensors.map(s => `<option value="${s.id}">${WT.esc(s.name)}${s.is_default ? ' (default)' : ''}</option>`).join(''));
    $('#pmPolicy').html(S.policies.map(x => `<option value="${WT.esc(x.id)}">${WT.esc(x.id)} · ${WT.esc(x.name)}</option>`).join(''));
    $('#pmFamilies').html(S.families.map(f => `<div class="col"><div class="form-check"><input class="form-check-input pmFam" type="checkbox" value="${WT.esc(f.name)}" id="pf${f.id}"><label class="form-check-label" for="pf${f.id}">${WT.esc(f.name)}</label></div></div>`).join(''));
    const d = p || {};
    $('#pmName').val(d.name || ''); $('#pmDesc').val(d.description || ''); $('#pmUrl').val(d.target_url || '');
    $('#pmFolder').val(d.folder_id || (S.folder !== 'all' && S.folder !== 'unfiled' ? S.folder : ''));
    $('#pmSensor').val(d.sensor_id || (S.sensors.find(s => s.is_default) || {}).id || '');
    $('#pmPolicy').val(d.source_policy_id || (S.policies[0] || {}).id);
    $('#pmDebug').val(d.debug_mode || 'both'); $('#pmScope').val(d.scope || 'fast');
    $('#pmKeep').prop('checked', d.keep_objects !== false); $('#pmRepo').val(d.repo_id || ''); $('#pmZone').val(d.zone_id || '');
    $('#pmSet').val((d.prefs || []).join('\n')); $('#pmEnabled').prop('checked', d.enabled !== false); $('#pmRunNow').prop('checked', false);
    (d.families || []).forEach(n => $(`.pmFam[value="${CSS.escape(n)}"]`).prop('checked', true));
    const sch = d.schedule || {type: 'on_demand'};
    $('#pmSchedType').val(sch.type || 'on_demand'); schedFields();
    if (sch.type === 'once') $('#pmAt').val(sch.at);
    if (sch.type === 'interval') $('#pmEvery').val(sch.every_hours);
    if (sch.time) $('#pmTime').val(sch.time);
    (sch.days || []).forEach(i => $('#d' + i).prop('checked', true));
    schedPreview();
    goStep(1);
    $('#profModal [data-bs-toggle="tooltip"]').each((i, el) => bootstrap.Tooltip.getOrCreateInstance(el));
    bootstrap.Modal.getOrCreateInstance('#profModal').show();
  }
  function goStep(n) {
    S.step = Math.max(1, Math.min(4, n));
    $('.wizard-pane').removeClass('active').filter(`[data-pane="${S.step}"]`).addClass('active');
    $('#pmSteps li').each(function () { const s = $(this).data('step'); $(this).toggleClass('active', s === S.step).toggleClass('done', s < S.step); });
    $('#pmBack').prop('disabled', S.step === 1);
    $('#pmNext').toggleClass('d-none', S.step === 4);
    $('#pmSave').toggleClass('d-none', S.step !== 4);
  }
  function profBody() {
    return {name: $('#pmName').val().trim(), description: $('#pmDesc').val().trim(), folder_id: $('#pmFolder').val() || null,
      target_url: $('#pmUrl').val().trim(), sensor_id: $('#pmSensor').val() || null, source_policy_id: $('#pmPolicy').val(),
      families: $('.pmFam:checked').map((i, el) => el.value).get(), debug_mode: $('#pmDebug').val(), scope: $('#pmScope').val(),
      keep_objects: $('#pmKeep').prop('checked'), repo_id: $('#pmRepo').val() || null, zone_id: $('#pmZone').val() || null,
      prefs: $('#pmSet').val().split('\n').map(x => x.trim()).filter(Boolean), schedule: schedule(),
      enabled: $('#pmEnabled').prop('checked'), run_now: $('#pmRunNow').prop('checked')};
  }

  // --------------------------------------------------------------- events
  $(document).on('click', '[data-folder]', function () { S.folder = $(this).data('folder'); tree(); });
  $('#newFolder').on('click', () => { const n = prompt('Folder name'); if (n) WT.post('/folders', {name: n}).then(() => { WT.ok('Folder created'); tree(); }).catch(e => WT.fail(e)); });
  $(document).on('click', '[data-ren]', function (e) { e.preventDefault(); e.stopPropagation(); const id = $(this).data('ren'); const n = prompt('New name'); if (n) WT.api('PUT', '/folders/' + id, {name: n}).then(() => tree()).catch(x => WT.fail(x)); });
  $(document).on('click', '[data-delf]', function (e) { e.preventDefault(); e.stopPropagation(); const id = $(this).data('delf'); if (confirm('Delete folder? Profiles inside move to Unfiled.')) WT.api('DELETE', '/folders/' + id).then(() => { S.folder = 'all'; tree(); }).catch(x => WT.fail(x)); });
  $('#newProfile, #profCards').on('click', '#newProfile, #emptyNew', e => { e.preventDefault(); openWizard(null); });
  $('#newProfile').on('click', () => openWizard(null));
  $(document).on('click', '[data-edit]', function () { WT.get('/profiles/' + $(this).data('edit')).then(openWizard).catch(e => WT.fail(e)); });
  $(document).on('click', '[data-run]', function () {
    const id = $(this).data('run');
    WT.post('/profiles/' + id + '/run').then(r => { WT.ok('Run #' + r.run_id + ' started'); location.href = '/scan-results/' + r.run_id; }).catch(e => WT.fail(e));
  });
  $(document).on('click', '[data-toggle]', function () { WT.post('/profiles/' + $(this).data('toggle') + '/toggle').then(r => { WT.ok(r.enabled ? 'Enabled' : 'Disabled'); profiles(); }).catch(e => WT.fail(e)); });
  $(document).on('click', '[data-copy]', function () { WT.post('/profiles/' + $(this).data('copy') + '/copy').then(() => { WT.ok('Copied'); tree(); }).catch(e => WT.fail(e)); });
  $(document).on('click', '[data-delp]', function () { const id = $(this).data('delp'); if (confirm('Delete profile #' + id + '?')) WT.api('DELETE', '/profiles/' + id).then(() => { WT.ok('Deleted'); tree(); }).catch(e => WT.fail(e)); });
  $('#pmNext').on('click', () => goStep(S.step + 1));
  $('#pmBack').on('click', () => goStep(S.step - 1));
  $('#pmSteps').on('click', 'li', function () { goStep($(this).data('step')); });
  $('#pmFamNone').on('click', () => $('.pmFam').prop('checked', false));
  $('#pmSchedType').on('change', schedFields);
  $(document).on('input change', '#pmSchedFields :input, .pmDay', schedPreview);
  $('#pmSave').on('click', function () {
    const b = profBody();
    if (!b.name || !b.target_url) { WT.warn('Name and target URL are required'); goStep(1); return; }
    const req = S.editing ? WT.api('PUT', '/profiles/' + S.editing, b) : WT.post('/profiles', b);
    req.then(r => { WT.ok('Profile saved'); bootstrap.Modal.getInstance('#profModal').hide();
      if (r.run_id) { location.href = '/scan-results/' + r.run_id; return; } tree(); }).catch(e => WT.fail(e));
  });
  $('#refreshProf').on('click', tree);
  $('#profSearch').on('input', profiles);

  $.when(WT.get('/sc/families'), WT.get('/sc/policies'), WT.get('/sensors')).then((f, p, s) => {
    S.families = f[0].families; S.policies = p[0].policies; S.sensors = s[0].sensors; tree();
  }).catch(e => WT.fail(e, 'Could not load scan references'));
  miniRunning();
  setInterval(() => { if (!document.hidden) miniRunning(); }, 5000);
})(jQuery, window.WT);
