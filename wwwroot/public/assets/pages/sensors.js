(function ($, WT) {
  'use strict';
  let MASK = '__SET__', editing = null;
  const FIELDS = {snName: 'name', snDesc: 'description', snHost: 'host', snPort: 'port', snUser: 'username',
    snPass: 'password', snKey: 'key_path', snLog: 'log_path', snJump: 'jump_host', snJumpUser: 'jump_user',
    snJumpPass: 'jump_password', snScName: 'sc_scanner_name', snZone: 'zone_id'};
  const SECRET = new Set(['snPass', 'snJumpPass']);

  function load() {
    WT.get('/sensors').then(r => {
      MASK = r.secret_mask || MASK;
      $('#snCards').html(r.sensors.length ? r.sensors.map(card).join('')
        : '<div class="col-12"><div class="empty">No sensors yet. <a href="#" id="snFirst">Add the first one</a>.</div></div>');
    }).catch(e => WT.fail(e));
  }
  function card(s) {
    return `<div class="col"><div class="card h-100">
      <div class="card-header d-flex align-items-center gap-2"><span class="fw-semibold">${WT.esc(s.name)}</span>
        ${s.is_default ? '<span class="badge text-bg-primary">default</span>' : ''}<span class="badge text-bg-light border ms-auto mono">${WT.esc(s.username)}@${WT.esc(s.host)}:${s.port}</span></div>
      <div class="card-body">
        <div class="small text-body-secondary">${WT.esc(s.description || '')}</div>
        <div class="small mt-1">log ${WT.esc(s.log_path)}${s.jump_host ? ' · jump ' + WT.esc(s.jump_host) : ''}${s.sc_scanner_name ? ' · SC scanner ' + WT.esc(s.sc_scanner_name) : ''}</div>
        <div class="small mt-1" data-status="${s.id}"></div>
      </div>
      <div class="card-footer d-flex flex-wrap gap-2">
        <button class="btn btn-sm btn-outline-primary" data-test="${s.id}">Test</button>
        <button class="btn btn-sm btn-outline-secondary" data-edit="${s.id}">Edit</button>
        ${s.is_default ? '' : `<button class="btn btn-sm btn-outline-secondary" data-default="${s.id}">Make default</button>`}
        <button class="btn btn-sm btn-outline-danger ms-auto" data-del="${s.id}">Delete</button>
      </div></div></div>`;
  }
  function open(s) {
    editing = s ? s.id : null;
    $('#snTitle').text(s ? 'Edit sensor' : 'Add sensor');
    $('#snTest').prop('disabled', !s);
    Object.entries(FIELDS).forEach(([el, key]) => {
      const v = s ? s[key] : '';
      if (SECRET.has(el)) { $('#' + el).val(v === MASK ? MASK : '').attr('placeholder', v === MASK ? 'set (type to change)' : ''); }
      else $('#' + el).val(v == null ? '' : v);
    });
    if (!s) { $('#snPort').val(22); $('#snUser').val('osadmin'); $('#snLog').val('/var/log/nessus-was/scanner.log'); }
    $('#snDefault').prop('checked', s ? s.is_default : false);
    bootstrap.Modal.getOrCreateInstance('#snModal').show();
  }
  function body() {
    const b = {}; Object.entries(FIELDS).forEach(([el, key]) => { b[key] = $('#' + el).val(); });
    b.is_default = $('#snDefault').prop('checked');
    return b;
  }

  $('#snNew').on('click', () => open(null));
  $(document).on('click', '#snFirst', e => { e.preventDefault(); open(null); });
  $(document).on('click', '[data-edit]', function () { WT.get('/sensors/' + $(this).data('edit')).then(open).catch(e => WT.fail(e)); });
  $('#snSave').on('click', function () {
    const b = body(); if (!b.name || !b.host) { WT.warn('Name and host are required'); return; }
    const req = editing ? WT.api('PUT', '/sensors/' + editing, b) : WT.post('/sensors', b);
    req.then(() => { WT.ok('Sensor saved'); bootstrap.Modal.getInstance('#snModal').hide(); load(); }).catch(e => WT.fail(e));
  });
  $('#snTest').on('click', function () { if (editing) testSensor(editing); });
  $(document).on('click', '[data-test]', function () { testSensor($(this).data('test')); });
  function testSensor(id) {
    $(`[data-status="${id}"]`).html('<span class="text-body-secondary">Testing…</span>');
    WT.post('/sensors/' + id + '/test').then(r => {
      const msg = `${r.host} via ${r.method} · service ${r.debug.active} · log ${r.log_readable ? 'readable' : 'not readable'} · sudo ${r.sudo ? 'yes' : 'no'}`;
      $(`[data-status="${id}"]`).html(`<span class="text-success">✓ ${WT.esc(msg)}</span>`);
      WT.ok(msg, 'Sensor reachable');
    }).catch(e => { $(`[data-status="${id}"]`).html(`<span class="text-danger">× ${WT.esc(e)}</span>`); WT.fail(e, 'Sensor unreachable'); });
  }
  $(document).on('click', '[data-default]', function () { WT.post('/sensors/' + $(this).data('default') + '/default').then(() => { WT.ok('Default sensor changed'); load(); }).catch(e => WT.fail(e)); });
  $(document).on('click', '[data-del]', function () { const id = $(this).data('del'); if (confirm('Delete sensor #' + id + '?')) WT.api('DELETE', '/sensors/' + id).then(() => { WT.ok('Deleted'); load(); }).catch(e => WT.fail(e)); });

  load();
})(jQuery, window.WT);
