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
      $('#snCards [data-bs-toggle="tooltip"]').each((i, el) => bootstrap.Tooltip.getOrCreateInstance(el));
      r.sensors.forEach(sn => refreshDebug(sn.id));
    }).catch(e => WT.fail(e));
  }
  const DEBUG_HELP = 'Enabling raises this scanner’s log level to DEBUG (WAS_LOG_LEVEL=debug): every scan writes '
    + 'detailed per-request lines, which the Logs page streams live. It restarts the scanner service, so it is refused '
    + 'while a scan is running, and it increases log volume. Turn it off to return to the normal info level.';
  function card(s) {
    return `<div class="col"><div class="card h-100">
      <div class="card-header d-flex align-items-center gap-2"><span class="fw-semibold">${WT.esc(s.name)}</span>
        ${s.is_default ? '<span class="badge text-bg-primary">default</span>' : ''}<span class="badge text-bg-light border ms-auto mono">${WT.esc(s.username)}@${WT.esc(s.host)}:${s.port}</span></div>
      <div class="card-body">
        <div class="small text-body-secondary">${WT.esc(s.description || '')}</div>
        <div class="small mt-1">log ${WT.esc(s.log_path)}${s.jump_host ? ' · jump ' + WT.esc(s.jump_host) : ''}${s.sc_scanner_name ? ' · SC scanner ' + WT.esc(s.sc_scanner_name) : ''}</div>
        <div class="d-flex align-items-center gap-2 mt-3 p-2 rounded border bg-body-tertiary">
          <div class="form-check form-switch mb-0"><input class="form-check-input" type="checkbox" role="switch" id="dbg${s.id}" data-dbg="${s.id}" disabled>
            <label class="form-check-label small" for="dbg${s.id}">Scanner debug</label></div>
          <span class="dbg-state small text-body-secondary" data-dbgstate="${s.id}">checking…</span>
          <a href="#" class="ms-auto text-body-secondary" tabindex="0" role="button"
             data-bs-toggle="tooltip" data-bs-placement="left" data-bs-title="${WT.esc(DEBUG_HELP)}" aria-label="What does enabling do?">
             <svg class="ic" viewBox="0 0 24 24" style="width:17px;height:17px"><circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><circle cx="12" cy="7.5" r=".6" fill="currentColor" stroke="none"/></svg></a>
        </div>
        <div class="small mt-1" data-status="${s.id}"></div>
      </div>
      <div class="card-footer d-flex flex-wrap gap-2">
        <button class="btn btn-sm btn-outline-primary" data-test="${s.id}">Test</button>
        <button class="btn btn-sm btn-outline-secondary" data-edit="${s.id}">Edit</button>
        ${s.is_default ? '' : `<button class="btn btn-sm btn-outline-secondary" data-default="${s.id}">Make default</button>`}
        <button class="btn btn-sm btn-outline-danger ms-auto" data-del="${s.id}">Delete</button>
      </div></div></div>`;
  }

  function refreshDebug(id) {
    WT.post('/sensors/' + id + '/test').then(r => {
      const on = /debug/i.test(r.debug.level) && !/info|default/i.test(r.debug.level);
      $(`[data-dbg="${id}"]`).prop('disabled', false).prop('checked', on);
      $(`[data-dbgstate="${id}"]`).text(on ? 'DEBUG · verbose logging' : 'info (normal)');
    }).catch(() => { $(`[data-dbgstate="${id}"]`).text('unreachable'); });
  }
  function refreshAllDebug() { WT.get('/sensors').then(r => r.sensors.forEach(s => refreshDebug(s.id))); }

  $(document).on('change', '[data-dbg]', function () {
    const id = $(this).data('dbg'), on = this.checked;
    if (!confirm(`Set the scanner log level to ${on ? 'DEBUG' : 'info'}? The scanner service restarts; it is refused while a scan is running.`)) {
      this.checked = !on; return;
    }
    const $sw = $(this).prop('disabled', true);
    $(`[data-dbgstate="${id}"]`).text(on ? 'enabling…' : 'disabling…');
    WT.post('/scanner/debug', {on, sensor: id}).then(r => {
      WT.ok('Scanner log level: ' + r.debug.level, 'Debug ' + (on ? 'enabled' : 'disabled'));
      refreshDebug(id);
    }).catch(e => { WT.fail(e); this.checked = !on; refreshDebug(id); }).always(() => $sw.prop('disabled', false));
  });
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
