(function ($, WT) {
  'use strict';
  let sel = null, editId = null;
  const esc = WT.esc;

  function resetForm() {
    editId = null;
    $('#rgId').val(''); $('#rgForm')[0].reset();
    $('#rgFormTitle').text('Add registry'); $('#rgSave').text('Save');
    $('#rgCancel, #rgNew').addClass('d-none'); $('#rgTokenNote').text('');
  }
  function editRow(r) {
    editId = r.id;
    $('#rgId').val(r.id); $('#rgName').val(r.name); $('#rgHost').val(r.host);
    $('#rgUser').val(r.username || ''); $('#rgToken').val(''); $('#rgInsecure').prop('checked', r.insecure);
    $('#rgFormTitle').text('Edit registry #' + r.id); $('#rgSave').text('Update');
    $('#rgCancel, #rgNew').removeClass('d-none');
    $('#rgTokenNote').html(r.has_token ? 'A token is stored. Leave blank to keep it; type a new one to replace it. <a href="#" id="rgClear">Remove token</a>' : '');
  }

  function list() {
    return WT.get('/registries').then(d => {
      const rs = d.registries || [];
      $('#rgCount').text(rs.length);
      $('#rgList').html(rs.length ? rs.map(r => `<li class="list-group-item ${r.id === (sel && sel.id) ? 'active-row' : ''}">
        <div class="d-flex align-items-center gap-2">
          <a href="#" data-sel="${r.id}" class="fw-semibold text-truncate" title="${esc(r.host)}">${esc(r.name)}</a>
          ${r.insecure ? '<span class="badge text-bg-warning">http</span>' : ''}
          ${r.has_token ? '<span class="badge text-bg-light border" title="authenticated">🔑</span>' : ''}
          <span class="ms-auto"></span>
          <a href="#" class="small" data-test="${r.id}">Test</a>
          <a href="#" class="small" data-edit="${r.id}">Edit</a>
          <a href="#" class="small text-danger" data-del="${r.id}">✕</a></div>
        <div class="mono text-body-secondary">${esc(r.host)}${r.username ? ' · ' + esc(r.username) : ''}</div>
        <div class="small d-none" data-teststate="${r.id}"></div></li>`).join('')
        : '<li class="list-group-item empty">No registries yet. Add one above.</li>');
      window._rgRows = rs;
      return rs;
    });
  }
  function select(id) {
    sel = (window._rgRows || []).find(r => r.id === id) || null;
    $('#rgSel').text(sel ? sel.host : '');
    $('#rgCatalog, #rgRepo, #rgTags').prop('disabled', !sel);
    $('#rgRepos').html('<li class="list-group-item empty">Load catalog, or type a repository and List tags.</li>');
    $('#rgTagList').html('<li class="list-group-item empty">Pick a repository to list its tags.</li>');
    $('#rgRepoLbl').text('');
    list();
  }

  function loadCatalog() {
    if (!sel) return;
    $('#rgRepos').html('<li class="list-group-item empty">Loading…</li>');
    WT.get(`/registries/${sel.id}/catalog`).then(d => {
      if (d.error) { $('#rgRepos').html(`<li class="list-group-item small text-warning">${esc(d.error)}</li>`); return; }
      const rs = d.repositories || [];
      $('#rgRepos').html(rs.length ? rs.map(r => `<li class="list-group-item"><a href="#" data-repo="${esc(r)}" class="mono">${esc(r)}</a></li>`).join('')
        : '<li class="list-group-item empty">No repositories.</li>');
    }).catch(e => WT.fail(e));
  }
  function listTags(repo) {
    if (!sel || !repo) return;
    $('#rgRepo').val(repo); $('#rgRepoLbl').text(repo);
    $('#rgTagList').html('<li class="list-group-item empty">Loading…</li>');
    WT.get(`/registries/${sel.id}/tags?repo=${encodeURIComponent(repo)}`).then(d => {
      if (d.error) { $('#rgTagList').html(`<li class="list-group-item small text-warning">${esc(d.error)}</li>`); return; }
      const ts = d.tags || [];
      $('#rgTagList').html(ts.length ? ts.map(t => `<li class="list-group-item d-flex align-items-center gap-2">
        <span class="mono">${esc(t)}</span>
        <button class="btn btn-sm btn-primary py-0 ms-auto" data-scan="${esc(t)}">Scan</button></li>`).join('')
        : '<li class="list-group-item empty">No tags.</li>');
    }).catch(e => WT.fail(e));
  }
  function scan(repo, tag) {
    if (!sel) return;
    WT.post(`/registries/${sel.id}/scan`, {repo: repo, tag: tag, scanners: ['vuln', 'secret']}).then(d => {
      WT.ok('Scan #' + d.run_id + ' started for ' + d.image);
      setTimeout(() => { window.location.href = '/trivy-scan/' + d.run_id; }, 600);
    }).catch(e => WT.fail(e));
  }

  $('#rgForm').on('submit', function (e) {
    e.preventDefault();
    const body = {name: $('#rgName').val().trim(), host: $('#rgHost').val().trim(),
      username: $('#rgUser').val().trim(), token: $('#rgToken').val(), insecure: $('#rgInsecure').is(':checked')};
    $('#rgSave').prop('disabled', true);
    const req = editId ? WT.api('PUT', '/registries/' + editId, body) : WT.post('/registries', body);
    req.then(() => { WT.ok(editId ? 'Updated' : 'Added'); resetForm(); list(); })
      .catch(e => WT.fail(e)).always(() => $('#rgSave').prop('disabled', false));
  });
  $('#rgCancel, #rgNew').on('click', resetForm);
  $(document).on('click', '#rgClear', function (e) { e.preventDefault(); if (editId) WT.api('PUT', '/registries/' + editId, {name: $('#rgName').val().trim(), host: $('#rgHost').val().trim(), username: $('#rgUser').val().trim(), insecure: $('#rgInsecure').is(':checked'), clear_token: true}).then(() => { WT.ok('Token removed'); list(); $('#rgTokenNote').text(''); }); });
  $(document).on('click', '[data-sel]', function (e) { e.preventDefault(); select(parseInt($(this).data('sel'), 10)); });
  $(document).on('click', '[data-edit]', function (e) { e.preventDefault(); const r = (window._rgRows || []).find(x => x.id === $(this).data('edit')); if (r) editRow(r); });
  $(document).on('click', '[data-del]', function (e) { e.preventDefault(); const id = $(this).data('del'); if (!confirm('Delete this registry connection?')) return; WT.api('DELETE', '/registries/' + id).then(() => { WT.ok('Deleted'); if (sel && sel.id === id) { sel = null; $('#rgSel').empty(); $('#rgCatalog,#rgRepo,#rgTags').prop('disabled', true); } list(); }).catch(e => WT.fail(e)); });
  $(document).on('click', '[data-test]', function (e) {
    e.preventDefault(); const id = $(this).data('test'); const $s = $(`[data-teststate="${id}"]`).removeClass('d-none').html('<span class="text-body-secondary">testing…</span>');
    WT.get('/registries/' + id + '/test').then(r => { $s.html(r.ok ? '<span class="text-success">✓ reachable, authenticated</span>' : r.reachable ? `<span class="text-warning">reachable (HTTP ${r.status}) — ${esc(r.detail || '')}</span>` : `<span class="text-danger">✕ ${esc(r.error || r.detail || 'unreachable')}</span>`); }).catch(e => $s.html('<span class="text-danger">✕ error</span>'));
  });
  $('#rgCatalog').on('click', loadCatalog);
  $('#rgTags').on('click', () => listTags($('#rgRepo').val().trim()));
  $('#rgRepo').on('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); listTags($('#rgRepo').val().trim()); } });
  $(document).on('click', '[data-repo]', function (e) { e.preventDefault(); listTags($(this).attr('data-repo')); });
  $(document).on('click', '[data-scan]', function () { scan($('#rgRepo').val().trim(), $(this).attr('data-scan')); });

  resetForm();
  list();
})(jQuery, window.WT);
