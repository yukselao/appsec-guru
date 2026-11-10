(function ($, WT) {
  'use strict';
  let watchId = null, watchTimer = null;
  const CODE = s => { s = String(s); return s[0] === '2' ? 'success' : s[0] === '3' ? 'primary' : s === '403' || s === '401' ? 'warning' : s[0] === '5' ? 'dark' : 'secondary'; };

  function wordlists() {
    WT.get('/fuzz/wordlists').then(r => {
      $('#fzWordlist').html(r.wordlists.map(w => `<option value="${WT.esc(w.name)}">${WT.esc(w.name)} (${w.words} words${w.builtin ? ', built-in' : ''})</option>`).join(''));
      $('#fzWl').html(r.wordlists.map(w => `<li class="list-group-item d-flex align-items-center gap-2">
        <span class="text-truncate">${WT.esc(w.name)}</span><span class="badge text-bg-secondary">${w.words}</span>
        ${w.builtin ? '<span class="badge text-bg-light border">built-in</span>' : `<button class="btn btn-sm btn-link text-danger ms-auto p-0" data-del-wl="${WT.esc(w.name)}">delete</button>`}</li>`).join(''));
    }).catch(e => WT.fail(e));
  }

  function renderRun(r) {
    $('#fzState').html(WT.statusBadge(r.status) + (r.active ? ' <span class="spinner-border spinner-border-sm text-primary"></span>' : ''));
    $('#fzCancel').prop('disabled', !r.active);
    $('#fzExport').prop('disabled', !r.hits.length);
    const st = r.stats || {};
    const byStatus = st.by_status || {};
    $('#fzStats').html(
      `<div class="col-auto"><span class="badge text-bg-primary">${r.hits.length}</span> found</div>` +
      `<div class="col-auto text-body-secondary small">wordlist ${WT.esc(r.wordlist)} · ${r.total_words || '?'} words · ${WT.esc(r.methods)}</div>` +
      Object.entries(byStatus).map(([c, n]) => `<div class="col-auto"><span class="badge text-bg-${CODE(c)}">${c}</span> ${n}</div>`).join(''));
    if (r.error) $('#fzStats').append(`<div class="col-12"><div class="alert alert-danger py-1 mb-0 small">${WT.esc(r.error)}</div></div>`);
    const q = ($('#fzSearch').val() || '').toLowerCase();
    const hits = r.hits.filter(h => !q || (h.path || '').toLowerCase().includes(q));
    $('#fzHits').html(hits.length ? hits.map(h => `<tr>
      <td><span class="badge text-bg-${CODE(h.status)}">${h.status}</span></td>
      <td class="mono"><a href="${WT.esc(h.url)}" target="_blank" rel="noopener">${WT.esc(h.path)}</a></td>
      <td>${h.length}</td><td>${h.words}</td><td>${h.lines}</td><td class="small text-truncate" style="max-width:200px">${WT.esc(h.redirect)}</td></tr>`).join('')
      : `<tr><td colspan="6" class="empty px-3">${r.active ? 'Scanning…' : (r.status === 'completed' ? 'No hidden paths matched.' : '—')}</td></tr>`);
    if (r.total_words) {
      const done = r.active ? Math.min(95, Math.round(r.hits.length / r.total_words * 100) + 5) : 100;
      $('#fzProg').css('width', done + '%').toggleClass('bg-primary', true);
    }
  }

  function watch(id) {
    watchId = id;
    clearInterval(watchTimer);
    const tick = () => WT.get('/fuzz/' + id).then(r => { renderRun(r); if (!r.active) { clearInterval(watchTimer); runs(); } });
    tick();
    watchTimer = setInterval(tick, 2000);
  }

  function runs() {
    WT.get('/fuzz?limit=30').then(r => {
      $('#fzRuns').html(r.runs.length ? r.runs.map(x => `<tr class="${x.id === watchId ? 'table-active' : ''}">
        <td><a href="#" data-open="${x.id}">${x.id}</a></td><td class="small mono text-truncate" style="max-width:240px">${WT.esc(x.target_url)}</td>
        <td class="small">${WT.esc(x.wordlist)}</td><td>${WT.statusBadge(x.status)}</td><td>${(x.stats || {}).found ?? x.hits.length}</td>
        <td class="small">${WT.dt(x.created_at)}</td>
        <td class="text-end"><a class="btn btn-sm btn-outline-secondary" href="#" data-open="${x.id}">Open</a>
          <button class="btn btn-sm btn-outline-danger" data-del="${x.id}" ${x.active ? 'disabled' : ''}>Delete</button></td></tr>`).join('')
        : '<tr><td colspan="7" class="empty px-3">No discovery runs yet.</td></tr>');
    });
  }

  $('#fzForm').on('submit', function (e) {
    e.preventDefault();
    const headers = $('#fzHeaders').val().split('\n').map(l => l.trim()).filter(Boolean).map(l => {
      const i = l.indexOf(':'); return i > 0 ? {name: l.slice(0, i).trim(), value: l.slice(i + 1).trim()} : null;
    }).filter(Boolean);
    const body = {target_url: $('#fzUrl').val().trim(), wordlist: $('#fzWordlist').val(), extensions: $('#fzExt').val().trim(),
      methods: $('#fzMethods').val(), match_codes: $('#fzMatch').val().trim(), filter_codes: $('#fzFilter').val().trim(),
      threads: parseInt($('#fzThreads').val() || '40', 10), rate: parseInt($('#fzRate').val() || '0', 10), extra_headers: headers};
    if (!/^https?:\/\//.test(body.target_url)) { WT.warn('Enter a target URL'); return; }
    $('#fzGo').prop('disabled', true);
    WT.post('/fuzz', body).then(r => { WT.ok('Discovery #' + r.run_id + ' started'); watch(r.run_id); runs(); })
      .catch(e => WT.fail(e)).always(() => $('#fzGo').prop('disabled', false));
  });
  $('#fzSearch').on('input', () => { if (watchId) WT.get('/fuzz/' + watchId).then(renderRun); });
  $('#fzCancel').on('click', () => { if (watchId) WT.post('/fuzz/' + watchId + '/cancel').then(() => WT.ok('Cancel requested')); });
  $('#fzExport').on('click', () => { if (watchId) WT.get('/fuzz/' + watchId).then(r => {
    const txt = r.hits.map(h => `${h.status}\t${h.length}\t${h.url}`).join('\n');
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([txt], {type: 'text/plain'}));
    a.download = `hidden-paths-${watchId}.txt`; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }); });
  $(document).on('click', '[data-open]', function (e) { e.preventDefault(); watch(parseInt($(this).data('open'), 10)); });
  $(document).on('click', '[data-del]', function () {
    const id = $(this).data('del'); if (!confirm('Delete discovery run #' + id + '?')) return;
    WT.api('DELETE', '/fuzz/' + id).then(() => { WT.ok('Deleted'); if (watchId === id) { clearInterval(watchTimer); watchId = null; } runs(); }).catch(e => WT.fail(e));
  });
  $(document).on('click', '[data-del-wl]', function () {
    const n = $(this).data('del-wl'); if (!confirm('Delete wordlist ' + n + '?')) return;
    WT.api('DELETE', '/fuzz/wordlists/' + encodeURIComponent(n)).then(() => { WT.ok('Deleted'); wordlists(); }).catch(e => WT.fail(e));
  });
  $('#fzUpload').on('click', () => bootstrap.Modal.getOrCreateInstance('#wlModal').show());
  $('#wlFile').on('change', function () {
    const f = this.files[0]; if (!f) return;
    if (!$('#wlName').val()) $('#wlName').val(f.name.replace(/[^A-Za-z0-9._-]/g, '_'));
    const rd = new FileReader(); rd.onload = () => $('#wlContent').val(rd.result); rd.readAsText(f);
  });
  $('#wlSave').on('click', function () {
    const name = $('#wlName').val().trim(), content = $('#wlContent').val();
    if (!name || !content.trim()) { WT.warn('Give a name and some words'); return; }
    WT.post('/fuzz/wordlists', {name, content}).then(r => { WT.ok(`Saved ${r.name} (${r.words} words)`); bootstrap.Modal.getInstance('#wlModal').hide(); $('#wlName,#wlContent').val(''); wordlists(); })
      .catch(e => WT.fail(e));
  });

  const t = new URLSearchParams(location.search).get('target');
  if (t) $('#fzUrl').val(t);
  wordlists(); runs();
})(jQuery, window.WT);
