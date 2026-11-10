(function ($, WT) {
  'use strict';
  const runId = $('#sastDetail').data('run');

  // ----------------------------------------------------------- list view
  if (!runId) {
    const list = () => WT.get('/sast').then(r => {
      $('#sastRuns').html(r.runs.length ? r.runs.map(x => {
        const f = (x.stats || {}).findings || {};
        const fc = Object.entries(f).map(([k, v]) => WT.sevBadge(k[0].toUpperCase() + k.slice(1)) + ' ' + v).join(' ');
        return `<tr><td><a href="/sast-scan/${x.id}">${x.id}</a></td><td class="small mono text-truncate" style="max-width:280px">${WT.esc(x.repo_url)}</td>
          <td>${WT.statusBadge(x.status)}${x.active ? ' <span class="spinner-border spinner-border-sm text-primary"></span>' : ''}</td>
          <td class="small">${(x.stats || {}).analysed || 0}/${(x.stats || {}).candidates || 0}</td><td>${fc || '0'}</td>
          <td class="small">${WT.dt(x.created_at)}</td><td class="text-end"><a class="btn btn-sm btn-outline-secondary" href="/sast-scan/${x.id}">Open</a></td></tr>`;
      }).join('') : '<tr><td colspan="7" class="empty px-3">No SAST runs yet.</td></tr>');
    }).catch(e => WT.fail(e));
    $('#sastForm').on('submit', function (e) {
      e.preventDefault();
      const body = {repo_url: $('#scRepo').val().trim(), ref: $('#scRef').val().trim(), token: $('#scToken').val(),
        max_functions: parseInt($('#scMax').val() || '40', 10), min_severity: $('#scMinSev').val(), include_tests: $('#scTests').prop('checked')};
      if (!/^https:\/\//.test(body.repo_url)) { WT.warn('Enter an https repository URL'); return; }
      $('#scGo').prop('disabled', true);
      WT.post('/sast', body).then(r => { WT.ok('SAST run #' + r.run_id + ' started'); location.href = '/sast-scan/' + r.run_id; })
        .catch(e => WT.fail(e)).always(() => $('#scGo').prop('disabled', false));
    });
    list(); setInterval(() => { if (!document.hidden) list(); }, 5000);
    return;
  }

  // ----------------------------------------------------------- detail view
  let chart = null, timer = null;
  const SEV = ['critical', 'high', 'medium', 'low'];
  const CP = {critical: '#1c2126', high: '#2f4a52', medium: '#c98a2b', low: '#2f9c8b'};

  function render(x) {
    const st = x.stats || {};
    $('#sdTitle').text('SAST run #' + x.id + ' · ' + (x.repo_url || '').replace(/^https:\/\//, ''));
    $('#sdStatus').html(WT.statusBadge(x.status) + (x.active ? ' <span class="spinner-border spinner-border-sm text-primary"></span>' : ''));
    $('#sdCancel').prop('hidden', !x.active);
    const card = (l, v) => `<div class="col-6 col-md-3"><div class="card stat-card h-100"><div class="card-body"><div class="value" style="font-size:1.2rem">${v}</div><div class="label">${l}</div></div></div></div>`;
    const fcount = Object.values(st.findings || {}).reduce((a, b) => a + b, 0);
    $('#sdCards').html(card('Files', st.files || 0) + card('Functions', st.functions || 0)
      + card('Analysed', `${st.analysed || 0}/${st.candidates || 0}`) + card('Findings', fcount)
      + (x.commit ? card('Commit', `<span class="mono small">${WT.esc(x.commit.slice(0, 10))}</span>`) : '')
      + (st.tokens ? card('LLM tokens', `${(st.tokens.prompt || 0) + (st.tokens.eval || 0)}`) : '')
      + (st.mode ? card('Mode', st.mode) : '') + (x.error ? `<div class="col-12"><div class="alert alert-danger py-2 mb-0">${WT.esc(x.error)}</div></div>` : ''));

    const sevFilter = $('#sdSev').val();
    const fs = (x.findings || []).filter(f => !sevFilter || f.severity === sevFilter);
    $('#sdFindings').html(fs.length ? fs.map((f, i) => `<div class="accordion-item">
      <h2 class="accordion-header"><button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#f${i}">
        ${WT.sevBadge(f.severity[0].toUpperCase() + f.severity.slice(1))}<span class="ms-2 fw-semibold">${WT.esc(f.title)}</span>
        <span class="ms-2 small text-body-secondary">${WT.esc(f.cwe || '')} · ${WT.esc(f.file)}:${f.line || '?'} · confidence ${WT.esc(f.confidence)}</span></button></h2>
      <div id="f${i}" class="accordion-collapse collapse" data-bs-parent="#sdFindings"><div class="accordion-body small">
        ${f.function ? `<div><b>Function:</b> <span class="mono">${WT.esc(f.function)}</span>${f.parameter ? ' · parameter <span class="mono">' + WT.esc(f.parameter) + '</span>' : ''}</div>` : ''}
        <p class="mt-2 mb-1">${WT.esc(f.description || '')}</p>
        ${f.evidence ? `<pre class="code">${WT.esc(f.evidence)}</pre>` : ''}
        ${f.recommendation ? `<div class="mt-2"><b>Fix:</b> ${WT.esc(f.recommendation)}</div>` : ''}</div></div></div>`).join('')
      : `<div class="empty p-3">${x.active ? 'Analysing…' : 'No findings.'}</div>`);

    $('#sdFns').html((x.functions || []).map(fn => `<li class="list-group-item d-flex align-items-center gap-2">
      <span class="text-truncate"><span class="mono">${WT.esc(fn.name)}</span> <span class="text-body-secondary">${WT.esc(fn.file)}</span></span>
      ${fn.verdict ? `<span class="badge text-bg-${fn.verdict === 'vulnerable' ? 'dark' : fn.verdict === 'safe' ? 'primary' : 'secondary'} ms-auto">${WT.esc(fn.verdict)}</span>` : (fn.status === 'candidate' ? '<span class="badge text-bg-light border ms-auto">queued</span>' : '')}
      <span class="badge text-bg-light border">${(fn.sinks || []).length} sinks</span></li>`).join('') || '<li class="list-group-item empty">No candidate functions.</li>');
    $('#sdEvents').html((x.events || []).map(e => `<div class="${e.level === 'error' ? 'text-danger' : e.level === 'warn' ? 'text-warning' : ''}">${WT.time(e.ts)} ${WT.esc(e.message)}</div>`).join(''));
    const ev = $('#sdEvents')[0]; if (ev) ev.scrollTop = ev.scrollHeight;

    const data = SEV.map(s => (x.findings || []).filter(f => f.severity === s).length);
    if (!chart) chart = new Chart($('#chSastSev')[0], {type: 'doughnut', data: {labels: SEV, datasets: [{data, backgroundColor: SEV.map(s => CP[s])}]}, options: {cutout: '58%', plugins: {legend: {position: 'bottom'}}}});
    else { chart.data.datasets[0].data = data; chart.update('none'); }
  }
  function load() { return WT.get('/sast/' + runId).then(x => { render(x); if (!x.active) clearInterval(timer); }).catch(e => WT.fail(e)); }
  $('#sdSev').on('change', load);
  $('#sdCancel').on('click', () => { if (confirm('Cancel this SAST run?')) WT.post('/sast/' + runId + '/cancel').then(() => WT.ok('Cancel requested')); });
  $('#sdDelete').on('click', () => { if (confirm('Delete SAST run #' + runId + '?')) WT.api('DELETE', '/sast/' + runId).then(() => { location.href = '/sast-scan'; }).catch(e => WT.fail(e)); });
  load(); timer = setInterval(() => { if (!document.hidden) load(); }, 4000);
})(jQuery, window.WT);
