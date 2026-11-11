(function ($, WT) {
  'use strict';
  // Each finding opens its own page; with several instances that page lists them first.
  const findTable = (f, base) => f.length ? f.map(x => {
    const href = `${base}/finding/${encodeURIComponent(x.plugin_id)}`;
    return `<tr><td class="mono"><a href="${href}">${WT.esc(x.plugin_id)}</a></td><td><a href="${href}">${WT.esc(x.name)}</a></td>
      <td>${WT.sevBadge(x.severity)}</td><td class="small">${WT.esc(x.family)}</td>
      <td class="text-end">${x.count > 1 ? `<a class="badge rounded-pill text-bg-primary text-decoration-none" href="${href}" title="Show the ${x.count} instances">${x.count}</a>` : x.count}</td></tr>`;
  }).join('')
    : '<tr><td colspan="5" class="empty px-3">No findings (if the scan is still running, they arrive when it ends).</td></tr>';

  // ------------------------------------------------------------- list view
  function loadRuns() {
    WT.get('/scans').then(r => {
      $('#runsBody').html(r.runs.length ? r.runs.map(x => `<tr>
        <td><a href="/scan-results/${x.id}">${x.id}</a></td><td><a href="/scan-results/${x.id}">${WT.esc(x.name)}</a></td>
        <td class="small">${WT.esc(x.target_url)}</td><td class="small">${WT.esc((x.families || []).join(', ') || 'from policy')}</td>
        <td>${WT.esc(x.debug_mode)}</td><td>${WT.statusBadge(x.status)}${x.active ? ' <span class="spinner-border spinner-border-sm text-warning"></span>' : ''}</td>
        <td>${x.duration_s ? WT.dur(x.duration_s) : ''}</td>
        <td>${Object.entries(x.severity).map(([k, v]) => WT.sevBadge(k) + ' ' + v).join(' ')}</td>
        <td class="text-end">${(x.log_counts || {}).total || 0}</td><td class="small">${WT.dt(x.created_at)}</td></tr>`).join('')
        : '<tr><td colspan="10" class="empty px-3">No runs yet. Start one from <a href="/create-scan">Create Scan</a>.</td></tr>');
    }).catch(e => { WT.fail(e); $('#runsBody').html('<tr><td colspan="10" class="empty px-3">Could not load runs.</td></tr>'); });
  }
  function loadSc() {
    WT.get('/sc/results?days=30').then(r => {
      $('#scBody').html(r.results.length ? r.results.map(x => `<tr><td>${WT.esc(x.id)}</td><td>${WT.esc(x.name)}</td><td>${WT.esc(x.resultType)}</td>
        <td>${WT.statusBadge(x.status)}</td><td class="small">${x.startTime > 0 ? new Date(x.startTime * 1000).toLocaleString('en-GB') : ''}</td>
        <td>${x.scanDuration > 0 ? WT.dur(x.scanDuration) : ''}</td>
        <td class="text-end"><a class="btn btn-sm btn-outline-primary" href="/scan-results/sc/${encodeURIComponent(x.id)}">Open</a></td></tr>`).join('')
        : '<tr><td colspan="7" class="empty px-3">No results in the last 30 days.</td></tr>');
    }).catch(e => { WT.fail(e); $('#scBody').html('<tr><td colspan="7" class="empty px-3">Could not load results.</td></tr>'); });
  }
  // ------------------------------------------------- Security Center result page
  const scId = $('#scDetail').data('result');
  if (scId) {
    WT.get('/sc/results/' + scId).then(r => {
      const res = r.result, notes = [];
      ((res.progress || {}).scanners || []).forEach(s => (s.errorNotes || []).forEach(n => notes.push(n.errorNotes)));
      $('#sdTitle').text(`${res.name} · Security Center result ${res.id}`);
      $('#sdStatus').html(WT.statusBadge(res.status));
      const tg = [];
      ((res.progress || {}).scanners || []).forEach(s => (s.targets || []).forEach(t => tg.push(t.targetUrl + ' @ ' + s.name)));
      const card = (l, v) => `<div class="col-6 col-md-3"><div class="card stat-card h-100"><div class="card-body"><div class="value" style="font-size:1.1rem">${v}</div><div class="label">${l}</div></div></div></div>`;
      $('#sdCards').html(card('Duration', WT.dur(res.scanDuration)) + card('Started', res.startTime > 0 ? new Date(res.startTime * 1000).toLocaleString('en-GB') : '–')
        + card('Import', WT.esc(res.importStatus || '–')) + card('Target / scanner', `<span class="small">${WT.esc(tg.join(', ') || '–')}</span>`));
      $('#sdNotes').html(notes.length ? `<div class="card mb-3"><div class="card-header">Scanner notes</div><div class="card-body small" style="white-space:pre-wrap">${WT.esc(notes.join('\n'))}</div></div>` : '');
      $('#sdFind').html(findTable(r.findings, '/scan-results/sc/' + encodeURIComponent(scId)));
      const sev = {}; r.findings.forEach(f => { sev[f.severity] = (sev[f.severity] || 0) + 1; });
      const order = ['Critical', 'High', 'Medium', 'Low', 'Info'], colors = ['#1c2126', '#2f4a52', '#c98a2b', '#2f9c8b', '#9aa6ad'];
      new Chart($('#chSdSev')[0], {type: 'doughnut', data: {labels: order, datasets: [{data: order.map(k => sev[k] || 0), backgroundColor: colors}]},
        options: {cutout: '60%', plugins: {legend: {position: 'bottom'}}}});
    }).catch(e => WT.fail(e));
  }

  // ----------------------------------------------------------- detail view
  const runId = $('#runDetail').data('run');
  let run = null, charts = {}, logLines = [];

  function card(label, value, cls) {
    return `<div class="col-6 col-md-4 col-xl-2"><div class="card stat-card h-100"><div class="card-body">
      <div class="value ${cls || ''}" style="font-size:1.25rem">${value}</div><div class="label">${label}</div></div></div></div>`;
  }
  function renderDetail(r) {
    run = r;
    $('#rdTitle').text(`Run #${r.id} · ${r.name}`);
    $('#rdStatus').html(WT.statusBadge(r.status) + (r.active ? ' <span class="spinner-border spinner-border-sm text-warning"></span>' : ''));
    $('#rdCancel').prop('hidden', !r.active);
    $('#rdLive').prop('hidden', !(r.active && r.scan_uuid));
    const lc = r.log_counts || {};
    $('#rdCards').html([
      card('Target', `<span class="small">${WT.esc(r.target_url)}</span>`),
      card('Duration', r.duration_s ? WT.dur(r.duration_s) : (r.started_at ? WT.dur((Date.now() - new Date(r.started_at)) / 1000) : '–')),
      card('SC result / scan', `${WT.esc(r.sc_result_id || '–')} / ${WT.esc(r.sc_scan_id || '–')}`),
      card('Policy (source → copy)', `${WT.esc(r.source_policy_id)} → ${WT.esc(r.derived_policy_id || 'same')}`),
      card('Log lines', `${lc.total || 0} <span class="small text-warning">W ${lc.warn || 0}</span> <span class="small text-danger">E ${lc.error || 0}</span>`),
      card('Findings', Object.entries(r.severity).map(([k, v]) => WT.sevBadge(k) + ' ' + v).join(' ') || '0'),
    ].join('') + `<div class="col-12 small text-body-secondary">Families: ${WT.esc((r.families || []).join(', ') || 'from policy')} · debug: ${WT.esc(r.debug_mode)} · fast scope: ${r.fast ? 'yes' : 'no'} · scanner UUID: <span class="mono">${WT.esc(r.scan_uuid || '–')}</span>${r.error ? ` · <span class="text-danger">${WT.esc(r.error)}</span>` : ''}</div>`);
    $('#rdFind').html(findTable(r.findings || [], '/scan-results/' + runId));
    $('#rdEvents').html(r.events.map(e => `<div class="${e.level === 'error' ? 'text-danger' : e.level === 'warn' ? 'text-warning' : e.level === 'ok' ? 'text-success' : ''}">${new Date(e.ts).toLocaleTimeString('en-GB')} ${WT.esc(e.message)}</div>`).join('') || '<div class="empty">No events</div>');
    const ev = $('#rdEvents')[0]; ev.scrollTop = ev.scrollHeight;
    drawCharts(r.stats || []);
  }
  function upsert(id, cfg) {
    if (charts[id]) { charts[id].data = cfg.data; charts[id].update('none'); return; }
    charts[id] = new Chart($('#' + id)[0], cfg);
  }
  function drawCharts(stats) {
    const labels = stats.map(s => new Date(s.minute).toLocaleTimeString('en-GB', {hour: '2-digit', minute: '2-digit'}));
    const C = WT.LEVEL_COLORS;
    upsert('chLevels', {type: 'bar', data: {labels, datasets: ['debug', 'info', 'notice', 'warn', 'error'].map(k => ({label: k.toUpperCase(), data: stats.map(s => s[k]), backgroundColor: C[k.toUpperCase()], stack: 'l'}))},
      options: {plugins: {legend: {position: 'bottom', labels: {boxWidth: 10}}}, scales: {x: {stacked: true, ticks: {maxTicksLimit: 8}}, y: {stacked: true, beginAtZero: true}}}});
    upsert('chActivity', {type: 'line', data: {labels, datasets: [
      {label: 'pages audited', data: stats.map(s => s.pages_audited), borderColor: '#198754', backgroundColor: '#198754', tension: .3, pointRadius: 0},
      {label: 'plugins started', data: stats.map(s => s.plugins_started), borderColor: '#6f42c1', backgroundColor: '#6f42c1', tension: .3, pointRadius: 0},
      {label: 'URLs found', data: stats.map(s => s.urls_found), borderColor: '#fd7e14', backgroundColor: '#fd7e14', tension: .3, pointRadius: 0}]},
      options: {plugins: {legend: {position: 'bottom', labels: {boxWidth: 10}}}, scales: {x: {ticks: {maxTicksLimit: 8}}, y: {beginAtZero: true}}}});
    upsert('chReqs', {type: 'line', data: {labels, datasets: [{label: 'req/s', data: stats.map(s => s.req_per_sec), borderColor: '#0d6efd', backgroundColor: 'rgba(13,110,253,.15)', fill: true, tension: .3, pointRadius: 0, spanGaps: true}]},
      options: {plugins: {legend: {display: false}}, scales: {x: {ticks: {maxTicksLimit: 8}}, y: {beginAtZero: true}}}});
  }
  function loadDetail() {
    return WT.get('/scans/' + runId).then(renderDetail).catch(e => WT.fail(e));
  }
  function loadLog() {
    const q = new URLSearchParams({tail: '3000', grep: $('#rlGrep').val(), level: $('#rlLevel').val()});
    WT.get(`/scans/${runId}/log?` + q.toString()).then(r => {
      logLines = r.lines;
      $('#rlInfo').text(`${r.total} lines in the file · showing ${r.lines.length} (last 3000 matches)`);
      let rx = null; try { rx = $('#rlGrep').val() ? new RegExp($('#rlGrep').val(), 'i') : null; } catch (e) { rx = null; }
      $('#rlView').html(r.lines.map(l => WT.logHtml(l, rx)).join('') || '<div class="text-secondary">No log captured</div>');
      $('#rlView').scrollTop($('#rlView')[0].scrollHeight);
    }).catch(e => WT.fail(e));
  }

  if (scId) { /* handled above */ } else if (runId) {
    WT.logProvider = {label: () => `run #${runId} captured log`, lines: onlyErr => onlyErr ? logLines.filter(l => /\[(WARN|ERROR)\]/.test(l)) : logLines};
    loadDetail().then(loadLog);
    setInterval(() => { if (run && run.active && !document.hidden) { loadDetail(); } }, 6000);
    $('#rlLoad').on('click', loadLog);
    $('#rlGrep').on('keydown', e => { if (e.key === 'Enter') loadLog(); });
    $('#rlAi').on('click', () => { WT.chat.addAttach(`run #${runId} log · ${logLines.length} lines`, logLines.join('\n')); WT.chat.open(); });
    $('#rdLive').on('click', () => { location.href = '/logs?uuid=' + encodeURIComponent(run.scan_uuid); });
    $('#rdFindings').on('click', () => WT.post(`/scans/${runId}/refresh-findings`).then(r => { WT.ok(r.findings.length + ' findings loaded'); loadDetail(); }).catch(e => WT.fail(e)));
    $('#rdCancel').on('click', () => { if (confirm('Cancel the run and stop the scan on Security Center?')) WT.post(`/scans/${runId}/cancel`).then(() => WT.ok('Cancel requested')).catch(e => WT.fail(e)); });
    $('#rdDelete').on('click', () => {
      if (!confirm(`Delete run #${runId} and its log file? The scan and result on Security Center stay.`)) return;
      WT.api('DELETE', '/scans/' + runId).then(() => { location.href = '/scan-results'; }).catch(e => WT.fail(e));
    });
    let anTimer = null;
    function renderAnalysis(d) {
      if (!d || d.state === 'none') { $('#rdReport').prop('hidden', true); return; }
      if (d.state === 'running') { $('#rdAnalysis').html('<div class="alert alert-info py-2"><span class="spinner-border spinner-border-sm me-2"></span>The offensive-security agent is analysing the findings…</div>'); return; }
      if (d.state === 'failed') { $('#rdAnalysis').html(`<div class="alert alert-danger py-2">${WT.esc(d.error)}</div>`); return; }
      const a = d.analysis || {};
      $('#rdReport').prop('hidden', false).attr('href', d.report_url);
      const paths = (a.attack_paths || []).map(p => `<div class="card mb-2"><div class="card-body">
        <div>${WT.sevBadge((p.severity||'').replace(/^./,c=>c.toUpperCase()))} <b>${WT.esc(p.title)}</b> <span class="small text-body-secondary">likelihood ${WT.esc(p.likelihood||'')}</span></div>
        <ol class="small mt-2 mb-0">${(p.steps||[]).map(s=>`<li>${WT.esc(s)}</li>`).join('')}</ol></div></div>`).join('');
      const recon = (a.recon||[]).map(r=>`<tr><td class="mono">${WT.esc(r.plugin_id)}</td><td>${WT.esc(r.fact)}</td><td>${WT.esc(r.why_it_matters)}</td></tr>`).join('');
      $('#rdAnalysis').html(`<div class="card mb-3 border-primary"><div class="card-header d-flex align-items-center">AI offensive analysis
        <span class="ms-2">${WT.sevBadge((a.risk_rating||'').replace(/^./,c=>c.toUpperCase()))}</span>
        <a class="btn btn-sm btn-outline-primary ms-auto" href="${d.report_url}" target="_blank" rel="noopener">Open HTML report</a></div>
        <div class="card-body">
          <p>${WT.esc(a.summary||'')}</p>
          <h3 class="h6 mt-3">Attack paths</h3>${paths||'<div class="empty">None.</div>'}
          <div class="row g-3 mt-1"><div class="col-lg-7"><h3 class="h6">Quick wins</h3><ul class="small">${(a.quick_wins||[]).map(w=>`<li>${WT.esc(w)}</li>`).join('')||'<li class="empty">None.</li>'}</ul></div>
          <div class="col-lg-5"><h3 class="h6">Reconnaissance</h3><table class="table table-sm small"><tbody>${recon||'<tr><td class="empty">None.</td></tr>'}</tbody></table></div></div>
        </div></div>`);
    }
    function pollAnalysis(initial) {
      WT.get('/scans/' + runId + '/analysis').then(d => {
        renderAnalysis(d);
        clearInterval(anTimer);
        if (d.state === 'running') anTimer = setInterval(() => WT.get('/scans/' + runId + '/analysis').then(x => { renderAnalysis(x); if (x.state !== 'running') { clearInterval(anTimer); if (x.state === 'done') WT.ok('AI analysis ready'); } }), 4000);
      });
    }
    $('#rdAnalyze').on('click', function () {
      $(this).prop('disabled', true);
      WT.post('/scans/' + runId + '/analyze', {}).then(() => { WT.ok('AI analysis started'); pollAnalysis(); })
        .catch(e => WT.fail(e)).always(() => $(this).prop('disabled', false));
    });
    pollAnalysis();
    $(document).on('wt:theme', () => { Object.values(charts).forEach(c => c.destroy()); charts = {}; drawCharts(run ? run.stats : []); });
  } else {
    loadRuns();
    setInterval(() => { if (!document.hidden && $('#tabRuns').hasClass('active')) loadRuns(); }, 8000);
    $('#tabScBtn').one('shown.bs.tab', loadSc);
    if (location.hash === '#sc') bootstrap.Tab.getOrCreateInstance('#tabScBtn').show();
  }
})(jQuery, window.WT);
