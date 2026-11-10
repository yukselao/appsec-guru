(function ($, WT) {
  'use strict';
  let chRuns = null, chSev = null;

  function stat(k, v) { $(`[data-stat="${k}"]`).text(v == null ? '–' : v); }

  function render(d) {
    $('#dashErr').html(d.errors.map(e => `<div class="alert alert-warning py-2">${WT.esc(e)}</div>`).join(''));
    stat('sc', d.sc.length); stat('scanner', d.scans.filter(s => s.has_dir).length); stat('chrome', d.chrome);
    stat('load', d.load ? d.load.load.split(' ')[0] : null); stat('mem', d.load ? d.load.mem.split('/')[0] + ' MB' : null);
    const dbg = d.debug || {};
    $('#dbgLevel').text((dbg.level || '–').replace('(varsayilan)', '(default)'));
    $('#dbgSvc').attr('class', 'badge text-bg-' + (dbg.active === 'active' ? 'success' : 'danger')).text(dbg.active ? 'service ' + dbg.active : '–');
    const byResult = {};
    d.runs.recent.forEach(r => { if (r.sc_result_id) byResult[r.sc_result_id] = r; });
    $('#dashRunning').html(WT.runningRows(d, {runsByResult: byResult}));
    $('#dashRecent').html(d.runs.recent.length ? d.runs.recent.map(r => `<tr>
      <td><a href="/scan-results/${r.id}">${r.id}</a></td><td>${WT.esc(r.name)}</td><td class="small">${WT.esc(r.target_url)}</td>
      <td>${WT.statusBadge(r.status)}</td><td>${r.duration_s ? WT.dur(r.duration_s) : ''}</td>
      <td>${Object.entries(r.severity).map(([k, v]) => WT.sevBadge(k) + ' ' + v).join(' ')}</td><td class="small">${WT.dt(r.created_at)}</td></tr>`).join('')
      : '<tr><td colspan="7" class="empty px-3">No runs yet. Start one from <a href="/create-scan">Create Scan</a>.</td></tr>');
    drawCharts(d);
  }

  function drawCharts(d) {
    const days = [], counts = [];
    for (let i = 13; i >= 0; i--) {
      const dt = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
      days.push(dt.slice(5)); counts.push((d.runs.daily.find(x => x.day === dt) || {}).count || 0);
    }
    if (!chRuns) chRuns = new Chart($('#chRuns')[0], {type: 'bar', data: {labels: days, datasets: [{label: 'runs', data: counts, backgroundColor: '#0d6efd'}]},
      options: {plugins: {legend: {display: false}}, scales: {y: {beginAtZero: true, ticks: {precision: 0}}}}});
    else { chRuns.data.labels = days; chRuns.data.datasets[0].data = counts; chRuns.update('none'); }

    const sev = {Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0};
    d.runs.recent.forEach(r => Object.entries(r.severity).forEach(([k, v]) => { sev[k] = (sev[k] || 0) + v; }));
    const labels = Object.keys(sev), data = labels.map(k => sev[k]);
    if (!chSev) chSev = new Chart($('#chSev')[0], {type: 'doughnut', data: {labels, datasets: [{data, backgroundColor: ['#1c2126', '#2f4a52', '#c98a2b', '#2f9c8b', '#9aa6ad']}]},
      options: {plugins: {legend: {position: 'right'}}, cutout: '60%'}});
    else { chSev.data.datasets[0].data = data; chSev.update('none'); }
  }

  function load() {
    WT.get('/dashboard').then(render).catch(e => $('#dashErr').html(`<div class="alert alert-danger">${WT.esc(e)}</div>`));
    WT.get('/sast?limit=10').then(r => stat('sast', r.runs.reduce((n, x) => n + Object.values((x.stats || {}).findings || {}).reduce((a, b) => a + b, 0), 0)));
  }

  $('[data-debug]').on('click', function () {
    const on = $(this).data('debug') === 1;
    if (!confirm(`Set the scanner log level to ${on ? 'DEBUG' : 'info'}? The scanner service restarts.`)) return;
    const $b = $(this).prop('disabled', true);
    WT.post('/scanner/debug', {on}).then(r => { WT.toast('Log level: ' + r.debug.level, 'success'); load(); })
      .catch(e => WT.toast(e, 'danger')).always(() => $b.prop('disabled', false));
  });
  $(document).on('wt:refresh', load);
  $(document).on('wt:theme', () => { [chRuns, chSev].forEach(c => c && c.destroy()); chRuns = chSev = null; load(); });

  load();
  setInterval(() => { if ($('#dashAuto').prop('checked') && !document.hidden) load(); }, 5000);
})(jQuery, window.WT);
