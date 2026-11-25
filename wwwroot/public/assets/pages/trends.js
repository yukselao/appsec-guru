(function ($, WT) {
  'use strict';
  let chart = null;
  const SEV = [['critical', 'Critical', '#dc3545'], ['high', 'High', '#fd7e14'], ['medium', 'Medium', '#e0a800'], ['low', 'Low', '#2f9c8b']];
  const source = () => $('input[name=trsrc]:checked').val();
  const esc = WT.esc;

  function drawCards(ov) {
    const by = {}; (ov.sources || []).forEach(s => by[s.source] = s);
    const s = by[source()] || {};
    const card = (l, n, cls, sub) => `<div class="col"><div class="card stat-card h-100"><div class="card-body py-2 text-center">
      <div class="value ${cls || ''}">${n == null ? '—' : n}</div><div class="label small">${l}</div>${sub ? `<div class="small text-body-secondary">${sub}</div>` : ''}</div></div></div>`;
    const d = s.delta;
    const deltaStr = d == null ? 'first scan' : d === 0 ? 'no change' : d > 0 ? `▲ ${d} vs previous` : `▼ ${Math.abs(d)} vs previous`;
    const deltaCls = d == null ? '' : d > 0 ? 'text-danger' : d < 0 ? 'text-success' : 'text-body-secondary';
    $('#trCards').html(
      card('Completed scans', s.scans) +
      card('Latest ' + (s.label || '').toLowerCase(), s.latest_total) +
      `<div class="col"><div class="card stat-card h-100"><div class="card-body py-2 text-center"><div class="value ${deltaCls}" style="font-size:1.1rem">${deltaStr}</div><div class="label small">Trend</div></div></div></div>`);
  }

  function drawChart(tl) {
    const pts = tl.points || [];
    $('#trChartTitle').text((tl.label || 'Findings') + ' over time');
    $('#trChartNote').text(pts.length ? `${pts.length} scan(s) · metric: ${tl.metric}` : '');
    $('#trChartEmpty').toggleClass('d-none', pts.length > 0);
    $('#trChart').toggle(pts.length > 0);
    if (chart) { chart.destroy(); chart = null; }
    if (!pts.length) return;
    const labels = pts.map(p => WT.dt(p.at));
    const datasets = SEV.map(([k, lbl, col]) => ({label: lbl, data: pts.map(p => p[k] || 0),
      borderColor: col, backgroundColor: col + '33', fill: true, tension: 0.25, pointRadius: 3}));
    chart = new Chart($('#trChart')[0], {type: 'line',
      data: {labels, datasets},
      options: {responsive: true, maintainAspectRatio: false, interaction: {mode: 'index', intersect: false},
        scales: {y: {stacked: true, beginAtZero: true, ticks: {precision: 0}}, x: {ticks: {maxRotation: 0, autoSkip: true}}},
        plugins: {legend: {position: 'bottom'}, tooltip: {callbacks: {afterTitle: items => pts[items[0].dataIndex].target}}}}});
  }

  function loadTop() {
    WT.get('/trends/overview').then(drawCards).catch(e => WT.fail(e));
    WT.get('/trends/timeline?source=' + source() + '&days=' + $('#trDays').val()).then(drawChart).catch(e => WT.fail(e));
    loadTargets();
  }
  function loadTargets() {
    return WT.get('/trends/targets?source=' + source()).then(d => {
      const ts = d.targets || [];
      $('#trTarget').html(ts.length ? ts.map((g, i) => `<option value="${i}">${esc(g.target)} (${g.scans.length})</option>`).join('')
        : '<option value="">— no target scanned twice —</option>');
      window._trTargets = ts;
      fillScans();
    });
  }
  function fillScans() {
    const ts = window._trTargets || [];
    const g = ts[parseInt($('#trTarget').val(), 10)];
    const opts = g ? g.scans.map(sc => `<option value="${sc.id}">#${sc.id} · ${WT.dt(sc.at)}</option>`).join('') : '';
    $('#trA').html(opts); $('#trB').html(opts);
    if (g && g.scans.length >= 2) { $('#trA').val(g.scans[0].id); $('#trB').val(g.scans[g.scans.length - 1].id); }
  }

  function row(f, tag) {
    const cls = tag === 'added' ? 'table-danger' : tag === 'removed' ? 'table-success' : '';
    return `<tr class="${cls}"><td>${WT.sevBadge(f.severity)}</td><td class="mono small">${esc(f.id)}</td>
      <td class="small">${esc(f.title)}</td><td class="small text-body-secondary">${esc(f.extra || '')}</td></tr>`;
  }
  function section(title, items, tag, cls) {
    return `<h6 class="mt-3 ${cls}">${title} <span class="badge text-bg-light border">${items.length}</span></h6>` +
      (items.length ? `<div class="table-responsive" style="max-height:32vh;overflow:auto"><table class="table table-sm align-middle mb-0">
        <thead><tr><th>Severity</th><th>ID</th><th>Finding</th><th></th></tr></thead><tbody>${items.map(f => row(f, tag)).join('')}</tbody></table></div>`
        : `<div class="empty px-2">none</div>`);
  }
  function compare() {
    const a = $('#trA').val(), b = $('#trB').val();
    if (!a || !b) { WT.warn('Pick two scans'); return; }
    if (a === b) { WT.warn('Pick two different scans'); return; }
    WT.get(`/trends/compare?source=${source()}&a=${a}&b=${b}`).then(d => {
      if (d.error) { WT.warn(d.error); return; }
      const s = d.summary;
      const card = (l, n, cls) => `<div class="col"><div class="card stat-card h-100"><div class="card-body py-2 text-center"><div class="value ${cls}">${n}</div><div class="label small">${l}</div></div></div></div>`;
      $('#trCmpSummary').removeClass('d-none').html(
        card('New', s.added, 'text-danger') + card('Fixed', s.removed, 'text-success') +
        card('Unchanged', s.unchanged, '') +
        card('Net change', (s.delta > 0 ? '+' : '') + s.delta, s.delta > 0 ? 'text-danger' : s.delta < 0 ? 'text-success' : ''));
      $('#trCmp').html(
        `<div class="small text-body-secondary">Baseline <b>#${d.a.id}</b> (${WT.dt(d.a.at)}, ${d.a.total}) → <b>#${d.b.id}</b> (${WT.dt(d.b.at)}, ${d.b.total}) · ${esc(d.a.target)}</div>` +
        section('New findings', d.added, 'added', 'text-danger') +
        section('Fixed / no longer present', d.removed, 'removed', 'text-success') +
        section('Still present', d.unchanged, 'unchanged', 'text-body-secondary'));
    }).catch(e => WT.fail(e));
  }

  $('input[name=trsrc]').on('change', loadTop);
  $('#trDays').on('change', () => WT.get('/trends/timeline?source=' + source() + '&days=' + $('#trDays').val()).then(drawChart));
  $('#trRefresh').on('click', loadTop);
  $('#trTarget').on('change', fillScans);
  $('#trCompare').on('click', compare);
  loadTop();
})(jQuery, window.WT);
