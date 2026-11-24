(function ($, WT) {
  'use strict';
  const card = (l, v, cls) => `<div class="col-6 col-md-3 col-xl-2"><div class="card stat-card h-100"><div class="card-body py-2 text-center"><div class="value ${cls || ''}">${v}</div><div class="label small">${l}</div></div></div></div>`;
  function load() {
    WT.get('/kubescape/overview').then(d => {
      const by = d.by_severity || {}, avg = d.avg_score;
      const scoreCls = avg == null ? '' : avg >= 80 ? 'text-success' : avg >= 50 ? 'text-warning' : 'text-danger';
      $('#kpCards').html(
        card('Manifest scans', d.scans) + card('Avg score', avg == null ? '—' : avg, scoreCls) +
        card('Failed controls', d.failed_controls, 'text-danger') + card('Failed resources', d.failed_resources) +
        card('Critical', by.Critical || 0) + card('High', by.High || 0) + card('Medium', by.Medium || 0) + card('Low', by.Low || 0));
      $('#kpControls').html((d.top_controls || []).length ? d.top_controls.map(c => `<li class="list-group-item d-flex align-items-center">
        <span>${WT.esc(c.name)}</span><span class="badge text-bg-secondary ms-auto">${c.count}</span></li>`).join('')
        : '<li class="list-group-item empty">No failing controls yet.</li>');
      $('#kpRecent').html((d.recent || []).length ? d.recent.map(x => { const st = x.stats || {};
        return `<tr><td><a href="/kubescape/${x.id}">${x.id}</a></td>
        <td class="text-truncate" style="max-width:160px" title="${WT.esc(x.name)}">${WT.esc(x.name)}</td>
        <td>${x.score == null ? '—' : `<span class="badge ${x.score >= 80 ? 'text-bg-success' : x.score >= 50 ? 'text-bg-warning' : 'text-bg-danger'}">${x.score}</span>`}</td>
        <td>${st.failed_controls ?? 0}</td><td class="small">${WT.dt(x.created_at)}</td></tr>`; }).join('')
        : '<tr><td colspan="5" class="empty px-3">No scans yet. <a href="/kubescape">Scan a manifest</a>.</td></tr>');
    }).catch(e => WT.fail(e));
  }
  $('#kpRefresh').on('click', load);
  load();
})(jQuery, window.WT);
