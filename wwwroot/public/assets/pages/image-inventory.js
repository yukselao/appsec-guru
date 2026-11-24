(function ($, WT) {
  'use strict';
  let all = [];
  const sev = (n, cls) => n ? `<span class="badge ${cls}">${n}</span>` : '<span class="text-body-secondary">0</span>';
  function draw() {
    const q = ($('#iiSearch').val() || '').toLowerCase();
    const rows = all.filter(x => !q || (x.image + ' ' + (x.os || '')).toLowerCase().includes(q));
    $('#iiBody').html(rows.length ? rows.map(x => { const b = x.by_severity || {};
      return `<tr>
        <td class="mono small text-truncate" style="max-width:260px" title="${WT.esc(x.image)}"><a href="/trivy-scan/${x.last_scan_id}">${WT.esc(x.image)}</a></td>
        <td class="small">${WT.esc(x.os || '—')}</td>
        <td class="mono small text-truncate" style="max-width:120px" title="${WT.esc(x.digest || '')}">${x.digest ? WT.esc(x.digest.slice(7, 19)) : '—'}</td>
        <td>${sev(b.Critical, 'text-bg-danger')}</td><td>${sev(b.High, 'text-bg-dark')}</td>
        <td>${b.Medium || 0}</td><td>${b.Low || 0}</td><td><b>${x.vulnerabilities}</b></td>
        <td class="${x.fixable ? 'text-success' : ''}">${x.fixable}</td>
        <td>${x.secrets ? `<span class="badge text-bg-warning">${x.secrets}</span>` : 0}</td>
        <td>${x.misconfigurations || 0}</td><td class="small">${x.packages || 0}</td>
        <td class="small">${x.scans}</td><td class="small">${WT.dt(x.last_scanned)}</td>
        <td><a class="btn btn-sm btn-link p-0" href="/trivy-scan?target=${encodeURIComponent(x.image)}">Re-scan</a></td></tr>`;
    }).join('') : '<tr><td colspan="15" class="empty px-3">No images scanned yet. <a href="/trivy-scan">Run a scan</a>.</td></tr>');
  }
  function load() { WT.get('/trivy/images').then(d => { all = d.images || []; draw(); }).catch(e => WT.fail(e)); }
  $('#iiSearch').on('input', draw);
  $('#iiRefresh').on('click', load);
  load();
})(jQuery, window.WT);
