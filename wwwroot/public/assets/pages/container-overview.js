(function ($, WT) {
  'use strict';
  function card(label, value, cls) {
    return `<div class="col-6 col-md-3 col-xl-2"><div class="card stat-card h-100"><div class="card-body py-2 text-center">
      <div class="value ${cls || ''}">${value}</div><div class="label small">${label}</div></div></div></div>`;
  }
  function load() {
    WT.get('/trivy/overview').then(d => {
      const by = d.by_severity || {};
      $('#coCards').html(
        card('Images', d.images) + card('Scans', d.scans) + card('Vulnerable images', d.vulnerable_images, 'text-danger') +
        card('Critical', by.Critical || 0) + card('High', by.High || 0) + card('Medium', by.Medium || 0) +
        card('Low', by.Low || 0) + card('Fixable', d.fixable, 'text-success') +
        card('Total vulns', d.total_vulnerabilities) + card('Secrets', d.secrets) +
        card('Secret images', d.secret_images) + card('Misconfig', d.misconfigurations));
      $('#coImages').html((d.most_vulnerable || []).length ? d.most_vulnerable.map(x => { const b = x.by_severity || {};
        return `<tr><td class="mono small text-truncate" style="max-width:280px" title="${WT.esc(x.target)}">${WT.esc(x.target)}</td>
        <td>${b.Critical ? `<span class="badge text-bg-danger">${b.Critical}</span>` : 0}</td>
        <td>${b.High ? `<span class="badge text-bg-dark">${b.High}</span>` : 0}</td>
        <td>${b.Medium || 0}</td><td>${b.Low || 0}</td><td><b>${x.vulnerabilities}</b></td></tr>`; }).join('')
        : '<tr><td colspan="6" class="empty px-3">No vulnerable images yet.</td></tr>');
      $('#coCves').html((d.top_cves || []).length ? d.top_cves.map(c => `<li class="list-group-item d-flex align-items-center">
        <span class="mono small">${WT.esc(c.cve)}</span><span class="badge text-bg-secondary ms-auto">${c.count}</span></li>`).join('')
        : '<li class="list-group-item empty">No CVEs yet.</li>');
      $('#coRecent').html((d.recent || []).length ? d.recent.map(x => { const st = x.stats || {};
        return `<tr><td><a href="/trivy-scan/${x.id}">${x.id}</a></td>
        <td class="mono small text-truncate" style="max-width:320px" title="${WT.esc(x.target)}">${WT.esc(x.target)}</td>
        <td>${WT.statusBadge(x.status)}</td><td>${st.vulnerabilities ?? 0}</td><td>${st.secrets ?? 0}</td><td>${st.misconfigurations ?? 0}</td>
        <td class="small">${WT.dt(x.created_at)}</td></tr>`; }).join('')
        : '<tr><td colspan="7" class="empty px-3">No scans yet. <a href="/trivy-scan">Start one</a>.</td></tr>');
    }).catch(e => WT.fail(e));
  }
  $('#coRefresh').on('click', load);
  load();
})(jQuery, window.WT);
