(function ($, WT) {
  'use strict';
  let rows = [];
  const srcBadge = s => s === 'trivy' ? '<span class="badge text-bg-info">Trivy</span>' : s === 'kubescape' ? '<span class="badge text-bg-primary">Kubescape</span>' : WT.esc(s);
  const typeLabel = {vulnerability: 'Vuln', misconfiguration: 'Misconfig', secret: 'Secret', 'k8s-control': 'K8s control'};
  function detail(f) {
    const d = f.detail || {};
    if (f.type === 'vulnerability') return `${WT.esc(d.package || '')} ${d.installed ? WT.esc(d.installed) : ''}${d.fixed ? ` → <span class="text-success">${WT.esc(d.fixed)}</span>` : ''}${d.cvss ? ` · CVSS ${WT.esc(d.cvss)}` : ''}`;
    if (f.type === 'secret') return `${WT.esc(d.category || '')} · ${WT.esc(d.file || '')}`;
    if (f.type === 'misconfiguration') return WT.esc((d.message || '').slice(0, 90));
    if (f.type === 'k8s-control') return `${WT.esc(d.category || '')} · ${d.failed_resources || 0} resource(s)`;
    return '';
  }
  function cards(sum) {
    const by = sum.by_severity || {}, src = sum.by_source || {};
    const card = (l, n, cls) => `<div class="col"><div class="card stat-card h-100"><div class="card-body py-2 text-center"><div class="value ${cls || ''}">${n || 0}</div><div class="label small">${l}</div></div></div></div>`;
    $('#fCards').html(card('Total', sum.total) + card('Critical', by.Critical, 'text-danger') + card('High', by.High) +
      card('Medium', by.Medium) + card('Low', by.Low) + card('Trivy', src.trivy) + card('Kubescape', src.kubescape));
  }
  function draw() {
    $('#fBody').html(rows.length ? rows.map(f => { const d = f.detail || {}; const link = (d.url || f.scan_page);
      return `<tr>
        <td>${WT.sevBadge(f.severity)}</td><td>${srcBadge(f.source)}</td><td class="small">${typeLabel[f.type] || f.type}</td>
        <td class="small">${d.url ? `<a href="${WT.esc(d.url)}" target="_blank" rel="noopener">${WT.esc(f.title)}</a>` : WT.esc(f.title)}</td>
        <td class="mono small">${WT.esc(f.identifier)}</td>
        <td class="mono small text-truncate" style="max-width:200px" title="${WT.esc(f.target)}"><a href="${WT.esc(f.scan_page)}">${WT.esc(f.target)}</a></td>
        <td class="small">${detail(f)}</td></tr>`;
    }).join('') : '<tr><td colspan="7" class="empty px-3">No findings match. Run a Trivy or Kubescape scan.</td></tr>');
    $('#fCount').text(rows.length);
  }
  function params() {
    const p = new URLSearchParams();
    if ($('#fSource').val()) p.set('source', $('#fSource').val());
    if ($('#fType').val()) p.set('type', $('#fType').val());
    if ($('#fSev').val()) p.set('severity', $('#fSev').val());
    if ($('#fSearch').val().trim()) p.set('q', $('#fSearch').val().trim());
    return p.toString();
  }
  function load() {
    WT.get('/findings/summary').then(cards);
    WT.get('/findings?' + params()).then(d => { rows = d.findings || []; $('#fShown').text(`showing ${rows.length} of ${d.total}`); draw(); }).catch(e => WT.fail(e));
  }
  function exportCsv() {
    const head = ['severity', 'source', 'type', 'title', 'identifier', 'target', 'scan_id'];
    const esc = v => '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"';
    const csv = [head.join(',')].concat(rows.map(f => head.map(h => esc(f[h])).join(','))).join('\n');
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([csv], {type: 'text/csv'})); a.download = 'findings.csv'; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }
  let t; $('#fSearch').on('input', () => { clearTimeout(t); t = setTimeout(load, 300); });
  $('#fSource, #fType, #fSev').on('change', load);
  $('#fRefresh').on('click', load);
  $('#fExport').on('click', exportCsv);
  load();
})(jQuery, window.WT);
