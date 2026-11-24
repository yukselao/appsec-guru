(function ($, WT) {
  'use strict';
  let all = [];
  function cards() {
    const by = {Critical: 0, High: 0, Medium: 0, Low: 0, Unknown: 0};
    all.forEach(c => { by[c.severity] = (by[c.severity] || 0) + 1; });
    const card = (l, n, cls) => `<div class="col"><div class="card stat-card h-100"><div class="card-body py-2 text-center"><div class="value ${cls || ''}">${n}</div><div class="label small">${l}</div></div></div></div>`;
    $('#ivCards').html(card('Unique CVEs', all.length) + card('Critical', by.Critical, 'text-danger') +
      card('High', by.High) + card('Medium', by.Medium) + card('Low', by.Low) +
      card('Fixable', all.filter(c => c.fixed).length, 'text-success'));
  }
  function draw() {
    const sev = $('#ivSev').val(), fix = $('#ivFixable').prop('checked'), q = ($('#ivSearch').val() || '').toLowerCase();
    const rows = all.filter(c => (!sev || c.severity === sev) && (!fix || c.fixed) &&
      (!q || (c.cve + ' ' + (c.packages || []).join(' ') + ' ' + c.title).toLowerCase().includes(q)));
    $('#ivBody').html(rows.length ? rows.map((c, i) => `
      <tr class="iv-row" data-i="${i}" style="cursor:pointer">
        <td class="text-body-secondary">▸</td><td>${WT.sevBadge(c.severity)}</td>
        <td class="mono small"><a href="${WT.esc(c.url)}" target="_blank" rel="noopener" onclick="event.stopPropagation()">${WT.esc(c.cve)}</a></td>
        <td class="small">${WT.esc(c.cvss || '')}</td><td><span class="badge text-bg-secondary">${c.image_count}</span></td>
        <td class="small">${c.fixed ? `<span class="text-success mono">${WT.esc(c.fixed)}</span>` : '<span class="text-body-secondary">—</span>'}</td>
        <td class="small">${WT.esc(c.title)}</td></tr>
      <tr class="iv-detail d-none" data-d="${i}"><td></td><td colspan="6" class="small">
        <div class="mb-1"><b>Packages:</b> ${(c.packages || []).map(p => `<span class="mono">${WT.esc(p)}</span>`).join(', ')}</div>
        <div><b>Affected images:</b> ${c.images.map(im => `<a class="mono me-2" href="/trivy-scan/${im.scan_id}">${WT.esc(im.image)}</a>`).join('')}</div>
      </td></tr>`).join('') : '<tr><td colspan="7" class="empty px-3">No CVEs match.</td></tr>');
  }
  function load() { WT.get('/trivy/vulnerabilities').then(d => { all = d.cves || []; cards(); draw(); }).catch(e => WT.fail(e)); }
  $(document).on('click', '.iv-row', function () { $(`.iv-detail[data-d="${$(this).data('i')}"]`).toggleClass('d-none'); $(this).find('td:first').text($(this).next('.iv-detail').hasClass('d-none') ? '▸' : '▾'); });
  $('#ivSev, #ivFixable').on('change', draw);
  $('#ivSearch').on('input', draw);
  $('#ivRefresh').on('click', load);
  load();
})(jQuery, window.WT);
