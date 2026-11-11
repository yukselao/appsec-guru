(function ($, WT) {
  'use strict';
  const $p = $('#findingPage'), src = $p.data('src'), ref = $p.data('ref'), plugin = String($p.data('plugin')), base = $p.data('base');
  const n = parseInt($p.data('n'), 10) || null;
  const api = src === 'sc' ? `/sc/results/${encodeURIComponent(ref)}/findings/${plugin}` : `/scans/${ref}/findings/${plugin}`;
  const self = base + '/finding/' + plugin;
  const date = t => t ? new Date(t * 1000).toLocaleString('en-GB') : '–';
  const para = t => WT.esc(t || '').replace(/\n{2,}/g, '</p><p>').replace(/\n/g, '<br>');
  const row = (k, v) => v ? `<tr><th class="text-body-secondary fw-normal text-nowrap">${k}</th><td class="text-break">${v}</td></tr>` : '';
  const btn = (href, label, off) => `<a class="btn btn-sm btn-outline-secondary ${off ? 'disabled' : ''}" href="${href}">${label}</a>`;

  function header(d) {
    const p = d.plugin;
    $('#fdSev').html(WT.sevBadge(p.severity));
    $('#fdTitle').text(p.name || 'Plugin ' + plugin);
    $('#fdSub').text(`plugin ${p.plugin_id}${p.family ? ' · ' + p.family : ''} · ${d.count} instance${d.count === 1 ? '' : 's'}`);
    document.title = (p.name || 'Finding') + ' · ' + document.title.split(' · ').pop();
  }

  function reference(p) {
    const cvss = Object.entries(p.cvss || {}).map(([k, v]) => `<div><span class="text-body-secondary">${WT.esc(k)}</span> <span class="mono">${WT.esc(v)}</span></div>`).join('');
    return `<div class="card mb-3"><div class="card-header">About this plugin</div><div class="card-body">
      ${p.synopsis && p.synopsis !== p.name ? `<p class="fw-semibold">${WT.esc(p.synopsis)}</p>` : ''}
      <h3 class="h6">Description</h3><p>${para(p.description) || '<span class="text-body-secondary">None.</span>'}</p>
      ${p.solution ? `<h3 class="h6">Solution</h3><p>${para(p.solution)}</p>` : ''}
      ${p.see_also.length ? `<h3 class="h6">See also</h3><ul class="mb-0">${p.see_also.filter(u => /^https?:\/\//i.test(u)).map(u => `<li><a href="${WT.esc(u)}" target="_blank" rel="noopener noreferrer" class="text-break">${WT.esc(u)}</a></li>`).join('')}</ul>` : ''}
    </div></div>
    <div class="card"><div class="card-header">Plugin reference</div><div class="card-body p-0"><table class="table table-sm mb-0"><tbody>
      ${row('Risk factor', WT.esc(p.risk_factor))}${row('CVE', p.cve.map(WT.esc).join(', '))}${row('References', p.xref.map(WT.esc).join(', '))}
      ${row('Scores', cvss)}${row('Exploit available', WT.esc(p.exploit_available))}${row('Check type', WT.esc(p.check_type))}
      ${row('Plugin published', p.plugin_published ? date(p.plugin_published) : '')}${row('Plugin modified', p.plugin_modified ? date(p.plugin_modified) : '')}
    </tbody></table></div></div>`;
  }

  function list(d) {
    $('#fdNav').html(btn(base, 'Back to the result'));
    const excerpt = t => { t = (t || '').trim().replace(/\s+/g, ' '); return t.length > 140 ? t.slice(0, 140) + '…' : t; };
    $('#fdBody').html(`<div class="card mb-3"><div class="card-header">${d.count} instances of this finding</div>
      <div class="card-body p-0"><div class="table-responsive"><table class="table table-hover align-middle mb-0">
        <thead><tr><th>#</th><th>Host</th><th>Port</th><th>Output</th><th>First seen</th><th>Last seen</th><th></th></tr></thead>
        <tbody>${d.instances.map(i => `<tr>
          <td><a href="${self}/${i.n}">${i.n}</a></td><td class="mono small">${WT.esc(i.host)}</td><td class="small">${WT.esc(i.port)}/${WT.esc(i.protocol)}</td>
          <td class="small">${WT.esc(excerpt(i.output)) || '<span class="text-body-secondary">no output</span>'}${i.attachments.length ? ` <span class="badge text-bg-light border">${i.attachments.length} file${i.attachments.length === 1 ? '' : 's'}</span>` : ''}</td>
          <td class="small text-nowrap">${date(i.first_seen)}</td><td class="small text-nowrap">${date(i.last_seen)}</td>
          <td class="text-end"><a class="btn btn-sm btn-outline-primary" href="${self}/${i.n}">Open</a></td></tr>`).join('')}</tbody></table></div></div></div>
      ${reference(d.plugin)}`);
  }

  function attachments(d, i) {
    if (!i.attachments.length) return '<div class="text-body-secondary small">Security Center returned no files for this instance.</div>';
    if (!d.attachment_base) return `<ul class="mb-0">${i.attachments.map(a => `<li>${WT.esc(a.name)} <span class="mono small">${WT.esc(a.id)}</span></li>`).join('')}</ul>`;
    return i.attachments.map(a => {
      const url = d.attachment_base + encodeURIComponent(a.id);
      return `<div class="mb-3"><div class="d-flex align-items-center gap-2 mb-1"><span class="fw-semibold">${WT.esc(a.name)}</span>
        <a class="btn btn-sm btn-outline-secondary ms-auto" href="${url}" target="_blank" rel="noopener">Open file</a></div>
        <img src="${url}" alt="" class="img-fluid border rounded" loading="lazy" onerror="this.remove()"></div>`;
    }).join('');
  }

  function detail(d, i) {
    const many = d.count > 1;
    $('#fdNav').html((many ? btn(`${self}/${i.n - 1}`, 'Previous', i.n <= 1) + btn(`${self}/${i.n + 1}`, 'Next', i.n >= d.count) + btn(self, `All ${d.count} instances`) : '') + btn(base, 'Back to the result'));
    $('#fdBody').html(`<div class="row g-3">
      <div class="col-xl-8">
        <div class="card mb-3"><div class="card-header d-flex align-items-center">Plugin output${many ? ` <span class="badge text-bg-secondary ms-2">instance ${i.n} of ${d.count}</span>` : ''}
          <button class="btn btn-sm btn-outline-secondary ms-auto" id="fdCopy">Copy</button></div>
          <div class="card-body"><pre class="mono small mb-0" id="fdOut" style="white-space:pre-wrap;word-break:break-word">${WT.esc(i.output) || 'No output.'}</pre></div></div>
        <div class="card mb-3"><div class="card-header">Files</div><div class="card-body">${attachments(d, i)}</div></div>
        ${i.urls.length ? `<div class="card mb-3"><div class="card-header">URLs in the output</div><ul class="list-group list-group-flush small">${i.urls.map(u => `<li class="list-group-item mono text-break">${WT.esc(u)}</li>`).join('')}</ul></div>` : ''}
        ${reference(d.plugin)}
      </div>
      <div class="col-xl-4"><div class="card"><div class="card-header">This instance</div><div class="card-body p-0"><table class="table table-sm mb-0"><tbody>
        ${row('Severity', WT.sevBadge(d.plugin.severity))}${row('Family', WT.esc(d.plugin.family))}
        ${row('Host', `<span class="mono">${WT.esc(i.host)}</span>`)}${row('IP', i.ip !== i.host ? `<span class="mono">${WT.esc(i.ip)}</span>` : '')}
        ${row('Port', WT.esc(i.port) + '/' + WT.esc(i.protocol))}${row('First seen', date(i.first_seen))}${row('Last seen', date(i.last_seen))}
        ${row('Vulnerability id', `<span class="mono small">${WT.esc(i.vuln_uuid)}</span>`)}
      </tbody></table></div></div></div></div>`);
    $('#fdCopy').on('click', () => navigator.clipboard.writeText(i.output || '').then(() => WT.ok('Output copied')).catch(() => WT.warn('Could not copy')));
  }

  WT.get(api).then(d => {
    header(d);
    if (!n && d.count > 1) return list(d);
    const i = d.instances[(n || 1) - 1];
    if (!i) { $('#fdBody').html(`<div class="alert alert-warning">Instance ${n} does not exist; this finding has ${d.count}.</div>`); $('#fdNav').html(btn(self, 'All instances')); return; }
    detail(d, i);
  }).catch(e => { $('#fdBody').html(`<div class="alert alert-danger">${WT.esc(e)}</div>`); $('#fdNav').html(btn(base, 'Back to the result')); });
})(jQuery, window.WT);
