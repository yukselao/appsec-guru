/* Shared renderer for the running-scans table (Dashboard, List Scans).
   A row whose scan is running on the scanner opens the live log on click. */
(function ($, WT) {
  'use strict';

  WT.runningRows = function (d, opts) {
    opts = opts || {};
    const now = Date.now() / 1000;
    const act = d.scans.filter(s => s.has_dir);
    const linked = new Set();
    const rows = d.sc.map(r => {
      const uuid = (r._uuids || [])[0];
      if (uuid) linked.add(uuid);
      const run = (opts.runsByResult || {})[String(r.id)];
      return `<tr class="${uuid ? 'row-link' : ''}" ${uuid ? `data-log="${WT.esc(uuid)}" title="Open the live log"` : ''}>
        <td>${WT.esc(r.id)}</td>
        <td>${WT.esc(r.name)}${run ? ` <a class="small" href="/scan-results/${run.id}" onclick="event.stopPropagation()">run #${run.id}</a>` : ''}</td>
        <td>${WT.statusBadge(r.status)}</td>
        <td>${r.startTime > 0 ? WT.dur(now - r.startTime) : ''}</td>
        <td>${WT.esc((r._scanners || []).join(', '))}</td>
        <td>${(r._targets || []).map(t => WT.esc(t.url) + ' ' + WT.statusBadge(t.status)).join('<br>')}</td>
        <td class="mono">${uuid ? WT.esc(uuid.slice(0, 8)) : '<span class="text-body-secondary">waiting for the scanner</span>'}</td>
        <td class="text-end text-nowrap">${uuid ? `<a class="btn btn-sm btn-outline-primary" href="/logs?uuid=${encodeURIComponent(uuid)}">Live log</a> ` : ''}<button class="btn btn-sm btn-outline-danger" data-stop="${WT.esc(r.id)}">Stop</button></td></tr>`;
    });
    act.filter(s => !linked.has(s.uuid)).forEach(s => rows.push(`<tr class="row-link" data-log="${WT.esc(s.uuid)}" title="Open the live log">
        <td>–</td><td>on the scanner only</td><td>${WT.statusBadge('running')}</td><td></td><td></td>
        <td>${WT.esc(s.target)}</td><td class="mono">${WT.esc(s.uuid.slice(0, 8))}</td>
        <td class="text-end"><a class="btn btn-sm btn-outline-primary" href="/logs?uuid=${encodeURIComponent(s.uuid)}">Live log</a></td></tr>`));
    return rows.length ? rows.join('') : `<tr><td colspan="8" class="empty px-3">No scan is running. <a href="/create-scan">Create a scan</a>.</td></tr>`;
  };

  $(document).on('click', 'tr.row-link[data-log]', function (e) {
    if ($(e.target).closest('a,button').length) return;
    location.href = '/logs?uuid=' + encodeURIComponent($(this).data('log'));
  });
  $(document).on('click', '[data-stop]', function () {
    const id = $(this).data('stop');
    if (!confirm(`Stop scan result ${id} on Security Center?`)) return;
    WT.post(`/sc/results/${id}/stop`).then(() => { WT.toast('Stop request sent', 'success'); $(document).trigger('wt:refresh'); })
      .catch(e => WT.toast(e, 'danger'));
  });
})(jQuery, window.WT);
