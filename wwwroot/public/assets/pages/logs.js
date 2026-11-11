(function ($, WT) {
  'use strict';
  const MAXL = 10000, SHOW = 3000, LEVELS = ['DEBUG', 'INFO', 'NOTICE', 'WARN', 'ERROR'];
  let es = null, paused = false, lines = [], counts = {}, pend = [], raf = null;
  let bucket = {}, chRate = null, chLv = null;

  const levels = () => new Set($('.lv:checked').map((i, el) => el.value).get());
  const findRx = () => { const v = $('#lgFind').val(); if (!v) return null; try { return new RegExp(v, 'i'); } catch (e) { return null; } };
  const show = (l, lv, set, rx) => set.has(lv) && (!rx || rx.test(l));

  function state(text, kind) { $('#lgState').attr('class', 'badge text-bg-' + kind).text(text); }
  function drawCounts() {
    $('#lgCounts').text(`${lines.length} lines` + LEVELS.filter(k => counts[k]).map(k => ` · ${k} ${counts[k]}`).join('') + (lines.length >= MAXL ? ` · keeping the last ${MAXL}` : ''));
  }
  function redraw() {
    const set = levels(), rx = findRx(), out = [];
    for (const [l, v] of lines) if (show(l, v, set, rx)) out.push(WT.logHtml(l, rx));
    $('#lgView').html(out.slice(-SHOW).join(''));
    if ($('#lgScroll').prop('checked')) $('#lgView').scrollTop($('#lgView')[0].scrollHeight);
  }
  function flush() {
    raf = null; if (!pend.length) return;
    const set = levels(), rx = findRx(), view = $('#lgView')[0];
    let html = '';
    for (const [l, v] of pend) if (show(l, v, set, rx)) html += WT.logHtml(l, rx);
    pend = [];
    if (html) { view.insertAdjacentHTML('beforeend', html); while (view.childElementCount > SHOW) view.removeChild(view.firstChild); }
    if ($('#lgScroll').prop('checked')) view.scrollTop = view.scrollHeight;
    drawCounts();
  }

  function scans(selected) {
    return WT.get('/dashboard').then(d => {
      const act = d.scans.filter(s => s.has_dir);
      $('#lgScan').html('<option value="">Whole scanner log</option>' + act.map(s =>
        `<option value="${WT.esc(s.uuid)}">${WT.esc(s.uuid.slice(0, 8))} · ${WT.esc(s.target)}${(s.sc_ids || []).length ? ' · SC ' + WT.esc(s.sc_ids.join(',')) : ''}</option>`).join(''));
      if (selected) {
        if (!$('#lgScan option[value="' + selected + '"]').length) $('#lgScan').append(`<option value="${WT.esc(selected)}">${WT.esc(selected.slice(0, 8))} (may have finished)</option>`);
        $('#lgScan').val(selected);
      } else if (act.length === 1) $('#lgScan').val(act[0].uuid);
    }).catch(e => WT.fail(e));
  }

  function start() {
    stop();
    const p = new URLSearchParams({uuid: $('#lgScan').val(), grep: $('#lgGrep').val(), backlog: $('#lgBack').val() || '200'});
    if (WT.sensor()) p.set('sensor', WT.sensor());
    es = new EventSource('/api/logs/stream?' + p.toString());
    state('connecting', 'warning');
    es.onopen = () => { state('live', 'success'); WT.toast('Log stream connected'); };
    es.onerror = () => state('disconnected, retrying', 'danger');
    es.onmessage = ev => {
      if (paused) return;
      const l = ev.data, v = WT.lvl(l);
      lines.push([l, v]); counts[v] = (counts[v] || 0) + 1; bucket[v] = (bucket[v] || 0) + 1;
      if (lines.length > MAXL) lines.splice(0, lines.length - MAXL);
      pend.push([l, v]); if (!raf) raf = requestAnimationFrame(flush);
    };
    $('#lgStop,#lgPause').prop('disabled', false);
  }
  function stop() {
    if (es) { es.close(); es = null; }
    state('off', 'secondary'); $('#lgStop,#lgPause').prop('disabled', true);
    paused = false; $('#lgPause').text('Pause');
  }

  function charts() {
    const C = WT.LEVEL_COLORS;
    chRate = new Chart($('#chRate')[0], {type: 'line', data: {labels: [], datasets: LEVELS.map(k => ({label: k, data: [], borderColor: C[k], backgroundColor: C[k], tension: .3, pointRadius: 0, borderWidth: 1.5}))},
      options: {animation: false, plugins: {legend: {display: false}}, scales: {x: {ticks: {maxTicksLimit: 4}}, y: {beginAtZero: true, ticks: {precision: 0}}}}});
    chLv = new Chart($('#chLv')[0], {type: 'doughnut', data: {labels: LEVELS, datasets: [{data: LEVELS.map(() => 0), backgroundColor: LEVELS.map(k => C[k])}]},
      options: {animation: false, cutout: '60%', plugins: {legend: {position: 'bottom', labels: {boxWidth: 10}}}}});
  }
  setInterval(() => {
    if (!chRate) return;
    const t = new Date().toLocaleTimeString('en-GB');
    chRate.data.labels.push(t);
    chRate.data.datasets.forEach(ds => ds.data.push(bucket[ds.label] || 0));
    if (chRate.data.labels.length > 36) { chRate.data.labels.shift(); chRate.data.datasets.forEach(ds => ds.data.shift()); }
    bucket = {};
    chRate.update('none');
    chLv.data.datasets[0].data = LEVELS.map(k => counts[k] || 0); chLv.update('none');
  }, 10000);

  // AI attach provider for the chat panel.
  WT.logProvider = {
    label: () => 'live log, scan ' + ($('#lgScan').val() ? $('#lgScan').val().slice(0, 8) : 'all'),
    lines: onlyErr => {
      const set = levels(), rx = findRx();
      return lines.filter(([l, v]) => onlyErr ? (v === 'WARN' || v === 'ERROR') : show(l, v, set, rx)).map(x => x[0]);
    }
  };

  $('#lgStart').on('click', start);
  $('#lgStop').on('click', stop);
  $('#lgPause').on('click', function () { paused = !paused; $(this).text(paused ? 'Resume' : 'Pause'); state(paused ? 'paused' : 'live', paused ? 'secondary' : 'success'); });
  $('#lgClear').on('click', () => { lines = []; counts = {}; $('#lgView').empty(); drawCounts(); });
  $('#lgSave').on('click', () => {
    const b = new Blob([lines.map(x => x[0]).join('\n') + '\n'], {type: 'text/plain'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(b);
    a.download = 'was-log-' + ($('#lgScan').val() || 'all').slice(0, 8) + '-' + new Date().toISOString().replace(/[:.]/g, '-') + '.log';
    a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  });
  $('#lgAi').on('click', () => {
    const ls = WT.logProvider.lines(false);
    WT.chat.addAttach(`${WT.logProvider.label()} · ${ls.length} lines`, ls.join('\n'));
    WT.chat.open();
  });
  $('.chip').on('click', function () { $('#lgGrep').val($(this).data('preset')); start(); });
  $('.lv').on('change', redraw);
  let ft = null; $('#lgFind').on('input', () => { clearTimeout(ft); ft = setTimeout(redraw, 250); });
  $(document).on('wt:theme', () => { chRate.destroy(); chLv.destroy(); charts(); });
  window.addEventListener('beforeunload', stop);

  charts();
  WT.sensorSelect('#lgSensor', {hideWhenSingle: true, onChange: () => { stop(); scans(); }});
  const want = (new URLSearchParams(location.search)).get('uuid');
  scans(want).then(() => { if (want) start(); });
})(jQuery, window.WT);
