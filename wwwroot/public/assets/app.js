/* Tenable WAS Cockpit: shared helpers, connection badge, theme, AI chat. */
(function ($) {
  'use strict';
  const WT = window.WT = {};

  WT.esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));

  // The active sensor is chosen on each page (in its form/controls), not a global widget.
  WT._sensor = (function () { try { return localStorage.getItem('wt-sensor') || ''; } catch (e) { return ''; } })();
  WT.sensor = function () { return WT._sensor || ''; };
  WT.setSensor = function (id) { WT._sensor = id ? String(id) : ''; try { localStorage.setItem('wt-sensor', WT._sensor); } catch (e) { /* ignore */ } };
  // Fills a <select> with sensors and remembers the choice; opts.onChange(id) fires on change.
  WT.sensorSelect = function (el, opts) {
    opts = opts || {};
    return WT.get('/sensors').then(r => {
      const list = r.sensors || []; const $el = $(el);
      if (!list.length) { $el.closest('[data-sensor-wrap]').addClass('d-none'); return list; }
      const cur = WT.sensor(); const def = (list.find(x => x.is_default) || list[0] || {});
      const val = cur && list.some(x => String(x.id) === cur) ? cur : String(def.id);
      $el.html(list.map(x => `<option value="${x.id}">${WT.esc(x.name)}${x.is_default ? ' (default)' : ''}</option>`).join('')).val(val);
      WT.setSensor(val);
      if (list.length < 2 && opts.hideWhenSingle) $el.closest('[data-sensor-wrap]').addClass('d-none');
      $el.off('change.wtsensor').on('change.wtsensor', function () { WT.setSensor(this.value); if (opts.onChange) opts.onChange(this.value); });
      return list;
    });
  };
  WT.api = function (method, path, data) {
    const headers = {}; const sid = WT.sensor(); if (sid) headers['X-Sensor'] = sid;
    return $.ajax({url: '/api' + path, method: method, contentType: 'application/json', dataType: 'json', headers: headers,
      data: data === undefined ? undefined : JSON.stringify(data)})
      .catch(xhr => {
        const msg = (xhr.responseJSON && (xhr.responseJSON.detail || xhr.responseJSON.error)) || xhr.statusText || 'request failed';
        return $.Deferred().reject(typeof msg === 'string' ? msg : JSON.stringify(msg)).promise();
      });
  };
  WT.get = p => WT.api('GET', p);
  WT.post = (p, d) => WT.api('POST', p, d || {});

  // Standard notification: every success, warning and error message goes through here
  // and shows as a toast at the top right. kind: success | info | warning | danger
  WT.toast = function (msg, kind, title) {
    const k = kind || 'info';
    const icons = {success: '✓', info: 'i', warning: '!', danger: '×'};
    const titles = {success: 'Done', info: 'Info', warning: 'Warning', danger: 'Error'};
    const $t = $(`<div class="toast border-0 shadow-sm" role="${k === 'danger' ? 'alert' : 'status'}">
      <div class="toast-header text-bg-${k === 'info' ? 'primary' : k}">
        <span class="me-2 fw-bold">${icons[k] || 'i'}</span><strong class="me-auto">${WT.esc(title || titles[k] || 'Info')}</strong>
        <small>${new Date().toLocaleTimeString('en-GB')}</small>
        <button type="button" class="btn-close btn-close-white ms-2" data-bs-dismiss="toast" aria-label="Close"></button></div>
      <div class="toast-body">${WT.esc(msg)}</div></div>`);
    $('#wtToasts').prepend($t);
    const t = new bootstrap.Toast($t[0], {delay: k === 'danger' ? 9000 : k === 'warning' ? 6000 : 3500});
    $t.on('hidden.bs.toast', () => $t.remove());
    t.show();
  };
  WT.ok = (m, t) => WT.toast(m, 'success', t);
  WT.warn = (m, t) => WT.toast(m, 'warning', t);
  WT.fail = (m, t) => WT.toast(m, 'danger', t);

  WT.statusBadge = function (s) {
    const v = String(s || '').toLowerCase();
    let k = 'secondary';
    if (/running|queued|launching|preparing|pending/.test(v)) k = 'warning';
    else if (/completed|done|finished/.test(v)) k = 'success';
    else if (/error|failed|stopped|cancel|interrupted|partial|abort/.test(v)) k = 'danger';
    return `<span class="badge text-bg-${k}">${WT.esc(s || '-')}</span>`;
  };
  WT.sevBadge = function (s) {
    const m = {Critical: 'danger', High: 'dark', Medium: 'warning', Low: 'primary', Info: 'secondary'};
    return `<span class="badge text-bg-${m[s] || 'secondary'}">${WT.esc(s)}</span>`;
  };
  WT.dur = function (sec) {
    sec = Math.max(0, Math.round(sec || 0));
    const h = Math.floor(sec / 3600), m = Math.floor(sec % 3600 / 60), s = sec % 60;
    return (h ? h + 'h ' : '') + (h || m ? m + 'm ' : '') + s + 's';
  };
  WT.dt = iso => iso ? new Date(iso).toLocaleString('en-GB') : '';
  WT.time = iso => iso ? new Date(iso).toLocaleTimeString('en-GB') : '';
  WT.lvl = l => { const m = l.match(/\[(DEBUG|INFO|NOTICE|WARN|ERROR|FATAL|TRACE)\]/); return m ? ({FATAL: 'ERROR', TRACE: 'DEBUG'}[m[1]] || m[1]) : 'INFO'; };
  WT.logHtml = function (line, rx) {
    let t = WT.esc(line.replace(/ \[scanUuid=[0-9a-f-]+\]/, ''));
    t = t.replace(/^(\S+)/, '<span class="ts">$1</span>');
    if (rx) { try { t = t.replace(new RegExp('(' + rx.source + ')', 'gi'), '<mark>$1</mark>'); } catch (e) { /* ignore */ } }
    return `<div class="l-${WT.lvl(line)}">${t}</div>`;
  };

  // Charts follow the theme.
  WT.chartColors = () => {
    const dark = document.documentElement.getAttribute('data-bs-theme') === 'dark';
    return {grid: dark ? 'rgba(255,255,255,.08)' : 'rgba(0,0,0,.06)', text: dark ? '#adb5bd' : '#6c757d'};
  };
  WT.chartDefaults = function () {
    if (!window.Chart) return;
    const c = WT.chartColors();
    Chart.defaults.color = c.text;
    Chart.defaults.borderColor = c.grid;
    Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
    Chart.defaults.maintainAspectRatio = false;
  };
  WT.LEVEL_COLORS = {DEBUG: '#9aa6ad', INFO: '#2f9c8b', NOTICE: '#3b444d', WARN: '#c98a2b', ERROR: '#1c2126'};

  // ---------------- theme
  $('#wtTheme').on('click', function () {
    const cur = document.documentElement.getAttribute('data-bs-theme') === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-bs-theme', cur);
    try { localStorage.setItem('wt-theme', cur); } catch (e) { /* ignore */ }
    WT.chartDefaults();
    $(document).trigger('wt:theme');
  });

  // ---------------- connection badge
  WT.refreshConn = function () {
    WT.get('/settings').then(r => {
      const s = r.settings, sc = !!s['sc.url'], ssh = !!s['ssh.host'];
      const $b = $('#wtConn');
      if (sc && ssh) $b.attr('class', 'badge rounded-pill text-bg-success wt-conn').text('SC + SSH configured');
      else $b.attr('class', 'badge rounded-pill text-bg-warning wt-conn').html('<a class="link-dark text-decoration-none" href="/settings">Settings incomplete</a>');
      $('#chatModel').text(s['ai.model'] || 'no model');
    }).catch(() => $('#wtConn').attr('class', 'badge rounded-pill text-bg-danger wt-conn').text('API unreachable'));
  };

  // ---------------- AI chat
  const Chat = WT.chat = {session: null, attach: '', ctrl: null, ctx: 24000};
  try { Chat.session = localStorage.getItem('wt-chat-session'); } catch (e) { /* ignore */ }
  if (!Chat.session) { Chat.session = Math.random().toString(16).slice(2) + Date.now().toString(16); try { localStorage.setItem('wt-chat-session', Chat.session); } catch (e) { /* ignore */ } }

  function md(t) {
    let h = WT.esc(t);
    h = h.replace(/```(\w*)\n?([\s\S]*?)```/g, (m, l, c) => '<pre>' + c + '</pre>');
    h = h.replace(/`([^`\n]+)`/g, '<code>$1</code>').replace(/\*\*([^*\n]+)\*\*/g, '<b>$1</b>').replace(/^#{1,4} (.*)$/gm, '<b>$1</b>');
    return h.replace(/\n/g, '<br>').replace(/<pre>([\s\S]*?)<\/pre>/g, (m, c) => '<pre>' + c.replace(/<br>/g, '\n') + '</pre>');
  }
  function bubble(role, content, stats) {
    let body = content, att = '';
    const i = body.indexOf('\n\n--- ATTACHMENT: ');
    if (role === 'user' && i >= 0) { att = body.slice(i + 2); body = body.slice(0, i); }
    return `<div class="bubble ${role}"><div class="who">${role === 'user' ? 'you' : 'assistant'}${stats ? ' · ' + WT.esc(stats) : ''}</div>${md(body)}${att ? `<details><summary class="small text-body-secondary">attachment: ${att.length} characters</summary><pre>${WT.esc(att)}</pre></details>` : ''}</div>`;
  }
  function statsText(s) {
    if (!s) return '';
    const sec = s.total_duration ? (s.total_duration / 1e9).toFixed(1) + ' s' : '';
    return [sec, s.prompt_eval_count ? s.prompt_eval_count + ' prompt tokens' : '', s.eval_count ? s.eval_count + ' output tokens' : ''].filter(Boolean).join(' · ');
  }
  Chat.load = function () {
    WT.get('/ai/history?session=' + Chat.session).then(r => {
      const $l = $('#chatLog').empty();
      if (!r.messages.length) $l.html('<div class="text-body-secondary small">Attach log lines and ask. Example: while following a scan on the Logs page, press "Log on screen" and ask "What is the scan doing right now, is anything wrong?"</div>');
      r.messages.forEach(m => $l.append(bubble(m.role, m.content, statsText(m.stats))));
      $l.scrollTop($l[0].scrollHeight);
    });
  };
  function attachInfo() { $('#chatAttachInfo').text(Chat.attach ? `attachment ready: ${Chat.attach.length} characters (added when you send)` : ''); }
  Chat.addAttach = function (title, text) {
    if (!text) { WT.toast('Nothing to attach. Start a stream on the Logs page or open a run.', 'warning'); return; }
    if (text.length > Chat.ctx) text = `[... first ${text.length - Chat.ctx} characters cut ...]\n` + text.slice(-Chat.ctx);
    Chat.attach = (Chat.attach ? Chat.attach + '\n\n' : '') + '--- ATTACHMENT: ' + title + ' ---\n' + text;
    attachInfo();
  };
  // Pages register a provider: WT.logProvider = {lines(onlyErrors) -> [str], label -> str}
  $('#chatAttachBtns').on('click', '[data-attach]', function () {
    const kind = $(this).data('attach');
    if (kind === 'status') {
      WT.get('/dashboard').then(d => Chat.addAttach('scan status', JSON.stringify({
        sc: d.sc.map(r => ({id: r.id, name: r.name, status: r.status, targets: r._targets, scanners: r._scanners})),
        scanner: d.scans.filter(s => s.has_dir), processes: d.was, chrome: d.chrome, chromedriver: d.drivers,
        load: d.load, log_level: (d.debug || {}).level}, null, 1))).catch(e => WT.toast(e, 'danger'));
      return;
    }
    const p = WT.logProvider;
    if (!p) { WT.toast('No log on this page. Attach from Logs or a Scan Results run.', 'warning'); return; }
    const ls = p.lines(kind === 'errors');
    Chat.addAttach(`${p.label()} · ${ls.length} lines${kind === 'errors' ? ' (WARN/ERROR)' : ''}`, ls.join('\n'));
  });
  $('#chatClear').on('click', () => {
    if (!confirm('Delete the chat history?')) return;
    WT.api('DELETE', '/ai/history?session=' + Chat.session).then(() => { Chat.attach = ''; attachInfo(); Chat.load(); });
  });
  Chat.send = async function () {
    let q = $('#chatInput').val().trim();
    if (!q && !Chat.attach) return;
    if (!q) q = 'Analyse the attached log: what is the scan doing, is anything wrong, what do you recommend?';
    const msg = q + (Chat.attach ? '\n\n' + Chat.attach : '');
    Chat.attach = ''; attachInfo(); $('#chatInput').val('');
    const $l = $('#chatLog'); $l.find('.text-body-secondary.small').remove();
    $l.append(bubble('user', msg));
    const $a = $(bubble('assistant', '…')); $l.append($a); $l.scrollTop($l[0].scrollHeight);
    const paint = () => { $a.html($(bubble('assistant', text || '…', stats)).html()); $l.scrollTop($l[0].scrollHeight); };
    $('#chatSend').prop('disabled', true); $('#chatStop').prop('disabled', false);
    Chat.ctrl = new AbortController();
    let text = '', stats = '';
    try {
      const r = await fetch('/api/ai/chat', {method: 'POST', headers: {'Content-Type': 'application/json'}, signal: Chat.ctrl.signal,
        body: JSON.stringify({session: Chat.session, message: msg})});
      if (!r.ok) { let j = {}; try { j = await r.json(); } catch (e) { /* ignore */ } throw new Error(j.detail || ('HTTP ' + r.status)); }
      const rd = r.body.getReader(), dec = new TextDecoder(); let buf = '';
      for (;;) {
        const {value, done} = await rd.read(); if (done) break;
        buf += dec.decode(value, {stream: true}); let i;
        while ((i = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, i); buf = buf.slice(i + 1); if (!line.trim()) continue;
          const d = JSON.parse(line);
          if (d.error) text += '\n[error] ' + d.error;
          text += d.delta || '';
          if (d.done) stats = statsText(d.stats);
        }
        paint();
      }
    } catch (e) { text += (text ? '\n' : '') + '[error] ' + (e.name === 'AbortError' ? 'stopped' : e.message); }
    finally {
      if (!text) text = '[empty answer]';
      paint(); Chat.ctrl = null;
      $('#chatSend').prop('disabled', false); $('#chatStop').prop('disabled', true);
    }
  };
  $('#chatSend').on('click', Chat.send);
  $('#chatStop').on('click', () => Chat.ctrl && Chat.ctrl.abort());
  $('#chatInput').on('keydown', e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); Chat.send(); } });
  Chat.open = () => bootstrap.Modal.getOrCreateInstance('#wtChat').show();
  $('#chatMax').on('click', function () {
    const full = $('#wtChatDialog').toggleClass('modal-fullscreen').hasClass('modal-fullscreen');
    $(this).text(full ? 'Restore' : 'Maximise');
    try { localStorage.setItem('wt-chat-max', full ? '1' : ''); } catch (e) { /* ignore */ }
  });
  try { if (localStorage.getItem('wt-chat-max')) { $('#wtChatDialog').addClass('modal-fullscreen'); $('#chatMax').text('Restore'); } } catch (e) { /* ignore */ }
  $('#wtChat').on('shown.bs.modal', () => { const l = $('#chatLog')[0]; l.scrollTop = l.scrollHeight; $('#chatInput').trigger('focus'); });
  $('#wtChat').on('show.bs.modal', () => {
    Chat.load();
    WT.get('/settings').then(r => { Chat.ctx = parseInt(r.settings['ai.ctx_chars'] || '24000', 10); });
  });

  $(function () { WT.chartDefaults(); WT.refreshConn(); });
})(jQuery);
