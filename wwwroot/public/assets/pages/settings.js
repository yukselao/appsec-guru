(function ($, WT) {
  'use strict';
  let MASK = '__SET__', defaults = {};
  const SRC = {env: ['success', 'env'], ui: ['primary', 'ui'], default: ['light border', 'default']};

  function fill(r) {
    MASK = r.secret_mask || MASK;
    defaults.prompt = r.default_prompt;
    $('[data-key]').each(function () {
      const k = $(this).data('key'), v = r.settings[k];
      if (this.type === 'checkbox') this.checked = String(v) === 'true';
      else if ($(this).data('secret')) { $(this).val(v === MASK ? MASK : ''); this.placeholder = v === MASK ? 'set (type to change)' : 'not set'; }
      else $(this).val(v == null ? '' : v);
    });
    $('[data-src]').each(function () {
      const k = $(this).data('src'), s = (r.sources || {})[k] || 'default', m = SRC[s] || SRC.default;
      const env = (r.env_names || {})[k];
      $(this).attr('class', 'badge src-badge text-bg-' + m[0]).text(m[1]).attr('title', env ? '.env variable: ' + env.toLowerCase() : '');
    });
    WT.refreshConn();
  }
  function load() { return WT.get('/settings').then(fill).catch(e => WT.fail(e)); }

  function values(section) {
    const out = {};
    $(`[data-section="${section}"] [data-key]`).each(function () {
      out[$(this).data('key')] = this.type === 'checkbox' ? (this.checked ? 'true' : 'false') : $(this).val();
    });
    return out;
  }
  $('[data-save]').on('click', function () {
    const sec = $(this).data('save'), $b = $(this).prop('disabled', true);
    WT.api('PUT', '/settings', values(sec)).then(r => { fill(r); WT.ok(r.saved.length + ' settings saved'); })
      .catch(e => WT.fail(e)).always(() => $b.prop('disabled', false));
  });
  $('[data-reset]').on('click', function () {
    const sec = $(this).data('reset');
    if (!confirm('Remove the values saved in the UI for this section and use the .env values again?')) return;
    const keys = $(`[data-section="${sec}"] [data-key]`).map((i, el) => $(el).data('key')).get();
    WT.post('/settings/reset', {keys}).then(r => { fill(r); WT.ok('.env values apply again'); }).catch(e => WT.fail(e));
  });
  $('[data-test]').on('click', function () {
    const what = $(this).data('test'), $b = $(this).prop('disabled', true).addClass('disabled');
    const old = $b.html(); $b.html('<span class="spinner-border spinner-border-sm me-1"></span>Testing…');
    WT.post('/settings/test/' + what).then(r => {
      if (what === 'sc') WT.ok(`Security Center ${r.version} reachable · ${r.was_policies} WAS policies` +
        (r.was_scanners === null ? ' · the WAS scanner list needs an administrator key' : ' · scanners: ' + (r.was_scanners.map(s => s.name + ' (' + s.status + ')').join(', ') || 'none')), 'Security Center API');
      else if (what === 'sc-ssh') WT.ok(`${r.host} via ${r.method} · ${r.package || 'SecurityCenter package not found'} · sudo ${r.sudo ? 'available' : 'not available'}`, 'Security Center SSH');
      else if (what === 'ssh') WT.ok(`${r.host} via ${r.method} · scanner service ${r.debug.active} · log level ${r.debug.level.replace('(varsayilan)', '(default)')} · log readable: ${r.log_readable ? 'yes' : 'no'} · sudo ${r.sudo ? 'available' : 'not available'}`, 'WAS scanner SSH');
      else {
        $('#aiModels').html((r.models || []).map(m => `<option value="${WT.esc(m.name)}">${WT.esc(m.params || '')}</option>`).join(''));
        const base = `Ollama ${r.version || ''} at ${r.url} · ${r.models.length} models`;
        if (r.model_found === false) WT.warn(base + ' · the selected model is not installed on this server', 'AI');
        else WT.ok(base + (r.model_found ? ` · model answered "${r.reply}" in ${r.chat_ms} ms` : ''), 'AI');
      }
    }).catch(e => WT.fail(e, 'Test failed')).always(() => $b.prop('disabled', false).removeClass('disabled').html(old));
  });
  $('#aiList').on('click', () => WT.get('/ai/models').then(r => {
    $('#aiModels').html(r.models.map(m => `<option value="${WT.esc(m.name)}">${WT.esc(m.params || '')}</option>`).join(''));
    WT.ok(r.models.length + ' models found; click the field to pick one');
  }).catch(e => WT.fail(e)));
  $('#tAuditBtn').on('shown.bs.tab', () => WT.get('/audit').then(r => $('#auditBody').html(r.audit.map(a =>
    `<tr><td class="small text-nowrap">${WT.dt(a.ts)}</td><td>${WT.esc(a.action)}</td><td class="small mono">${WT.esc(JSON.stringify(a.details))}</td><td class="small">${WT.esc(a.client_ip || '')}</td></tr>`).join('')
    || '<tr><td colspan="4" class="empty px-3">No entries</td></tr>')));

  load();
})(jQuery, window.WT);
