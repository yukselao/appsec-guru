(function ($, WT) {
  'use strict';
  const apps = window.WT_TESTAPPS || [];
  const host = () => $('#taHost').val().trim() || '192.168.1.82';

  function copy(text) {
    (navigator.clipboard && window.isSecureContext ? navigator.clipboard.writeText(text) : Promise.reject())
      .then(() => WT.ok('Copied to the clipboard'))
      .catch(() => {
        const ta = $('<textarea>').val(text).css({position: 'fixed', opacity: 0}).appendTo('body').select();
        try { document.execCommand('copy'); WT.ok('Copied to the clipboard'); } catch (e) { WT.warn('Select the text and copy it manually'); }
        ta.remove();
      });
  }
  function render() {
    $('#taCards').html(apps.map(a => {
      const url = `http://${host()}:${a.port}${a.path === '/' ? '' : a.path}`;
      const cmd = `mkdir -p ~/test-apps/${a.id} && cd ~/test-apps/${a.id}\ncat > docker-compose.yml <<'EOF'\n${a.compose}\nEOF\ndocker compose up -d && docker compose ps`;
      return `<div class="col"><div class="card h-100 app-card">
        <div class="card-header"><span class="fw-semibold">${WT.esc(a.name)}</span><span class="badge text-bg-light border ms-auto">port ${a.port}</span></div>
        <div class="card-body">
          <p class="small mb-2">${WT.esc(a.about)}</p>
          <div class="mb-2">${a.tags.map(t => `<span class="badge text-bg-secondary-subtle text-secondary-emphasis border me-1 mb-1">${WT.esc(t)}</span>`).join('')}</div>
          <ul class="nav nav-pills nav-sm small mb-2" role="tablist">
            <li class="nav-item"><button class="nav-link active py-1 px-2" data-bs-toggle="pill" data-bs-target="#c-${a.id}" type="button">docker-compose.yml</button></li>
            <li class="nav-item"><button class="nav-link py-1 px-2" data-bs-toggle="pill" data-bs-target="#s-${a.id}" type="button">One-liner</button></li>
          </ul>
          <div class="tab-content">
            <div class="tab-pane fade show active" id="c-${a.id}"><pre class="code"><button class="btn btn-sm btn-light border copy-btn" data-copy="compose" data-app="${a.id}">Copy</button>${WT.esc(a.compose)}</pre></div>
            <div class="tab-pane fade" id="s-${a.id}"><pre class="code"><button class="btn btn-sm btn-light border copy-btn" data-copy="cmd" data-app="${a.id}">Copy</button>${WT.esc(cmd)}</pre></div>
          </div>
        </div>
        <div class="card-footer d-flex align-items-center gap-2">
          <a class="small mono text-truncate" href="${WT.esc(url)}" target="_blank" rel="noopener">${WT.esc(url)}</a>
          <a class="btn btn-sm btn-primary ms-auto text-nowrap" href="/create-scan?target=${encodeURIComponent(url)}">Scan this</a>
        </div></div></div>`;
    }).join(''));
  }

  $('#taCards').on('click', '[data-copy]', function () {
    const a = apps.find(x => x.id === $(this).data('app'));
    if ($(this).data('copy') === 'compose') copy(a.compose);
    else copy(`mkdir -p ~/test-apps/${a.id} && cd ~/test-apps/${a.id}\ncat > docker-compose.yml <<'EOF'\n${a.compose}\nEOF\ndocker compose up -d && docker compose ps`);
  });
  $('#taAll').on('click', () => {
    const services = apps.map(a => a.compose.replace(/^services:\n/, '')).join('\n');
    copy('# All test apps in one stack. Needs about 4 GB of RAM.\nservices:\n' + services + '\n');
  });
  $('#taHost').on('input', () => { try { localStorage.setItem('wt-labhost', $('#taHost').val()); } catch (e) { /* ignore */ } render(); });

  try { $('#taHost').val(localStorage.getItem('wt-labhost') || '192.168.1.82'); } catch (e) { $('#taHost').val('192.168.1.82'); }
  render();
})(jQuery, window.WT);
