(function ($, WT) {
  'use strict';

  function api() { return ($('#dvApi').val() || location.origin).replace(/\/$/, ''); }
  function t() { return $('#dvTarget').val().trim(); }
  function pol() { return $('#dvPolicy').val().trim(); }

  const API_SNIPPETS = () => [
    ['Start a scan', 'Launch a WAS scan with two plugin families, fast scope and full debug. Returns a run id.',
      `curl -s -X POST ${api()}/api/scans -H 'Content-Type: application/json' -d '{
  "url": "${t()}",
  "policy": "${pol()}",
  "families": ["Authentication & Session", "Injection"],
  "fast": true, "debug": "both", "keep": true
}'`],
    ['List running scans', 'Scans running on Security Center and the scanner host, with their scanner UUID.',
      `curl -s ${api()}/api/dashboard | jq '{running: .sc, scanner: [.scans[]|select(.has_dir)], chrome: .chrome}'`],
    ['Watch a run', 'Poll one run: status, scanner UUID and per-level log counts.',
      `RUN=1
curl -s ${api()}/api/scans/$RUN | jq '{status, sc_result_id, scan_uuid, log_counts}'`],
    ['Fetch the captured log', 'Download the scanner log captured for a run (or filter WARN/ERROR).',
      `RUN=1
curl -s "${api()}/api/scans/$RUN/log?tail=5000&level=WARN,ERROR" | jq -r '.lines[]'
# whole file:
curl -s ${api()}/api/scans/$RUN/log/download -o run-$RUN.log`],
    ['Live log stream (SSE)', 'Follow the scanner log of a scan UUID in real time.',
      `UUID=$(curl -s ${api()}/api/scans/1 | jq -r .scan_uuid)
curl -sN "${api()}/api/logs/stream?uuid=$UUID"`],
    ['Analyse findings with AI', 'Run the offensive-security agent over a finished run, then open the HTML report.',
      `RUN=1
curl -s -X POST ${api()}/api/scans/$RUN/analyze -d '{}'
# wait, then:
curl -s ${api()}/api/scans/$RUN/analysis | jq '{risk: .analysis.risk_rating, paths: [.analysis.attack_paths[].title]}'
curl -s ${api()}/api/scans/$RUN/report -o report-$RUN.html`],
    ['Get a run’s findings', 'The parsed findings with severity and plugin output.',
      `curl -s ${api()}/api/scans/1 | jq '.findings[] | {plugin_id, severity, name, family}'`],
    ['Hidden path discovery', 'Start an ffuf discovery and read the hits.',
      `ID=$(curl -s -X POST ${api()}/api/fuzz -H 'Content-Type: application/json' -d '{"target_url":"${t()}","wordlist":"common-paths.txt"}' | jq -r .run_id)
curl -s ${api()}/api/fuzz/$ID | jq '.hits[] | {status, path, length}'`],
    ['SAST scan a repo', 'Clone and review a Git repository with the SAST agent.',
      `ID=$(curl -s -X POST ${api()}/api/sast -H 'Content-Type: application/json' -d '{"repo_url":"https://github.com/OWASP/NodeGoat","max_functions":30}' | jq -r .run_id)
curl -s ${api()}/api/sast/$ID | jq '{status, findings: .stats.findings}'`],
    ['Toggle scanner debug', 'Switch the scanner log level without launching a scan.',
      `curl -s -X POST ${api()}/api/scanner/debug -d '{"on": true}'   # and "on": false to revert`],
  ];

  const CLI_SNIPPETS = [
    ['Copy the tools to the Security Center host', 'The two single-file tools need only Python 3.6 and ssh access to the scanner.',
      `scp tsc-was-debug-scanctl.py tsc-was-scanmon.py sc4:~/
ssh sc4 'chmod 700 ~/tsc-was-*.py'
# credentials: ~/.tsc-was.env with TSC_SC_URL / TSC_ACCESS_KEY / TSC_SECRET_KEY`],
    ['Start a scan with debug', 'Derive a policy with two families, launch and capture the debug log.',
      `python3 ~/tsc-was-debug-scanctl.py scan --url ${'${TARGET}'} --policy 1000002 \\
   --families "Authentication & Session,Injection" --fast --debug both --keep --download`],
    ['List running scans', 'Scans on Security Center plus the scanner-side processes.',
      `python3 ~/tsc-was-scanmon.py list`],
    ['Follow a scan’s log live', 'Tail the scanner log for one scan, filtered.',
      `python3 ~/tsc-was-scanmon.py tail --grep 'Auditing page|plugin started'`],
    ['Live panel', 'Refreshing panel of scans, scanner load and the last log lines.',
      `python3 ~/tsc-was-scanmon.py top --interval 5`],
    ['Toggle debug by hand', 'Change the scanner log level directly.',
      `python3 ~/tsc-was-debug-scanctl.py debug on     # and: debug off`],
  ];

  function render() {
    const cardHtml = (s) => `<div class="card mb-2"><div class="card-body">
      <div class="d-flex align-items-start gap-2"><div><div class="fw-semibold">${WT.esc(s[0])}</div><div class="small text-body-secondary">${WT.esc(s[1])}</div></div>
      <button class="btn btn-sm btn-outline-secondary ms-auto copy-snip">Copy</button></div>
      <pre class="code mt-2 mb-0">${WT.esc(s[2])}</pre></div></div>`;
    $('#dvApiCards').html(API_SNIPPETS().map(cardHtml).join(''));
    $('#dvCliCards').html(CLI_SNIPPETS.map(cardHtml).join(''));
  }
  $(document).on('click', '.copy-snip', function () {
    const txt = $(this).closest('.card-body').find('pre').text();
    (navigator.clipboard && window.isSecureContext ? navigator.clipboard.writeText(txt) : Promise.reject())
      .then(() => WT.ok('Copied')).catch(() => {
        const ta = $('<textarea>').val(txt).css({position: 'fixed', opacity: 0}).appendTo('body').select();
        try { document.execCommand('copy'); WT.ok('Copied'); } catch (e) { WT.warn('Select and copy manually'); } ta.remove();
      });
  });
  $('#dvApi, #dvTarget, #dvPolicy').on('input', render);
  $('#dvApi').val(location.origin);
  render();
})(jQuery, window.WT);
