"""Deterministic HTML report from the offensive-security analysis JSON.
Self-contained (no external assets), opens in its own browser tab."""
import datetime
import html
import json


def esc(x):
    return html.escape(str(x if x is not None else ""))


SEV_COLOR = {"critical": "#1c2126", "high": "#2f4a52", "medium": "#c98a2b", "low": "#2f9c8b",
             "informational": "#6b7681", "info": "#6b7681"}


def _badge(sev):
    c = SEV_COLOR.get(str(sev or "").lower(), "#6c757d")
    return '<span class="sev" style="background:{}">{}</span>'.format(c, esc(sev or "-"))


def render(run, analysis, findings):
    a = analysis or {}
    meta = run or {}
    gen = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    sev_counts = {}
    for f in findings:
        sev_counts[f.get("severity") or "Info"] = sev_counts.get(f.get("severity") or "Info", 0) + 1
    by_id = {str(f.get("plugin_id")): f for f in findings}

    def finding_names(ids):
        return ", ".join(esc(by_id.get(str(i), {}).get("name") or i) for i in (ids or []))

    paths = "".join(
        '<div class="card"><div class="card-h">{b} <b>{t}</b> <span class="muted">likelihood: {lk}</span></div>'
        '<ol>{steps}</ol><div class="muted small">Findings: {fnd}</div></div>'.format(
            b=_badge(p.get("severity")), t=esc(p.get("title")), lk=esc(p.get("likelihood") or "-"),
            steps="".join("<li>{}</li>".format(esc(s)) for s in p.get("steps") or []),
            fnd=finding_names(p.get("findings")))
        for p in a.get("attack_paths") or []) or '<p class="muted">No attack path identified.</p>'

    cats = "".join(
        '<tr><td>{b}</td><td><b>{n}</b><div class="small muted">{note}</div></td><td>{fnd}</td></tr>'.format(
            b=_badge(c.get("severity")), n=esc(c.get("name")), note=esc(c.get("note")), fnd=finding_names(c.get("findings")))
        for c in a.get("categories") or [])

    recon = "".join(
        '<tr><td class="mono">{pid}</td><td>{fact}</td><td>{why}</td></tr>'.format(
            pid=esc(r.get("plugin_id")), fact=esc(r.get("fact")), why=esc(r.get("why_it_matters")))
        for r in a.get("recon") or []) or '<tr><td colspan="3" class="muted">No reconnaissance notes.</td></tr>'

    wins = "".join("<li>{}</li>".format(esc(w)) for w in a.get("quick_wins") or [])
    fp = "".join("<li><span class='mono'>{}</span> — {}</li>".format(esc(f.get("plugin_id")), esc(f.get("reason")))
                 for f in a.get("false_positive_watch") or [])

    rows = "".join(
        '<tr><td class="mono">{pid}</td><td>{n}</td><td>{b}</td><td>{fam}</td><td>{cve}</td>'
        '<td class="urls">{urls}</td><td><pre>{out}</pre></td></tr>'.format(
            pid=esc(f.get("plugin_id")), n=esc(f.get("name")), b=_badge(f.get("severity")),
            fam=esc(f.get("family")), cve=esc(", ".join(f.get("cve") or [])),
            urls="<br>".join(esc(u) for u in (f.get("urls") or [])[:8]),
            out=esc((f.get("output") or "")[:1500]))
        for f in findings)

    chips = " ".join('{} {}'.format(_badge(k), v) for k, v in sev_counts.items())
    return TEMPLATE.format(
        title=esc(meta.get("name") or "WAS scan"), target=esc(meta.get("target_url")), gen=gen,
        policy=esc(meta.get("source_policy_id")), rating=_badge(a.get("risk_rating")),
        summary=esc(a.get("summary") or "No summary."), chips=chips, paths=paths,
        cats=cats or '<tr><td colspan="3" class="muted">No categories.</td></tr>', recon=recon,
        wins=wins or "<li class='muted'>None.</li>", fp=fp or "<li class='muted'>None flagged.</li>",
        rows=rows or '<tr><td colspan="7" class="muted">No findings.</td></tr>', count=len(findings),
        model=esc(meta.get("_model") or ""))


TEMPLATE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{title} — AppSec Guru report</title>
<style>
:root{{--fg:#1d1f23;--bg:#fff;--muted:#6c757d;--line:#e2e3e0;--card:#f8f9fa;--accent:#2f9c8b}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 -apple-system,Segoe UI,Roboto,Arial,sans-serif}}
.wrap{{max-width:1100px;margin:0 auto;padding:28px 22px 80px}}
h1{{font-size:24px;margin:0 0 4px}}h2{{font-size:19px;margin:28px 0 12px;border-bottom:2px solid var(--line);padding-bottom:6px}}
.muted{{color:var(--muted)}}.small{{font-size:13px}}.mono{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}}
.head{{display:flex;align-items:center;gap:12px;border-bottom:3px solid var(--accent);padding-bottom:14px}}
.wolf{{width:40px;height:40px;color:var(--accent)}}
.meta{{color:var(--muted);font-size:13px;margin-top:4px}}
.sev{{color:#fff;border-radius:10px;padding:1px 9px;font-size:12px;font-weight:600;white-space:nowrap}}
.chips{{margin:10px 0}}.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:10px 0}}
.card-h{{display:flex;gap:10px;align-items:center;margin-bottom:8px}}
ol{{margin:6px 0 6px 20px}}ul{{margin:6px 0 6px 20px}}
table{{border-collapse:collapse;width:100%;font-size:13px;margin-top:8px}}th,td{{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}}
th{{background:var(--card);font-size:12px;text-transform:uppercase;color:var(--muted)}}
pre{{white-space:pre-wrap;word-break:break-word;margin:0;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;max-height:200px;overflow:auto}}
.urls{{max-width:260px;word-break:break-all}}.summary{{background:#fff3f3;border-left:4px solid var(--accent);padding:12px 16px;border-radius:6px}}
@media print{{.card,table{{break-inside:avoid}}}}
</style></head><body><div class="wrap">
<div class="head">
  <svg class="wolf" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"><path d="M12 3l2.5 3H18l-1 3 3 2-2.5 2 .5 3.3-3.5-1L12 21l-4.5-2.5-3.5 1 .5-3.3L2 14l3-2-1-3h3.5L12 3z"/><circle cx="9.3" cy="12" r=".9" fill="currentColor"/><circle cx="14.7" cy="12" r=".9" fill="currentColor"/></svg>
  <div><h1>{title}</h1><div class="meta">Target {target} · policy {policy} · generated {gen}{model} · AppSec Guru offensive analysis</div></div>
  <div style="margin-left:auto">Risk: {rating}</div>
</div>
<h2>Executive summary</h2><div class="summary">{summary}</div><div class="chips">{chips}</div>
<h2>Attack paths</h2>{paths}
<h2>Categories</h2><table><thead><tr><th>Severity</th><th>Category</th><th>Findings</th></tr></thead><tbody>{cats}</tbody></table>
<h2>Reconnaissance (informational findings)</h2><table><thead><tr><th>Plugin</th><th>Fact</th><th>Why it matters</th></tr></thead><tbody>{recon}</tbody></table>
<h2>Quick wins</h2><ul>{wins}</ul>
<h2>False-positive watch</h2><ul>{fp}</ul>
<h2>All findings ({count})</h2><table><thead><tr><th>Plugin</th><th>Name</th><th>Severity</th><th>Family</th><th>CVE</th><th>URLs</th><th>Plugin output</th></tr></thead><tbody>{rows}</tbody></table>
</div></body></html>"""
