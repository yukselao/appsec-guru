---
name: html-report
title: Render an analysis as a standalone HTML report
---
# Skill: html-report

The harness renders the findings-analysis JSON into a self-contained HTML file
(no external assets) with: a header (target, policy, scan time, risk rating), an
executive summary, the attack paths as ordered cards, a category breakdown, a
reconnaissance table from informational findings, quick wins, and a full finding
table with plugin output. The report is downloadable and openable in its own
browser tab from the Scan Results page. The model supplies the JSON; the
template is deterministic (api/harness/report.py) so the report always renders.
