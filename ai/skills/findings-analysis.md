---
name: findings-analysis
title: Analyse WAS findings from an attacker's point of view
---
# Skill: findings-analysis

Input: the scan's findings as JSON — each with `plugin_id`, `name`, `severity`,
`family`, `count`, `urls` and `output` (plugin output text), plus scan metadata
(target, policy, duration) and any fetched attachments.

Produce a single JSON object:

```
{
  "summary": "3-5 sentence executive read: overall exposure and the one thing to fix first",
  "risk_rating": "critical|high|medium|low|informational",
  "attack_paths": [
    {"title": "...", "severity": "critical|high|medium|low",
     "steps": ["recon ...", "exploit ...", "impact ..."],
     "findings": ["plugin_id", ...], "likelihood": "high|medium|low"}
  ],
  "categories": [
    {"name": "Authentication & Session|Injection|Data Exposure|Transport|Client-side|Reconnaissance",
     "severity": "...", "findings": ["plugin_id", ...], "note": "what this group means for an attacker"}
  ],
  "recon": [{"plugin_id": "...", "fact": "detected tech / endpoint / token", "why_it_matters": "..."}],
  "quick_wins": ["concrete fix that removes the most risk for the least effort", ...],
  "false_positive_watch": [{"plugin_id": "...", "reason": "..."}]
}
```

Rules: put every real finding in exactly one category; inform at least one
attack path from an informational finding when the data allows; keep plugin ids
exactly as given so the UI can link back.
