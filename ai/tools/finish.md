---
name: finish
description: End the review of the current function with a one-line verdict.
parameters: {"type": "object", "properties": {"verdict": {"type": "string", "enum": ["vulnerable", "safe", "not_reachable", "unsure"]}, "summary": {"type": "string"}}, "required": ["verdict", "summary"]}
---
