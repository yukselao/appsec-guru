---
name: report_finding
description: Report one confirmed vulnerability. Call once per vulnerable parameter/sink pair.
parameters: {"type": "object", "properties": {"file": {"type": "string"}, "line": {"type": "integer"}, "function": {"type": "string"}, "parameter": {"type": "string"}, "cwe": {"type": "string", "description": "e.g. CWE-89"}, "title": {"type": "string"}, "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]}, "confidence": {"type": "string", "enum": ["high", "medium", "low"]}, "description": {"type": "string", "description": "source -> path -> sink"}, "evidence": {"type": "string", "description": "the exact vulnerable code lines"}, "recommendation": {"type": "string"}}, "required": ["file", "line", "cwe", "title", "severity", "confidence", "description"]}
---
Stored in sast_findings. Duplicates (same file, line, CWE) keep the highest confidence.
