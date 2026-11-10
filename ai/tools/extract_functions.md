---
name: extract_functions
description: Extract functions with their parameters, line ranges, calls and sink hits from one source file.
parameters: {"type": "object", "properties": {"path": {"type": "string", "description": "repository-relative file path"}}, "required": ["path"]}
agent_callable: false
---
Implements the function-extraction skill. Python uses `ast`; other languages use
signature patterns with brace/`end` matching.
