---
name: read_file
description: Read a line range of a repository file with line numbers (max 200 lines per call).
parameters: {"type": "object", "properties": {"path": {"type": "string"}, "start": {"type": "integer"}, "end": {"type": "integer"}}, "required": ["path"]}
---
