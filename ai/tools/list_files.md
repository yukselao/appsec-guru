---
name: list_files
description: List source files of the cloned repository grouped by language, skipping vendored, generated and (optionally) test code.
parameters: {"type": "object", "properties": {"include_tests": {"type": "boolean"}}}
agent_callable: false
---
Used by the sast skill (inventory step).
