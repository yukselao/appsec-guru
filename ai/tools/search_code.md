---
name: search_code
description: Search the repository for a regular expression and return matching lines (file:line:text, max 60). Use it to find callers, routes and sanitizers.
parameters: {"type": "object", "properties": {"pattern": {"type": "string"}, "glob": {"type": "string", "description": "optional file glob, e.g. *.py"}}, "required": ["pattern"]}
---
