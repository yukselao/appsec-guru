---
name: get_function
description: Return the source (with line numbers) and parameters of a function by name, searching the whole repository. Use it to follow an argument into a callee.
parameters: {"type": "object", "properties": {"name": {"type": "string", "description": "function or Class.method name"}, "path": {"type": "string", "description": "optional file path to narrow the search"}}, "required": ["name"]}
---
