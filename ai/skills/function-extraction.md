---
name: function-extraction
title: Extract functions and their arguments
---
# Skill: function-extraction

Goal: turn each source file into a list of functions with their parameters, so
that the review can go argument by argument.

For every function record:

| Field | Meaning |
| --- | --- |
| `name` | qualified name (`Class.method` when inside a class) |
| `params` | parameter names in order, without `self`/`this`/`cls` |
| `start_line`, `end_line` | 1-based, inclusive |
| `decorators` / `route` | framework hints: `@app.route`, `@GetMapping`, `router.get(...)`, `Route::` |
| `sinks` | sink-catalog hits inside the body: sink id, line, matched text |
| `calls` | names of functions it calls (for following data into callees) |

Language handling in `extract_functions`:

- **Python:** the `ast` module (exact).
- **JavaScript/TypeScript, PHP, Java, C#, Go, Ruby:** signature patterns plus
  brace or `end` matching. Arrow functions assigned to names and object
  methods count as functions. Anonymous callbacks passed to route registrations
  are named after the route (`GET /users/:id`).

Treat route handlers as entry points: their parameters (and the request object
they receive) are attacker controlled.
