---
name: argument-analysis
title: Argument-by-argument taint review of one function
---
# Skill: argument-analysis

Input from the harness: the function source with line numbers, its parameter
list, the sinks found in it, its callers if known, and the file path.

Do this for **each parameter**, in order:

1. **Source.** Is the value attacker controlled? Route/controller parameters,
   `request.*`, `req.query/body/params`, `$_GET/$_POST/$_REQUEST`, headers,
   cookies, uploaded files, message queues and CLI args are. Constants and
   config are not. Unknown caller: look it up with `search_code` for the
   function name; if still unknown, treat as untrusted with low confidence.
2. **Path.** Follow the value line by line: assignments, string building,
   format/concatenation, passing into other functions (open them with
   `get_function`).
3. **Guards.** Note validation, allow-lists, casts, escaping, ORM/parameter
   binding, path normalisation + prefix checks. Decide whether the guard fits
   the sink.
4. **Sink.** Which sink does it reach (sink-catalog id)? On which line?
5. **Verdict.** vulnerable / safe / not reachable. Only "vulnerable" is reported.

For every vulnerable parameter call `report_finding` with:
`file`, `line` (the sink line), `function`, `parameter`, `cwe`, `title`,
`severity` (critical/high/medium/low), `confidence` (high/medium/low),
`description` (source -> path -> sink), `evidence` (the exact code
lines), `recommendation` (concrete fix).

Then call `finish` with a one-line summary for the function. Do not report
style issues, missing logging or theoretical problems without a reachable sink.
