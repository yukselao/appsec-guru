# ai/ — agentic harness definitions

The harness in `api/harness/` reads these Markdown files at run time. Editing a
file changes the agent's behaviour on the next run; no rebuild or restart needed.

```
ai/
├── agents/<name>.md   who the agent is: role, mission, decision rules, which skills and tools it may use
├── skills/<name>.md   reusable playbooks an agent follows (prompt text the harness injects)
└── tools/<name>.md    tool contract: description + JSON parameter schema (front matter);
                       the Python implementation lives in api/harness/tools.py under the same name
```

Every file starts with YAML-like front matter between `---` lines. The harness
parses `key: value` pairs and JSON values (lists, objects) only.

| Agent | Skills | Tools |
| --- | --- | --- |
| `sast-agent` | `sast`, `function-extraction`, `argument-analysis`, `sink-catalog` | `repo_clone`, `list_files`, `extract_functions`, `get_function`, `read_file`, `search_code`, `report_finding`, `finish` |

## How a SAST run works

1. **sast** (orchestration skill) clones the repository with `repo_clone`.
2. **function-extraction** runs `extract_functions` over every source file: name, parameters, line range, the sinks each function reaches.
3. Functions that take arguments and reach a sink become candidates, ranked by sink severity.
4. For each candidate the **sast-agent** follows **argument-analysis**: one parameter at a time, from entry to sink, using `get_function`, `read_file` and `search_code` to follow callees and sanitizers, and calls `report_finding` for every confirmed issue, then `finish`.
5. Findings land in PostgreSQL (`sast_findings`) and show on the SAST Scan page.

The LLM is the Ollama model from Settings > AI. A model without tool support
still works: the harness switches to a JSON-answer mode for step 4.

## Adding a tool

1. Write `ai/tools/<name>.md` with `name`, `description` and `parameters` (JSON Schema) in the front matter.
2. Implement `def <name>(ctx, **args)` in `api/harness/tools.py` and add it to `REGISTRY`.
3. List the tool in the agent's `tools:` front matter.
