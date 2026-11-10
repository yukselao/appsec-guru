---
name: repo_clone
description: Shallow-clone a GitHub or GitLab repository into the run workspace and return the commit id.
parameters: {"type": "object", "properties": {"url": {"type": "string", "description": "https clone URL of the repository or project page"}, "ref": {"type": "string", "description": "branch or tag; empty for the default branch"}}, "required": ["url"]}
agent_callable: false
---
Used by the sast skill (harness step 1). Supports public repositories and private
ones with a token passed by the run (never stored). `git clone --depth 1`.
