---
name: sast
title: Static analysis of a repository
---
# Skill: sast

Orchestration playbook for a repository review. The harness executes steps 1-3
deterministically and runs the agent for step 4.

1. **Fetch.** Clone the GitHub/GitLab repository (shallow, given ref) with
   `repo_clone`. Record the commit id.
2. **Inventory.** `list_files` by language. Skip vendored and generated code:
   `node_modules`, `vendor`, `dist`, `build`, minified files, lock files.
   Tests are skipped unless the run asks for them.
3. **Extract.** Apply the function-extraction skill to every source file
   (`extract_functions`). Keep functions that take at least one argument.
   Mark the sinks each function reaches using the sink-catalog skill.
4. **Prioritise.** Candidates are functions with arguments and at least one
   sink. Order by highest sink severity, then by whether the function looks
   like an entry point (route handler, controller, CLI command). Stop at the
   run's function budget.
5. **Analyse.** For each candidate run the sast-agent with the
   argument-analysis skill.
6. **Report.** Deduplicate findings by (file, line, CWE). Keep the highest
   confidence.

Coverage notes the run summary must state: files scanned, functions extracted,
candidates, candidates analysed, findings by severity, and any step that failed.
