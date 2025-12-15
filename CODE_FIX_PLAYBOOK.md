# Code Fix Playbook

Short guide for producing clear, minimal, and testable fixes.

## What to capture before fixing
- Problem summary: what is broken, who is affected, expected vs actual.
- Reproduction steps and failing inputs (include env/branch/feature flag states).
- Evidence: logs, stack traces, screenshots, or failing test output.
- Scope guess: likely files/modules and any risky areas (auth, payments, migrations).

## How to approach the fix
- Locate the source: search by symptom and by domain; read nearby tests and docs.
- Minimize blast radius: prefer the smallest change that addresses the root cause.
- Preserve conventions: match existing patterns, error handling, logging, and style.
- Keep compatibility: avoid breaking public contracts; gate risky changes behind flags when needed.
- Document non-obvious choices with a short comment near the change.

## Patch quality checklist
- Change set is cohesive and easy to review (avoid mixing refactors with fixes).
- Inputs are validated; errors are actionable; no secrets in logs.
- Add/adjust tests that prove the bug and the fix; avoid brittle assertions.
- Keep behavior for unrelated paths intact; watch for performance regressions.
- Include migrations/config changes only when essential and describe the rollout.

## Testing checklist
- Unit tests for the changed area.
- Integration/e2e where behavior crosses boundaries (API, DB, queue, UI).
- Manual sanity for the reported repro.
- Note any tests you could not run and why.

## Ready-to-use prompt for AI code fixes
Copy/paste and fill the brackets:

```
You are a senior engineer fixing a bug.

Bug summary: [clear description]
Reproduction: [steps/inputs/logs]
Scope: [files/modules suspected]
Constraints: [performance, backwards-compat, security/privacy notes]

Please:
- Propose the minimal code change.
- Explain the reasoning briefly.
- Provide the patch as unified diff per file (no placeholders).
- List tests to run; if new tests are needed, include them.
- Call out risks and mitigations.
```

## Delivery
- Prefer patches that apply cleanly (unified diff).
- If you cannot test locally, state the gap and how to verify in CI.
- Share follow-up chores separately (monitoring, cleanup, docs).


