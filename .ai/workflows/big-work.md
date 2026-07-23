# Big Work Workflow

Use this mode for substantial writing, IETF drafts, planning, research, or mixed tasks. For substantial coding tasks, use `plan-then-execute.md` instead.

Read `_contract.md` before starting. It defines what is allowed, what requires asking, and when to interrupt.

## 1. Clarify Intent

Identify:

- Goal
- Non-goals
- Constraints
- Acceptance criteria
- Audience or users
- Risks and unknowns

Ask important questions upfront instead of interrupting later.

## 2. Plan

Produce a concise plan in `.ai/plans/` (one file per task):

- Approach
- Files likely to change
- Verification method
- Stop conditions
- Expected git checkpoint

Wait for user approval before substantial execution.

## 3. Execute

Work autonomously per `_contract.md`. Keep `.ai/session.md` current during long runs so progress survives a context reset. Place in-flight drafts under `.ai/drafts/` and exploratory notes under `.ai/scratch/`.

## 4. Verify

Use proof appropriate to the task:

- Code: tests, lint, typecheck, build, app smoke test.
- IETF drafts: build output, references, terminology, section consistency, normative language, idnits when available.
- Writing: structure, clarity, consistency, citations, final diff.
- Research or planning: sources, assumptions, alternatives, decision record.

If a check cannot be run, state why.

## 5. Finish

Before stopping:

- Update `.ai/session.md`.
- Review git status and diff.
- Create a local git checkpoint for substantial work using `.ai/git.md`.
- Push only if the user requested or approved it.
- Summarize what changed, what was verified, and any remaining risks.
