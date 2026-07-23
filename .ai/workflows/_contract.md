# Operating Contract

Shared by `big-work.md` and `plan-then-execute.md`. Read this before either workflow.

## Principle

Spend meaningful time upfront clarifying intent. After the user approves the plan, work autonomously until the task is complete. Do not interrupt for routine choices already covered by the approved plan.

## Ask the user only when

- The requested behavior is ambiguous in a way that changes product or document semantics.
- You would need to discard, overwrite, or revert user work.
- You need credentials, external access, or approval for a risky command.
- The approved plan no longer fits what you found.
- A major scope expansion is required.

## Allowed during autonomous execution

- Read relevant files.
- Edit files within approved scope.
- Add tests, drafts, notes, or supporting artifacts.
- Refactor or reorganize within approved scope.
- Run relevant checks; iterate on failures until acceptance criteria are met.
- Create local git checkpoints (see `.ai/git.md`).

## Not allowed without asking

- Destructive git operations (`reset --hard`, `clean`, discarding changes, force-push).
- Discarding user changes.
- Publishing, pushing, or sharing externally unless already approved.
- Adding major dependencies.
- Changing public behavior or scope beyond the approved plan.
