# Agent Instructions

## Defaults

- Read `.ai/session.md` before starting. If it is the template stub, treat the user's prompt as the starting point.
- Consult `.ai/commands.md` before running build / test / lint commands; add commands there as they are established.
- See `.ai/index.md` for the list of supporting files and when to read each.
- Preserve user changes; do not reset or discard work unless asked.
- Follow existing project patterns.
- Make small, focused edits.
- Run relevant checks when practical.
- Update `.ai/session.md` at the end of a meaningful work unit or before a likely context reset. Trivial edits (typos, one-liners) do not require a session.md update.

## What counts as substantial

Work that should survive a context reset: multiple files changed, a completed milestone, or work spanning more than one session. The defaults above apply outside an active workflow; substantial work uses one of the workflows below.

## Workflow selection

Switch into a workflow when the task qualifies. If unsure which applies, propose a workflow before starting and wait for confirmation.

- `.ai/workflows/plan-then-execute.md` — substantial coding tasks where the user wants upfront planning before implementation.
- `.ai/workflows/big-work.md` — substantial writing, IETF drafts, research, planning, or mixed tasks.

Both workflows share `.ai/workflows/_contract.md`.

## Git checkpoints

After substantial work, follow `.ai/git.md` and create a local commit unless the user asks not to. Local commits do not require permission; pushes do. If the project has no git repo, skip commits — file-system state is the only durable artifact.

## Kickoff prompts

Fresh start:

> Read AGENTS.md, then load `.ai/session.md` and propose the next step.

Resume:

> Resume from `.ai/session.md`.
