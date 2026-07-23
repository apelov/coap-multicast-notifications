# Git Checkpoints

Use git as the durable checkpoint after substantial work. If the project has no git repo, skip this file — file-system state is the only durable artifact.

## Default: Local Repository

After a substantial completed task:

1. Run relevant checks first.
2. Update `.ai/session.md`.
3. Review `git status` and `git diff`.
4. Stage only files that belong to the completed work.
5. Commit with a concise message.

Do not commit unrelated user changes unless the user explicitly asks.

Suggested commit style:

```text
type: short summary
```

Examples:

```text
feat: add plan-then-execute workflow
docs: update agent handoff policy
test: cover parser edge cases
fix: preserve user edits during setup
```

## GitHub Private Repository

Use GitHub only when the user asks for it or approves it. Requires `gh auth login` first.

If there is no GitHub remote yet, use `gh` to create a private repo:

```sh
gh repo create <repo-name> --private --source=. --remote=origin --push
```

If `origin` already exists:

```sh
git push -u origin HEAD
```

Ask before pushing if the user has not already authorized GitHub publication for this project.

## Never Do Without Explicit Permission

- `git reset --hard`
- `git clean`
- `git checkout -- <path>` to discard changes
- Force-push
- Commit secrets, credentials, or local-only config
