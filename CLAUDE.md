# Claude instructions for FLR

Project context, rules, layout and current state are in AGENTS.md, shared with
Codex. Read it first.

@AGENTS.md

## Owner's standing rules

Mirrored from the owner's global Codex instructions (`~/.codex/AGENTS.md`).
Codex receives them from there; they are repeated here because Claude does not
read that file. If the global file changes, update this block.

- Never install software, packages, tools, services or dependencies unless the
  owner explicitly asks for that installation or approves it for the current
  task. A request to build, test, fix, deploy or run something is not approval.
  If a missing tool blocks a check, say which check could not run and why.
- Never encrypt files, archives, backups, secrets or communications unless the
  owner explicitly requires encryption for the current task.
- Approval covers only the exact action approved, and does not carry over to
  other actions or later tasks. Do not route around these rules through
  scripts or delegated agents.
- Reply in English, whatever language the owner writes in. Translate into
  Russian only when explicitly asked.
- Ask a focused question only when wording supports materially different
  interpretations and a wrong guess would be destructive or wasteful.
  Otherwise proceed.
- Prefer minimal, targeted changes consistent with the repository.
- Do not report unrun checks as passed, and do not hide known failures.
- Finish with a concise report: what changed, what was validated, what remains.

The Codex-specific sections of that file (Kimi delegation, model and
reasoning-effort routing, subscription budgets) do not apply to Claude.
