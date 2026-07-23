# Installing on Agent Hosts

Design System Guardian has one canonical core and exactly two canonical Agent Skills. Codex, Claude Code, OpenClaw, and Kimi Code load that same package through thin host manifests. Deep Code and any other Agent Skills-compatible host use the generic installer.

Review and pin the full Git commit before installation. A movable branch name is convenient for discovery but is not release authority.

## Requirements

- Python 3.11 or newer for Guardian diagnostics.
- Filesystem and command execution in the agent host.
- An existing Figma connector or complete canonical snapshot evidence.
- A protected, authority-bound Guardian command for any production gate.

If a host cannot load the skills, execute the CLI, or provide complete source evidence, report `unsupported` or the exact source status and stop. Never weaken the policy to make a host appear supported.

## Codex

```powershell
codex plugin marketplace add pv-vimalnair/design-system-guardian --ref main --json
codex plugin add design-system-guardian@pv-vimalnair-design-system-guardian --json
```

Start a new task and confirm that only `build-with-design-system` and `audit-design-system` are exposed by this plugin.

## Claude Code

```powershell
claude plugin marketplace add pv-vimalnair/design-system-guardian
claude plugin install design-system-guardian@pv-vimalnair-design-system-guardian
```

Start a new Claude Code session. The skills are namespaced under `design-system-guardian`.

## OpenClaw

OpenClaw officially maps Codex and Claude bundles, so Guardian does not ship a second native OpenClaw runtime.

```powershell
openclaw plugins marketplace list pv-vimalnair/design-system-guardian
openclaw plugins install design-system-guardian --marketplace pv-vimalnair/design-system-guardian
openclaw plugins inspect design-system-guardian
```

Restart the Gateway or start a new session after installation. Inspection must report a compatible bundle with exactly the two Guardian skills.

## Kimi Code

From Kimi Code, install the public GitHub repository and reload:

```text
/plugins install https://github.com/pv-vimalnair/design-system-guardian
/reload
/plugins info design-system-guardian
```

The repository-root `kimi.plugin.json` points to the same nested canonical skills and Guardian package.

## Deep Code and generic Agent Skills hosts

DeepSeek is a model/API; Deep Code is one skills-capable host for it. Deep Code discovers skills under `~/.agents/skills/` or `<project>/.deepcode/skills/`. Other compatible agents commonly discover `~/.agents/skills/`, `<project>/.agents/skills/`, or a configured skill root.

Clone the repository at a reviewed commit, then run the generic installer with an absolute Python executable. On PowerShell:

```powershell
$python = (Get-Command python -ErrorAction Stop).Source
python plugins/design-system-guardian/scripts/install_agent_skills.py `
  --target-root "$HOME\.agents\skills" `
  --python "$python"
```

On macOS or Linux:

```bash
python_bin="$(command -v python3)"
python3 plugins/design-system-guardian/scripts/install_agent_skills.py \
  --target-root "$HOME/.agents/skills" \
  --python "$python_bin"
```

For a project-local Deep Code install, replace the target with `<project>/.deepcode/skills`. For another host, select its documented Agent Skills root.

The installer exports only the two skill folders. Each installed skill receives a small diagnostic launcher and a drift-detection binding to the deterministic Guardian package-content digest, immutable policy digest, Guardian CLI digest, installed skill files, and absolute Python digest. It does not duplicate `guardian_core`, profiles, catalogs, trust anchors, or audit state.

The binding and launcher are account-owned evidence, not a security boundary against same-account tampering. The generic launcher is diagnostic-only; a host-specific protected execution boundary is still required before Guardian can authorize production.

## Updating

- Codex, Claude Code, OpenClaw, and Kimi Code update through their native marketplace or plugin workflow after the manifest version changes.
- For a generic install, check out the reviewed new Guardian commit and rerun the installer with `--replace`.
- The installer replaces only an intact prior install from the same package root. It refuses unknown or locally modified skill folders.
- An operating-system lock and transaction journal roll back a prepared replacement or finish committed cleanup on the next run after interruption.
- Re-enroll the absolute Python path by rerunning the installer after a Python upgrade.

Every update must preserve the immutable policy digest. A missing or changed policy, changed package content, stale binding, changed interpreter, modified skill, or modified launcher blocks execution.

## What universal support means

Guardian is usable by any host that implements Agent Skills (or equivalent skill injection), allows the two skills to access their bundled resources, and can run the deterministic Guardian CLI. A plain chat surface with no skill loading, filesystem, or command execution cannot enforce Guardian and must remain `unsupported`.
