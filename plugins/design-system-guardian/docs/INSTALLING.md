# Installing on Agent Hosts

Design System Guardian has one canonical core and exactly two canonical Agent Skills. Codex, Claude Code, OpenClaw, and Kimi Code load the same package through thin host manifests. Deep Code and other Agent Skills-compatible hosts use the integrity-bound generic installer.

Review and pin the full Git commit before installation. A movable branch name is convenient for discovery but is not release authority.

## Requirements

- Python 3.11 or newer for Guardian diagnostics.
- Filesystem and command execution in the agent host.
- An existing Figma connection for Figma work, or complete supported project evidence for another adapter.
- A design-system-owner-provided local onboarding candidate for a company that has not been enrolled yet.
- A protected, authority-bound Guardian command for any production gate.

If a host cannot load the skills, execute the CLI, access bundled resources, or provide complete supported evidence, it must report `unsupported` or the exact source state and stop. No sealed Guardian manifest means the work is not Guardian-approved.

## Codex

```powershell
codex plugin marketplace add pv-vimalnair/design-system-guardian --ref main --json
codex plugin add design-system-guardian@pv-vimalnair-design-system-guardian --json
```

Start a new task and confirm that only `build-with-design-system` and `audit-design-system` are exposed.

## Claude Code

```powershell
claude plugin marketplace add pv-vimalnair/design-system-guardian
claude plugin install design-system-guardian@pv-vimalnair-design-system-guardian
```

Start a new Claude Code session. The same two skills are namespaced under `design-system-guardian`.

## OpenClaw

Guardian reuses the compatible Codex/Claude bundle and does not ship a second native runtime.

```powershell
openclaw plugins marketplace list pv-vimalnair/design-system-guardian
openclaw plugins install design-system-guardian --marketplace pv-vimalnair/design-system-guardian
openclaw plugins inspect design-system-guardian
```

Restart the Gateway or start a new session. Inspection must report a compatible bundle with exactly the two Guardian skills.

## Kimi Code

From Kimi Code, install the public GitHub repository and reload:

```text
/plugins install https://github.com/pv-vimalnair/design-system-guardian
/reload
/plugins info design-system-guardian
```

The repository-root `kimi.plugin.json` points to the same nested canonical skills and Guardian package.

## Deep Code and generic Agent Skills hosts

DeepSeek is a model/API; Deep Code is one skills-capable host for it. Common skill roots include `~/.agents/skills/`, `<project>/.agents/skills/`, and `<project>/.deepcode/skills/`. Use the exact root documented by the host.

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

### Optional fresh-host diagnostic runtime

The commands above are the default path: without `--bootstrap-runtime`, the installer never creates a virtual environment or invokes `pip`. It first performs a read-only check that `cryptography==46.0.7`, `cffi==2.1.0`, and `pycparser==3.0` and their required imports are present in the selected Python. Unrelated host distributions are allowed. A mismatch blocks before the skill target is written and points to the permission-bound bootstrap option.

When the host needs an isolated diagnostic runtime, the agent must first explain the exact local change and ask for explicit permission. Only after permission may it add the flag:

```powershell
$python = (Get-Command python -ErrorAction Stop).Source
python plugins/design-system-guardian/scripts/install_agent_skills.py `
  --target-root "$HOME\.agents\skills" `
  --python "$python" `
  --bootstrap-runtime
```

An absolute Python 3.11+ executable remains required; this option does not install Python. Guardian rejects symlinks, Windows junctions, and other reparse-point redirects before and after creating runtime storage; the accepted default must remain under the real account-local `~/.design-system-guardian/runtimes/` path. Guardian creates an isolated Guardian-owned virtual environment under `~/.design-system-guardian/runtimes/<integrity-id>/`, outside the project and skill roots. It installs exactly `cryptography==46.0.7`, `cffi==2.1.0`, and `pycparser==3.0` from the bundled `requirements.txt` with pip dependency resolution disabled. Strict verification then rejects every other installed distribution except `pip`, `setuptools`, and `wheel`, and verifies all required imports before binding either skill launcher.

If Python, virtual-environment creation, pinned dependency installation, or verification is unavailable or fails, the installation blocks with exit `2` and the host remains `unsupported`. Guardian must fail closed: a failed bootstrap is never treated as a working installation or production approval. This diagnostic option does not create an always-on protected route.

For a project-local Deep Code install, replace the target with `<project>/.deepcode/skills`.

The installer exports only the two skill folders. Each installed skill receives a diagnostic launcher plus a drift-detection binding to the exact package, immutable policy, CLI, skill files, and absolute Python digest. It does not copy `guardian_core`, profiles, catalogs, trust anchors, or audit state. The generic route is diagnostic-only; a protected host boundary is still required for production authority.

## First use: simple for the user, strict underneath

The agent, not the ordinary user, runs these commands internally:

1. `guardian setup status --profile <id>` checks readiness without writing.
2. If setup is missing, the agent validates the local owner-provided candidate with `guardian setup preview --input <candidate.json>`.
3. The agent explains the exact local profile, Figma allowlist, and digests, then asks for permission.
4. Only after permission, the agent creates the exact digest-bound permitted bundle and runs `guardian setup apply --input <permitted-bundle.json>`.
5. The agent reruns `guardian setup status --profile <id>` and continues only when the result is ready.

The candidate must contain the catalog authority public key path, one exact profile, and one signed complete catalog snapshot. Guardian cannot safely generate a company's catalog authority or decide that discovered Figma assets are approved. An authorized design-system owner prepares that candidate once; users do not install a second Guardian copy or manually copy a policy seal.

All installed company design-system data is local-only under `~/.design-system-guardian/`. It is never added to the plugin, marketplace package, GitHub update, or telemetry.

## Portable skills, host-controlled routing

Skills are portable; automatic routing is not. Installation on Claude Code, Kimi Code, OpenClaw, or a generic Agent Skills host does not prove that Guardian runs before raw Figma or framework tools.

An enforceable host needs an independently configured always-on protected route that invokes Guardian before visual selection and protects the evidence from the building agent. Without that route, Guardian use is diagnostic or `unsupported`, and Guardian cannot prevent raw-tool bypass. A model name, skill folder, plugin manifest, or default prompt alone is not an enforcement boundary.

Across every host, the portable fallback rule is: No sealed Guardian manifest means not Guardian-approved.

## Updating

- Codex, Claude Code, OpenClaw, and Kimi Code update through their native marketplace or plugin workflow after the manifest version changes.
- For a generic install, check out the reviewed new commit and rerun the installer with `--replace`.
- The installer replaces only an intact prior install from the same package root and refuses unknown or locally modified skill folders.
- A journal rolls back prepared replacements or finishes committed cleanup after interruption.
- Transient staging remains beside, never inside, the watched live skill root.
- Rerun the installer after a Python upgrade so its exact path and digest are rebound.

Every update must preserve the immutable policy digest. A missing or changed policy, package, interpreter, skill, launcher, or binding blocks execution. Updates never include local profiles, catalogs, Figma observations, audit history, prompts, product source, credentials, or user activity.

## What universal support means

Guardian skills are portable to hosts that implement Agent Skills or equivalent instruction loading, permit bundled-resource access, run the CLI, and supply a supported adapter. Portability is not automatic routing. Without an always-on protected route, local Figma/UX evidence is diagnostic, clean evidence stays `not_assessed`, and raw-tool bypass cannot be prevented. A plain chat surface remains `unsupported`.
