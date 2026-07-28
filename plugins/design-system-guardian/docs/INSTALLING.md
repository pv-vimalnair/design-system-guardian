# Installing on Agent Hosts

Design System Guardian 0.3.8 has one canonical core and exactly two canonical Agent Skills. Codex, Claude Code, OpenClaw, and Kimi Code load the same package through thin host manifests. Qwen Code, terminal agents, Deep Code, and other Agent Skills-compatible hosts use the integrity-bound generic installer.

Review and pin the full Git commit before installation. A movable branch name is convenient for discovery but is not release authority.

## Requirements

- Python 3.11 or newer for Guardian diagnostics.
- Filesystem and command execution in the agent host.
- An existing Figma connection for Figma work, or complete supported project evidence for another adapter.
- Complete Figma library discovery for the target file. An owner-provided signed onboarding candidate is required only when the user or organization chooses the optional enterprise route.
- A protected, authority-bound Guardian command for any production gate.

If a host cannot load the skills, execute the CLI, access bundled resources, or provide complete supported evidence, it must report `unsupported` or the exact source state and stop. No sealed Guardian manifest means the work is not Guardian-approved.

## Codex

```powershell
codex plugin marketplace add pv-vimalnair/design-system-guardian --ref main --json
codex plugin add design-system-guardian@pv-vimalnair-design-system-guardian --json
```

Start a new task and confirm version `0.3.8` and only `build-with-design-system` and `audit-design-system` are exposed. An install command without this read-back is not a completed reload.

## Claude Code

```powershell
claude plugin marketplace add pv-vimalnair/design-system-guardian
claude plugin install design-system-guardian@pv-vimalnair-design-system-guardian
```

Start a new Claude Code session. Confirm version `0.3.8`; the same two skills must be namespaced under `design-system-guardian`.

## OpenClaw

Guardian reuses the compatible Codex/Claude bundle and does not ship a second native runtime.

```powershell
openclaw plugins marketplace list pv-vimalnair/design-system-guardian
openclaw plugins install design-system-guardian --marketplace pv-vimalnair/design-system-guardian
openclaw plugins inspect design-system-guardian
```

Restart the Gateway or start a new session. Inspection must report version `0.3.8` and a compatible bundle with exactly the two Guardian skills.

## Kimi Code

From Kimi Code, install the public GitHub repository and reload:

```text
/plugins install https://github.com/pv-vimalnair/design-system-guardian
/reload
/plugins info design-system-guardian
```

The repository-root `kimi.plugin.json` points to version `0.3.8`, the same nested canonical skills, and the same Guardian package. `/reload` plus `/plugins info` is required read-back.

## Qwen Code, terminal, Deep Code, and generic Agent Skills hosts

DeepSeek is a model/API; Deep Code is one skills-capable host for it. Common skill roots include Qwen Code's `~/.qwen/skills/`, `~/.agents/skills/`, `<project>/.agents/skills/`, and `<project>/.deepcode/skills/`. A terminal agent uses the exact Agent Skills root it documents. Use only that host's real root; do not create a guessed copy.

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

For Qwen Code, replace the target with `$HOME\.qwen\skills` on Windows or `$HOME/.qwen/skills` on macOS/Linux. A terminal or another compatible host uses the same command with its documented target root.

The installer exports only the two skill folders. Each installed skill receives a diagnostic launcher plus a drift-detection binding to the exact package, immutable policy, CLI, skill files, and absolute Python digest. It does not copy `guardian_core`, profiles, catalogs, trust anchors, or audit state. The generic route is diagnostic-only; a protected host boundary is still required for production authority.

## First use: simple for the user, strict underneath

The agent, not the ordinary user, runs these commands internally:

1. For every new Guardian task, create a new run ID and run `guardian selection status --run-id <run-id>` without writing. A different target Figma file requires a different run and another confirmation.
2. Through the genuine existing Figma connection, discover the complete published library candidates and exact one-to-one catalog read-back for the target file. Never author or reconstruct discovery/read-back; compute content digests from independently read Figma values, not from the catalog being checked. Every canonical token must carry its exact selected variable/style binding and resolved content digest; every component/icon must carry its exact published file, node, asset key, version, design-contract digest, and Code Connect mapping digest. Show each candidate as **Use** or **Do not use**. Do not preselect or silently inherit the prior task's answer.
3. Run `guardian selection preview --run-id <run-id> --input <discovery.json>`. Explain the exact project, target file, selected and excluded libraries, versions, and catalog binding.
4. Only after the user confirms, run `guardian selection apply --input <permission-bound-selection.json>` and read back status. At least one published library must be selected; zero selected libraries block visual work.
5. Use only the selected libraries. Every unselected library is forbidden for that run, even if it was selected for another client, project, task, or Figma file.

Personal selection records, file keys, names, catalogs, profiles, snapshots, and run evidence stay under account-owned Guardian local state. They are not copied into the plugin, marketplace package, project, Git history, public Elo fixtures, or telemetry.

The catalog read-back remains local and is labeled `unprotected_caller_carried`. Guardian rejects incomplete, duplicated, excluded, or internally mismatched catalog/read-back evidence before apply. A same-account caller can still fabricate matching inputs, so this local lane is not independently proven Figma or company approval and never makes `productionReady=true`.

### Optional signed enterprise onboarding

The v0.3.7 enterprise path remains available and unchanged for organizations that require externally signed catalog authority:

1. `guardian setup status --profile <id>` checks readiness without writing.
2. If setup is missing, the agent validates the local owner-provided candidate with `guardian setup preview --input <candidate.json>`.
3. The agent explains the exact local profile, Figma allowlist, and digests, then asks for permission.
4. Only after permission, the agent creates the exact digest-bound permitted bundle and runs `guardian setup apply --input <permitted-bundle.json>`.
5. The agent reruns `guardian setup status --profile <id>` and continues only when the result is ready.
6. When a complete externally signed catalog v2 carries approved usage rules, the agent runs `guardian rules activate preview`, explains the exact activation, and asks permission.
7. Only after permission, the agent runs `guardian rules activate apply` with the exact digest-bound bundle. Permission enables the retained evaluator; it does not approve rules.
8. The agent runs `guardian rules list --profile <id>` read-only and explains the effective rule capability without exposing rule prose or company content.
9. If v2 evaluator coverage is needed, the agent runs `guardian rules upgrade preview --profile <id>` without writing, explains that Guardian can check all six approved machine-rule types including `widget_class`, and asks whether it may save that exact evaluator permission locally.
10. Only after permission, the agent runs `guardian rules upgrade apply --input <permission-bound-bundle.json>`, reruns `guardian rules list`, and keeps design-system, Usage Rules, UX/accessibility, and protected-authority results separate.

## First use: exact-run judgment decisions

After completing an assessment, the agent explains every finding before asking. It preserves raw findings and shows the effective result separately. For a selected conflict, the build skill offers **Fix and evaluate again** or **Approve this exact version anyway**; the user may add an optional reason.

The same four CLI forms work on every supported host that can invoke the bundled Guardian CLI:

    guardian judgment preview --profile <profile-id> --run-id <run-id> --input <candidate.json>
    guardian judgment apply --input <granted-bundle.json>
    guardian judgment status --profile <profile-id> --run-id <run-id>
    guardian judgment revoke --input <granted-revocation.json>

The agent runs these commands for the user. Preview and status are read-only. Apply and revoke require separate explicit permission for the exact local operation, followed by status read-back. An approval is limited to selected conflicts in one exact run; it is reevaluated for every new screen or flow and never carries to a duplicate file, future run, or new version.

This decision layer is additive over v0.3.6. It never changes raw evidence or design-system, Usage Rules, sentinel, stale/incomplete, unsupported, not-assessed, or protected-authority results. Assessments, reasons, decisions, revocations, and company evidence remain local and never enter Git, Elo, or telemetry.

For the optional enterprise route, the candidate must contain the catalog authority public key path, one exact profile, and one signed complete catalog snapshot. Guardian cannot safely generate a company's catalog authority or decide that discovered Figma assets are enterprise-approved. An authorized design-system owner prepares that candidate once; users do not install a second Guardian copy or manually copy a policy seal.

All installed company design-system data is local-only under `~/.design-system-guardian/`. It is never added to the plugin, marketplace package, GitHub update, or telemetry.

## Portable skills, host-controlled routing

Skills are portable; automatic routing is not. Installation on Claude Code, Kimi Code, OpenClaw, or a generic Agent Skills host does not prove that Guardian runs before raw Figma or framework tools.

An enforceable host needs an independently configured always-on protected route that invokes Guardian before visual selection and protects the evidence from the building agent. Without that route, Guardian use is diagnostic or `unsupported`, and Guardian cannot prevent raw-tool bypass. A model name, skill folder, plugin manifest, or default prompt alone is not an enforcement boundary.

Across every host, the portable fallback rule is: No sealed Guardian manifest means not Guardian-approved.

## Updating

Review and pin the new full Git commit, then refresh the installed host package. These commands update public plugin source only; they do not copy local company state into the package.

Codex:

```powershell
codex plugin marketplace upgrade pv-vimalnair-design-system-guardian --json
codex plugin add design-system-guardian@pv-vimalnair-design-system-guardian --json
```

Claude Code:

```powershell
claude plugin marketplace update pv-vimalnair-design-system-guardian
claude plugin update design-system-guardian@pv-vimalnair-design-system-guardian
```

OpenClaw: inspect the dry run before applying it.

```powershell
openclaw plugins update design-system-guardian --dry-run
openclaw plugins update design-system-guardian
openclaw plugins inspect design-system-guardian
```

Kimi Code: rerun the repository install, then reload and inspect.

```text
/plugins install https://github.com/pv-vimalnair/design-system-guardian
/reload
/plugins info design-system-guardian
```

For a generic install, check out the reviewed new commit and inspect the exact target without writing:

```powershell
python plugins/design-system-guardian/scripts/install_agent_skills.py `
  --target-root "$HOME\.agents\skills" `
  --status
```

Status is one of `current`, `update_required`, `reload_required`, or `invalid`. `current` means the version, package, policy, launcher, both skill folders, binding, and recorded runtime all match the reviewed candidate. Any other status is not current. Then rerun the same installer command with `--replace` only when an update is required.

- The installer replaces only an intact prior install from the same package root and refuses unknown or locally modified skill folders.
- A normal update rejects a lower SemVer, malformed version, partial install, or divergent two-skill version before replacing either skill.
- A journal rolls back prepared replacements or finishes committed cleanup after interruption.
- Transient staging remains beside, never inside, the watched live skill root.
- Rerun the installer after a Python upgrade so its exact path and digest are rebound.
- If atomic promotion is blocked by a Windows watcher, Guardian restores the prior intact installation and returns `reload_required` with `host_restart_required`. Close or restart only the named agent host, rerun the same verified `--replace` command, start a new task or session, and rerun `--status`. Guardian never kills a process or overwrites the watched root in place.

After every native or generic update, read back version `0.3.8` and exactly the two canonical skills. Do not claim a host is updated while it reports an older version, `update_required`, `reload_required`, or `invalid`.

Every update must preserve the immutable policy digest. A missing or changed policy, package, interpreter, skill, launcher, or binding blocks execution. Updates never include local profiles, catalogs, Figma observations, audit history, prompts, product source, credentials, or user activity.

## What universal support means

Guardian skills are portable to hosts that implement Agent Skills or equivalent instruction loading, permit bundled-resource access, run the CLI, and supply a supported adapter. Portability is not automatic routing. Clean schema-v2 `personal_local` adapter coverage remains `not_assessed` for Figma and Flutter; caller-carried UX evidence remains `not_assessed` too. Without an always-on protected route, `productionReady=false` and raw-tool bypass cannot be prevented. A plain chat surface remains `unsupported`.
