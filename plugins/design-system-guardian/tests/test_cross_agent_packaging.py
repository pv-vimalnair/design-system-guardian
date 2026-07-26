from __future__ import annotations

import importlib.metadata
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import mock


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = PLUGIN_ROOT.parents[1]
EXPECTED_VERSION = "0.3.4"
EXPECTED_SKILLS = {"audit-design-system", "build-with-design-system"}


def load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: dict[str, object]) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def installer_module() -> ModuleType:
    path = PLUGIN_ROOT / "scripts" / "install_agent_skills.py"
    spec = importlib.util.spec_from_file_location("guardian_generic_installer", path)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load generic installer module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def launcher_module() -> ModuleType:
    path = PLUGIN_ROOT / "scripts" / "generic_skill_launcher.py"
    spec = importlib.util.spec_from_file_location("guardian_generic_launcher", path)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load generic launcher module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CrossAgentPackagingTests(unittest.TestCase):
    def test_host_manifests_share_one_version_and_one_skill_source(self) -> None:
        manifests = {
            "codex": load_json(PLUGIN_ROOT / ".codex-plugin" / "plugin.json"),
            "claude": load_json(PLUGIN_ROOT / ".claude-plugin" / "plugin.json"),
            "kimi": load_json(REPOSITORY_ROOT / "kimi.plugin.json"),
        }

        for host, manifest in manifests.items():
            with self.subTest(host=host):
                self.assertEqual(manifest["name"], "design-system-guardian")
                self.assertEqual(manifest["version"], EXPECTED_VERSION)
                self.assertEqual(manifest["license"], "MIT")

        self.assertEqual(manifests["codex"]["skills"], "./skills/")
        self.assertEqual(manifests["claude"]["skills"], "./skills/")
        self.assertEqual(
            manifests["kimi"]["skills"],
            "./plugins/design-system-guardian/skills/",
        )
        self.assertEqual(
            manifests["codex"]["description"],
            manifests["claude"]["description"],
        )
        self.assertEqual(
            manifests["codex"]["description"],
            manifests["kimi"]["description"],
        )
        self.assertIn(
            "preview-only rule validation",
            str(manifests["codex"]["description"]),
        )
        self.assertEqual(
            manifests["codex"]["interface"]["longDescription"],
            manifests["kimi"]["interface"]["longDescription"],
        )
        self.assertIn(
            "preview-only rule validation",
            str(manifests["codex"]["interface"]["longDescription"]),
        )
        for host, manifest in manifests.items():
            with self.subTest(host=host):
                self.assertIn("rules", manifest["keywords"])

    def test_claude_marketplace_points_to_the_canonical_plugin(self) -> None:
        marketplace = load_json(REPOSITORY_ROOT / ".claude-plugin" / "marketplace.json")
        self.assertEqual(marketplace["name"], "pv-vimalnair-design-system-guardian")
        self.assertEqual(marketplace["owner"], {"name": "Pv Vimal Nair"})
        self.assertEqual(len(marketplace["plugins"]), 1)
        entry = marketplace["plugins"][0]
        self.assertEqual(entry["name"], "design-system-guardian")
        self.assertEqual(entry["source"], "./plugins/design-system-guardian")
        self.assertEqual(entry["version"], EXPECTED_VERSION)
        self.assertEqual(
            entry["description"],
            load_json(PLUGIN_ROOT / ".codex-plugin" / "plugin.json")["description"],
        )
        self.assertIn("rules", entry["tags"])
        self.assertTrue(entry["strict"])

    def test_all_hosts_reuse_exactly_two_canonical_agent_skills(self) -> None:
        skill_dirs = {
            path.name
            for path in (PLUGIN_ROOT / "skills").iterdir()
            if path.is_dir() and (path / "SKILL.md").is_file()
        }
        self.assertEqual(skill_dirs, EXPECTED_SKILLS)

        skill_files = {
            path.relative_to(PLUGIN_ROOT).as_posix()
            for path in PLUGIN_ROOT.rglob("SKILL.md")
        }
        self.assertEqual(
            skill_files,
            {f"skills/{name}/SKILL.md" for name in EXPECTED_SKILLS},
        )

    def test_cross_agent_install_guide_covers_native_and_generic_hosts(self) -> None:
        guide = (PLUGIN_ROOT / "docs" / "INSTALLING.md").read_text(encoding="utf-8")
        for phrase in (
            "Claude Code",
            "OpenClaw",
            "Kimi Code",
            "Deep Code",
            ".agents/skills",
            "Agent Skills-compatible",
            "unsupported",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, guide)

        self.assertNotIn("copy the Guardian core", guide)
        self.assertNotIn("Default routing on every compatible agent", guide)

        kimi = load_json(REPOSITORY_ROOT / "kimi.plugin.json")
        instructions = str(kimi["skillInstructions"])
        self.assertIn("explicitly invoked", instructions)
        self.assertIn("cannot prevent raw-tool bypass", instructions)
        self.assertNotIn("route through one of the two Guardian skills", instructions)

    def test_install_guide_documents_host_refresh_commands(self) -> None:
        guide = (PLUGIN_ROOT / "docs" / "INSTALLING.md").read_text(encoding="utf-8")
        for phrase in (
            "codex plugin marketplace upgrade pv-vimalnair-design-system-guardian --json",
            "codex plugin add design-system-guardian@pv-vimalnair-design-system-guardian --json",
            "claude plugin marketplace update pv-vimalnair-design-system-guardian",
            "claude plugin update design-system-guardian@pv-vimalnair-design-system-guardian",
            "openclaw plugins update design-system-guardian --dry-run",
            "openclaw plugins update design-system-guardian",
            "/plugins install https://github.com/pv-vimalnair/design-system-guardian",
            "/reload",
            "/plugins info design-system-guardian",
            "--replace",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, guide)

    def test_all_agent_guidance_is_fail_closed_and_setup_is_agent_driven(self) -> None:
        guide = (PLUGIN_ROOT / "docs" / "INSTALLING.md").read_text(encoding="utf-8")
        for phrase in (
            "guardian setup status",
            "guardian setup preview",
            "guardian setup apply",
            "No sealed Guardian manifest",
            "local-only",
            "unsupported",
            "Skills are portable; automatic routing is not.",
            "always-on protected route",
            "cannot prevent raw-tool bypass",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, guide)

    def test_install_guide_documents_permission_bound_runtime_bootstrap(self) -> None:
        guide = (PLUGIN_ROOT / "docs" / "INSTALLING.md").read_text(encoding="utf-8")
        for phrase in (
            "--bootstrap-runtime",
            "explicit permission",
            "Python 3.11",
            "isolated Guardian-owned virtual environment",
            "bundled `requirements.txt`",
            "never creates a virtual environment or invokes `pip`",
            "host remains `unsupported`",
            "fail closed",
            "does not create an always-on protected route",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, guide)

        lowered = guide.lower()
        self.assertNotIn("zero prerequisites", lowered)
        self.assertNotIn("no prerequisites", lowered)

    def test_installer_refuses_a_non_python_file(self) -> None:
        installer = PLUGIN_ROOT / "scripts" / "install_agent_skills.py"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fake_python = root / "not-python"
            fake_python.write_text("not an executable\n", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(installer),
                    "--target-root",
                    str(root / "skills"),
                    "--python",
                    str(fake_python.resolve()),
                ],
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("cannot execute --python", result.stderr)

    def test_runtime_bootstrap_is_explicit_and_requires_exact_pins(self) -> None:
        module = installer_module()
        self.assertEqual(
            module.DEFAULT_RUNTIME_BASE,
            Path.home() / ".design-system-guardian" / "runtimes",
        )
        base_arguments = [
            "--target-root",
            str((PLUGIN_ROOT / "unused-skills").resolve()),
            "--python",
            str(Path(sys.executable).resolve()),
        ]
        self.assertFalse(module.parser().parse_args(base_arguments).bootstrap_runtime)
        self.assertTrue(
            module.parser()
            .parse_args([*base_arguments, "--bootstrap-runtime"])
            .bootstrap_runtime
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            invalid = Path(temp_dir) / "requirements.txt"
            invalid.write_text("cryptography>=46.0.7\n", encoding="utf-8")
            with self.assertRaisesRegex(
                module.InstallError,
                "only exact name==version pins",
            ):
                module.load_pinned_requirements(invalid)

    def test_default_install_verifies_host_without_provisioning(self) -> None:
        module = installer_module()
        commands: list[list[str]] = []

        def fake_runner(
            command: list[str],
            **_: object,
        ) -> subprocess.CompletedProcess[bytes]:
            arguments = [str(value) for value in command]
            commands.append(arguments)
            return subprocess.CompletedProcess(arguments, 0, stdout=b"", stderr=b"")

        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "skills"
            with mock.patch.object(module, "provision_runtime") as provision:
                module.install(
                    target,
                    Path(sys.executable).resolve(),
                    False,
                    runtime_runner=fake_runner,
                )
            provision.assert_not_called()
            self.assertEqual(
                {path.name for path in target.iterdir() if path.is_dir()},
                EXPECTED_SKILLS,
            )
            host_checks = [
                command
                for command in commands
                if module.RUNTIME_VERIFICATION in command
            ]
            self.assertEqual(len(host_checks), 1)
            self.assertNotIn("-I", host_checks[0])
            script_index = host_checks[0].index("-c")
            self.assertFalse(json.loads(host_checks[0][script_index + 4]))
            self.assertFalse(
                any(
                    "-m" in command
                    and (
                        "pip" in command
                        or "venv" in command
                    )
                    for command in commands
                )
            )

    def test_default_dependency_failure_is_read_only_and_points_to_bootstrap(self) -> None:
        module = installer_module()

        def failing_runner(
            command: list[str],
            **_: object,
        ) -> subprocess.CompletedProcess[bytes]:
            arguments = [str(value) for value in command]
            if module.RUNTIME_VERIFICATION in arguments:
                return subprocess.CompletedProcess(
                    arguments,
                    1,
                    stdout=b"",
                    stderr=b"cffi: expected 2.1.0, found missing",
                )
            return subprocess.CompletedProcess(arguments, 0, stdout=b"", stderr=b"")

        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "skills"
            with self.assertRaisesRegex(
                module.InstallError,
                "--bootstrap-runtime",
            ):
                module.install(
                    target,
                    Path(sys.executable).resolve(),
                    False,
                    runtime_runner=failing_runner,
                )
            self.assertFalse(target.exists())

    def test_runtime_verifier_rejects_unpinned_only_in_isolated_mode(self) -> None:
        module = installer_module()
        approved = [
            SimpleNamespace(metadata={"Name": name}, version=version)
            for name, version in module.REQUIRED_RUNTIME_PINS.items()
        ]
        bootstrap = [
            SimpleNamespace(metadata={"Name": name}, version="1.0")
            for name in module.BOOTSTRAP_DISTRIBUTIONS
        ]
        rogue = SimpleNamespace(
            metadata={"Name": "rogue-package"},
            version="9.9",
        )

        def execute(distributions: list[object], *, strict: bool) -> object:
            arguments = [
                "verify-runtime",
                json.dumps(module.REQUIRED_RUNTIME_PINS),
                json.dumps(module.RUNTIME_IMPORTS),
                json.dumps(strict),
                json.dumps(module.BOOTSTRAP_DISTRIBUTIONS),
            ]
            with (
                mock.patch.object(
                    importlib.metadata,
                    "distributions",
                    return_value=distributions,
                ),
                mock.patch.object(importlib, "import_module"),
                mock.patch.object(sys, "argv", arguments),
                self.assertRaises(SystemExit) as exit_result,
            ):
                exec(module.RUNTIME_VERIFICATION, {})
            return exit_result.exception.code

        self.assertEqual(execute([*approved, *bootstrap], strict=True), 0)
        strict_failure = execute([*approved, *bootstrap, rogue], strict=True)
        self.assertIn("unexpected runtime distributions", str(strict_failure))
        self.assertEqual(
            execute([*approved, *bootstrap, rogue], strict=False),
            0,
        )

    def test_runtime_storage_rejects_symlink_and_reparse_redirects(self) -> None:
        module = installer_module()
        symlink = SimpleNamespace(st_mode=module.stat.S_IFLNK, st_file_attributes=0)
        reparse = SimpleNamespace(
            st_mode=module.stat.S_IFDIR,
            st_file_attributes=module.REPARSE_POINT_FLAG,
        )
        with mock.patch.object(module.os, "lstat", return_value=symlink):
            self.assertTrue(module._path_is_redirect(Path("redirect")))
        with mock.patch.object(module.os, "lstat", return_value=reparse):
            self.assertTrue(module._path_is_redirect(Path("redirect")))

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            redirected = root / "guardian-local"
            runtime_base = redirected / "runtimes"

            def redirect_component(path: Path) -> bool:
                return Path(path).absolute() == redirected.absolute()

            with (
                mock.patch.object(
                    module,
                    "_path_is_redirect",
                    side_effect=redirect_component,
                ),
                self.assertRaisesRegex(
                    module.InstallError,
                    "runtime storage redirect is forbidden",
                ),
            ):
                module.install(
                    root / "project" / ".agents" / "skills",
                    Path(sys.executable).resolve(),
                    False,
                    bootstrap_runtime=True,
                    runtime_runner=lambda command, **_: subprocess.CompletedProcess(
                        command,
                        0,
                        stdout=b"",
                        stderr=b"",
                    ),
                    runtime_base=runtime_base,
                )
            self.assertFalse(runtime_base.exists())
    def test_opt_in_bootstrap_binds_the_account_local_runtime(self) -> None:
        module = installer_module()
        commands: list[list[str]] = []

        def fake_runner(
            command: list[str],
            **_: object,
        ) -> subprocess.CompletedProcess[bytes]:
            arguments = [str(value) for value in command]
            commands.append(arguments)
            if arguments[1:5] == ["-I", "-m", "venv", "--copies"]:
                stage_root = Path(arguments[-1])
                fake_python = module.runtime_python_path(stage_root)
                fake_python.parent.mkdir(parents=True, exist_ok=True)
                fake_python.write_bytes(b"guardian isolated python")
            return subprocess.CompletedProcess(arguments, 0, stdout=b"", stderr=b"")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            project_root = root / "project-repository"
            target = project_root / ".agents" / "skills"
            runtime_base = root / "guardian-local" / "runtimes"
            module.install(
                target,
                Path(sys.executable).resolve(),
                False,
                bootstrap_runtime=True,
                runtime_runner=fake_runner,
                runtime_base=runtime_base,
            )

            runtime_roots = list(runtime_base.iterdir())
            self.assertEqual(len(runtime_roots), 1)
            runtime_root = runtime_roots[0]
            runtime_python = module.runtime_python_path(runtime_root)
            marker = load_json(runtime_root / module.RUNTIME_MARKER_NAME)
            self.assertEqual(marker["owner"], "design-system-guardian")
            self.assertEqual(Path(str(marker["targetRoot"])).resolve(), target.resolve())
            self.assertTrue(runtime_root.resolve().is_relative_to(runtime_base.resolve()))
            self.assertFalse(runtime_root.resolve().is_relative_to(project_root.resolve()))
            self.assertEqual(
                {path.name for path in target.parent.iterdir()},
                {"skills"},
            )
            self.assertEqual(
                marker["requirements"]["pins"],
                {"cffi": "2.1.0", "cryptography": "46.0.7", "pycparser": "3.0"},
            )

            for name in EXPECTED_SKILLS:
                binding = load_json(
                    target
                    / name
                    / "references"
                    / "guardian-install.json"
                )
                self.assertEqual(
                    Path(str(binding["python"]["path"])).resolve(),
                    runtime_python.resolve(),
                )
            self.assertEqual(
                {path.name for path in target.iterdir() if path.is_dir()},
                EXPECTED_SKILLS,
            )

            venv_calls = [
                command
                for command in commands
                if command[1:5] == ["-I", "-m", "venv", "--copies"]
            ]
            pip_calls = [
                command
                for command in commands
                if command[1:4] == ["-I", "-m", "pip"]
            ]
            self.assertEqual(len(venv_calls), 1)
            self.assertEqual(len(pip_calls), 1)
            self.assertEqual(
                pip_calls[0][4:],
                [
                    "--isolated",
                    "--disable-pip-version-check",
                    "install",
                    "--no-input",
                    "--no-deps",
                    "--requirement",
                    str((PLUGIN_ROOT / "requirements.txt").resolve()),
                ],
            )
            self.assertNotIn("cryptography==46.0.7", pip_calls[0])
            verification_calls = [
                command
                for command in commands
                if command[1:3] == ["-I", "-c"]
                and "importlib.metadata" in command[3]
            ]
            self.assertGreaterEqual(len(verification_calls), 2)
            self.assertEqual(
                json.loads(verification_calls[0][4]),
                {"cffi": "2.1.0", "cryptography": "46.0.7", "pycparser": "3.0"},
            )
            self.assertEqual(
                set(json.loads(verification_calls[0][5])),
                set(module.RUNTIME_IMPORTS),
            )

            module.install(
                target,
                Path(sys.executable).resolve(),
                True,
                bootstrap_runtime=True,
                runtime_runner=fake_runner,
                runtime_base=runtime_base,
            )
            self.assertEqual(
                sum(
                    command[1:5] == ["-I", "-m", "venv", "--copies"]
                    for command in commands
                ),
                1,
            )
            self.assertEqual(
                sum(
                    command[1:4] == ["-I", "-m", "pip"]
                    for command in commands
                ),
                1,
            )

    def test_package_digest_covers_runtime_sentinel_resources(self) -> None:
        installer = installer_module()
        launcher = launcher_module()
        self.assertEqual(installer.PACKAGE_ENTRIES, launcher.PACKAGE_ENTRIES)
        self.assertIn("sentinels", installer.PACKAGE_ENTRIES)
        self.assertIn("requirements.txt", installer.PACKAGE_ENTRIES)

        with tempfile.TemporaryDirectory() as temp_dir:
            package_copy = Path(temp_dir) / "package"
            package_copy.mkdir()
            ignored = shutil.ignore_patterns(
                ".dart_tool",
                ".pytest_cache",
                "__pycache__",
                "*.pyc",
                "*.pyo",
                "build",
            )
            for entry_name in installer.PACKAGE_ENTRIES:
                source = PLUGIN_ROOT / entry_name
                destination = package_copy / entry_name
                if source.is_dir():
                    shutil.copytree(source, destination, ignore=ignored)
                else:
                    shutil.copy2(source, destination)

            before = installer.package_digest(package_copy)
            self.assertEqual(before, launcher.package_digest(package_copy))
            sentinel = package_copy / "sentinels" / "manifest.json"
            sentinel.write_text(sentinel.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            after = installer.package_digest(package_copy)
            self.assertNotEqual(before, after)
            self.assertEqual(after, launcher.package_digest(package_copy))

    def test_generic_installer_exports_only_the_two_skills_and_binds_one_core(self) -> None:
        installer = PLUGIN_ROOT / "scripts" / "install_agent_skills.py"
        module = installer_module()
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "skills"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(installer),
                    "--target-root",
                    str(target),
                    "--python",
                    sys.executable,
                ],
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                {path.name for path in target.iterdir() if path.is_dir()},
                EXPECTED_SKILLS,
            )
            for name in EXPECTED_SKILLS:
                installed = target / name
                self.assertTrue((installed / "SKILL.md").is_file())
                binding = load_json(installed / "references" / "guardian-install.json")
                self.assertEqual(binding["mode"], "diagnostic-only")
                self.assertEqual(Path(str(binding["packageRoot"])), PLUGIN_ROOT.resolve())
                self.assertEqual(binding["pluginVersion"], EXPECTED_VERSION)
                self.assertEqual(binding["packageDigest"], module.package_digest(PLUGIN_ROOT))
                self.assertTrue((installed / "scripts" / "guardian.py").is_file())
                self.assertFalse((installed / "guardian_core").exists())

                help_result = subprocess.run(
                    [sys.executable, str(installed / "scripts" / "guardian.py"), "--help"],
                    capture_output=True,
                    check=False,
                    text=True,
                )
                self.assertEqual(help_result.returncode, 0, help_result.stderr)
                self.assertIn("doctor", help_result.stdout)

            audit_binding_path = (
                target
                / "audit-design-system"
                / "references"
                / "guardian-install.json"
            )
            original_binding = load_json(audit_binding_path)
            changed_digest = dict(original_binding)
            changed_digest["packageDigest"] = "0" * 64
            write_json(audit_binding_path, changed_digest)
            blocked_digest = subprocess.run(
                [
                    sys.executable,
                    str(target / "audit-design-system" / "scripts" / "guardian.py"),
                    "--help",
                ],
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertEqual(blocked_digest.returncode, 2)
            self.assertIn("package digest mismatch", blocked_digest.stderr.lower())

            missing_package = dict(original_binding)
            missing_package["packageRoot"] = str((Path(temp_dir) / "missing-package").resolve())
            write_json(audit_binding_path, missing_package)
            blocked_manifest = subprocess.run(
                [
                    sys.executable,
                    str(target / "audit-design-system" / "scripts" / "guardian.py"),
                    "--help",
                ],
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertEqual(blocked_manifest.returncode, 2)
            self.assertIn("missing json evidence", blocked_manifest.stderr.lower())
            write_json(audit_binding_path, original_binding)

            repeated = subprocess.run(
                [
                    sys.executable,
                    str(installer),
                    "--target-root",
                    str(target),
                    "--python",
                    sys.executable,
                    "--replace",
                ],
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertEqual(repeated.returncode, 0, repeated.stderr)

            changed_skill = target / "build-with-design-system" / "SKILL.md"
            changed_skill.write_text("modified\n", encoding="utf-8")
            blocked_launcher = subprocess.run(
                [
                    sys.executable,
                    str(target / "build-with-design-system" / "scripts" / "guardian.py"),
                    "--help",
                ],
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertEqual(blocked_launcher.returncode, 2)
            self.assertIn("managed skill content changed", blocked_launcher.stderr)

            refused = subprocess.run(
                [
                    sys.executable,
                    str(installer),
                    "--target-root",
                    str(target),
                    "--python",
                    sys.executable,
                    "--replace",
                ],
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertEqual(refused.returncode, 2)
            self.assertIn("refusing to replace modified skill", refused.stderr)

    def test_interrupted_replacement_recovers_after_each_rename(self) -> None:
        module = installer_module()
        operations = [
            ("backup", "audit-design-system"),
            ("promote", "audit-design-system"),
            ("backup", "build-with-design-system"),
            ("promote", "build-with-design-system"),
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for interruption_after in range(1, len(operations) + 1):
                with self.subTest(interruption_after=interruption_after):
                    target = root / f"skills-{interruption_after}"
                    module.install(target, Path(sys.executable), False)

                    manifest = load_json(PLUGIN_ROOT / ".codex-plugin" / "plugin.json")
                    binding = module.make_binding(
                        Path(sys.executable).resolve(),
                        manifest["version"],
                    )
                    transaction = f"{interruption_after:032x}"
                    stage_root, backup_root = module._transaction_paths(
                        target,
                        transaction,
                    )
                    self.assertEqual(stage_root.parent, target.parent)
                    self.assertEqual(backup_root.parent, target.parent)
                    self.assertNotEqual(stage_root.parent, target)
                    stage_root.mkdir()
                    backup_root.mkdir()
                    module.write_journal(
                        target,
                        transaction,
                        {name: True for name in module.SKILL_NAMES},
                        phase="prepared",
                    )
                    for name in module.SKILL_NAMES:
                        module.stage_skill(name, stage_root, binding)

                    for action, name in operations[:interruption_after]:
                        if action == "backup":
                            (target / name).rename(backup_root / name)
                        else:
                            (stage_root / name).rename(target / name)

                    self.assertTrue(module.recover_interrupted(target))
                    for name in module.SKILL_NAMES:
                        module.validate_managed_skill(target / name)
                    self.assertFalse((target / module.JOURNAL_NAME).exists())
                    self.assertFalse(stage_root.exists())
                    self.assertFalse(backup_root.exists())

            shutil.rmtree(root, ignore_errors=False)


if __name__ == "__main__":
    unittest.main()
