from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = PLUGIN_ROOT.parents[1]
EXPECTED_VERSION = "0.3.0"
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

    def test_claude_marketplace_points_to_the_canonical_plugin(self) -> None:
        marketplace = load_json(REPOSITORY_ROOT / ".claude-plugin" / "marketplace.json")
        self.assertEqual(marketplace["name"], "pv-vimalnair-design-system-guardian")
        self.assertEqual(marketplace["owner"], {"name": "Pv Vimal Nair"})
        self.assertEqual(len(marketplace["plugins"]), 1)
        entry = marketplace["plugins"][0]
        self.assertEqual(entry["name"], "design-system-guardian")
        self.assertEqual(entry["source"], "./plugins/design-system-guardian")
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
                    stage_root = target / f".guardian-stage-{transaction}"
                    backup_root = target / f".guardian-backup-{transaction}"
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
