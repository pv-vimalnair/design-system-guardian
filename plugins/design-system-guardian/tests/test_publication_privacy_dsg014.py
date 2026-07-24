from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path
from types import ModuleType


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CHECKER_PATH = REPOSITORY_ROOT / "scripts" / "check_public_release.py"
BOOTSTRAP_COMMIT = "05f736facf2187af638cf0ea6cb3897c77711c06"


def checker_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("guardian_public_release", CHECKER_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load public-release checker")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=root, capture_output=True, check=False)
    if result.returncode:
        raise AssertionError(result.stderr.decode("utf-8", "replace"))
    return result.stdout.decode("utf-8", "strict").strip()


def write(root: Path, relative: str, value: str | bytes) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, bytes):
        path.write_bytes(value)
    else:
        path.write_text(value, encoding="utf-8", newline="\n")


def commit(root: Path, message: str = "fixture") -> str:
    git(root, "add", "-A")
    git(root, "commit", "-m", message)
    return git(root, "rev-parse", "HEAD")


def make_repo(parent: Path) -> Path:
    root = parent / "repo"
    root.mkdir()
    git(root, "init", "-b", "main")
    git(root, "config", "user.email", "guardian-tests@example.invalid")
    git(root, "config", "user.name", "Guardian Tests")
    write(root, "README.md", "# Public fixture\n")
    write(root, ".gitignore", "*.tmp\n")
    write(root, "LICENSE", "fixture\n")
    write(root, "plugins/design-system-guardian/policy/policy-v1.json", '{"fixture":true}\n')
    return root


class PublicationPrivacyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.checker = checker_module()

    def scan(self, root: Path, **kwargs: object):
        return self.checker.check_public_release(
            root,
            history=False,
            local_home=None,
            require_clean=True,
            check_prior_suite=False,
            **kwargs,
        )

    def test_clean_scan_reads_committed_bytes_and_rejects_dirty_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = make_repo(Path(temp))
            commit(root)
            write(root, "README.md", "uncommitted " + "ghp_" + "abcdefghijklmnopqrstuvwxyz123456\n")
            blocked = self.scan(root)
            self.assertFalse(blocked.ok)
            self.assertIn("dirty_tree", blocked.codes)
            committed_only = self.checker.check_public_release(
                root, history=False, local_home=None, require_clean=False,
                check_prior_suite=False,
            )
            self.assertTrue(committed_only.ok, self.checker.render_result(committed_only))

    def test_strict_allowlist_and_runtime_state_are_rejected(self) -> None:
        fixtures = {
            "unknown-root.txt": "public-looking\n",
            "plugins/design-system-guardian/profiles/acme.json": '{"profileId":"acme"}\n',
            "plugins/design-system-guardian/docs/runtime.json": json.dumps(
                {"profileId": "company-profile", "snapshotId": "snap-1", "runId": "run-1"}
            ),
        }
        for relative, payload in fixtures.items():
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temp:
                root = make_repo(Path(temp))
                write(root, relative, payload)
                commit(root)
                result = self.scan(root)
                self.assertFalse(result.ok)
                self.assertTrue(
                    {"path_not_allowed", "runtime_state"}.intersection(result.codes),
                    self.checker.render_result(result),
                )

    def test_absolute_homes_and_secret_shapes_are_rejected(self) -> None:
        payloads = (
            "C:" + "\\Users\\PublicLeakCandidate\\.design-system-guardian\\profiles\\one.json\n",
            "/" + "home/public-leak-candidate/.design-system-guardian/profiles/one.json\n",
            "/" + "root/.design-system-guardian/profiles/one.json\n",
            "-----BEGIN " + "PRIVATE KEY-----\n",
            "ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890AB\n",
        )
        for payload in payloads:
            with self.subTest(kind=payload[:8]), tempfile.TemporaryDirectory() as temp:
                root = make_repo(Path(temp))
                write(root, "plugins/design-system-guardian/docs/evidence.md", payload)
                commit(root)
                result = self.scan(root)
                self.assertFalse(result.ok)
                self.assertTrue(
                    {"absolute_home", "secret_material"}.intersection(result.codes),
                    self.checker.render_result(result),
                )

    def test_symlink_mode_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = make_repo(Path(temp))
            commit(root)
            blob = git(root, "hash-object", "-w", "README.md")
            git(
                root, "update-index", "--add", "--cacheinfo",
                f"120000,{blob},plugins/design-system-guardian/docs/link",
            )
            git(root, "commit", "-m", "symlink mode")
            result = self.scan(root)
            self.assertFalse(result.ok)
            self.assertIn("unsupported_git_mode", result.codes)

    def test_gitlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = make_repo(Path(temp))
            commit(root)
            git(
                root, "update-index", "--add", "--cacheinfo",
                "160000,1111111111111111111111111111111111111111,plugins/design-system-guardian/vendor",
            )
            git(root, "commit", "-m", "gitlink")
            result = self.scan(root)
            self.assertFalse(result.ok)
            self.assertIn("unsupported_git_mode", result.codes)

    def test_local_hash_and_identifier_matches_are_redacted(self) -> None:
        private_id = "company-profile-7e43c9f8"
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = make_repo(base)
            private_payload = json.dumps(
                {"profileId": private_id, "displayName": "Private Design System"}
            ) + "\n"
            write(root, "plugins/design-system-guardian/docs/sample.json", private_payload)
            commit(root)
            home = base / "private-home"
            write(home, "profiles/private.json", private_payload)
            result = self.checker.check_public_release(
                root, history=False, local_home=home, require_clean=True,
                check_prior_suite=False,
            )
            rendered = self.checker.render_result(result)
            self.assertFalse(result.ok)
            self.assertTrue({"local_file_match", "local_identifier_match"}.intersection(result.codes))
            self.assertNotIn(private_id, rendered)
            self.assertNotIn(str(home), rendered)

    def test_reachable_history_is_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = make_repo(Path(temp))
            write(root, "plugins/design-system-guardian/docs/old.md", "-----BEGIN " + "PRIVATE KEY-----\n")
            commit(root, "secret")
            (root / "plugins/design-system-guardian/docs/old.md").unlink()
            commit(root, "remove")
            current = self.scan(root)
            self.assertTrue(current.ok)
            history = self.checker.check_public_release(
                root, history=True, local_home=None, require_clean=True,
                check_prior_suite=False,
            )
            self.assertFalse(history.ok)
            self.assertIn("history_violation", history.codes)

    def test_history_compares_local_hashes_and_semantic_identifiers(self) -> None:
        private_identifier = "company-design-é-7e43c9f8"
        private_binary = b"private-design-system-binary\x00fixture"
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = make_repo(base)
            write(
                root,
                "plugins/design-system-guardian/docs/removed.json",
                json.dumps({"profileId": private_identifier}, ensure_ascii=True) + "\n",
            )
            write(root, "plugins/design-system-guardian/docs/removed.bin", private_binary)
            commit(root, "private historical evidence")
            (root / "plugins/design-system-guardian/docs/removed.json").unlink()
            (root / "plugins/design-system-guardian/docs/removed.bin").unlink()
            commit(root, "remove private historical evidence")
            home = base / "private-home"
            write(
                home,
                "profiles/private.json",
                json.dumps({"profileId": private_identifier}, ensure_ascii=False) + "\n",
            )
            write(home, "snapshots/private.bin", private_binary)
            result = self.checker.check_public_release(
                root,
                history=True,
                local_home=home,
                require_clean=True,
                check_prior_suite=False,
            )
            rendered = self.checker.render_result(result)
            self.assertIn("local_file_match", result.codes)
            self.assertIn("local_identifier_match", result.codes)
            self.assertNotIn(private_identifier, rendered)
            self.assertNotIn(str(home), rendered)

    def test_linked_local_subtree_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = make_repo(base)
            commit(root)
            home = base / "private-home"
            write(home, "profiles/linked/private.json", '{"profileId":"private-profile-123"}\n')
            original = self.checker._is_link_or_reparse

            def simulated_reparse(path: Path) -> bool:
                return path.name == "linked" or original(path)

            with mock.patch.object(self.checker, "_is_link_or_reparse", side_effect=simulated_reparse):
                result = self.checker.check_public_release(
                    root,
                    history=False,
                    local_home=home,
                    require_clean=True,
                    check_prior_suite=False,
                )
            self.assertFalse(result.ok)
            self.assertIn("local_state_unavailable", result.codes)
    def test_output_is_deterministic_and_contains_no_values(self) -> None:
        result = self.checker.ReleaseResult(False, ("runtime_state", "dirty_tree", "runtime_state"))
        self.assertEqual(
            self.checker.render_result(result),
            "FAIL clean-public-release [dirty_tree,runtime_state]",
        )

    def test_prior_suite_bootstrap_is_exact_and_transition_is_additive(self) -> None:
        current = json.loads((REPOSITORY_ROOT / "plugins/design-system-guardian/benchmarks/elo-suite.json").read_text(encoding="utf-8"))
        self.checker.validate_prior_suite_transition(current, current)
        weakened = json.loads(json.dumps(current))
        weakened["achievements"].pop()
        with self.assertRaises(Exception):
            self.checker.validate_prior_suite_transition(current, weakened)
        self.assertTrue(self.checker.bootstrap_without_prior_suite_allowed(BOOTSTRAP_COMMIT))
        self.assertFalse(self.checker.bootstrap_without_prior_suite_allowed("1" * 40))

    def test_real_policy_and_two_skill_surface_remain_unchanged(self) -> None:
        from guardian_core.canonical import sha256_digest

        policy = REPOSITORY_ROOT / "plugins/design-system-guardian/policy/policy-v1.json"
        self.assertEqual(
            sha256_digest(json.loads(policy.read_text(encoding="utf-8"))),
            "3bf2913583cee2d791aed5093bc1df905b26dcdbb0c4d945f0ae5b2eddaaa99f",
        )
        skills = {
            path.parent.name
            for path in (REPOSITORY_ROOT / "plugins/design-system-guardian/skills").glob("*/SKILL.md")
        }
        self.assertEqual(skills, {"build-with-design-system", "audit-design-system"})


if __name__ == "__main__":
    unittest.main()
