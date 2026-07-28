from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tests.test_publication_privacy_dsg014 import commit, make_repo, write


class PersonalSelectionPublicationPrivacyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from tests.test_publication_privacy_dsg014 import checker_module

        cls.checker = checker_module()

    def test_personal_selection_identifiers_are_compared_in_current_and_history(self) -> None:
        marker = "figma-private-library-7e43c9f8"
        local_document = {
            "runId": "private-run-7e43c9f8",
            "selectionDigest": "a" * 64,
            "targetFigmaFile": {
                "fileKey": "figma-private-working-7e43c9f8",
                "version": "private-version-17",
                "name": "Private client working file",
            },
            "selectedLibraryFileKeys": [marker],
            "excludedLibraryFileKeys": ["figma-private-excluded-7e43c9f8"],
        }
        for history in (False, True):
            with self.subTest(history=history), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                repository = make_repo(base)
                home = base / "local-home"
                write(
                    home,
                    "personal/task-selections/private-run.json",
                    json.dumps(local_document, sort_keys=True) + "\n",
                )
                relative = "plugins/design-system-guardian/docs/selection-fixture.json"
                write(
                    repository,
                    relative,
                    json.dumps({"selectedLibraryFileKeys": [marker]}) + "\n",
                )
                commit(repository, "synthetic selection fixture")
                if history:
                    (repository / relative).unlink()
                    commit(repository, "remove synthetic selection fixture")

                result = self.checker.check_public_release(
                    repository,
                    history=history,
                    local_home=home,
                    require_clean=True,
                    check_prior_suite=False,
                )

                self.assertFalse(result.ok)
                self.assertIn("local_identifier_match", result.codes)
                self.assertNotIn(marker, self.checker.render_result(result))

    def test_personal_runtime_paths_and_documents_are_structurally_blocked(self) -> None:
        payload = json.dumps(
            {
                "runId": "synthetic-run",
                "selectionDigest": "b" * 64,
                "targetFigmaFile": {
                    "fileKey": "synthetic-working-file",
                    "version": "synthetic-version",
                },
            }
        ) + "\n"
        with tempfile.TemporaryDirectory() as directory:
            repository = make_repo(Path(directory))
            write(
                repository,
                "plugins/design-system-guardian/personal/task-selections/run.json",
                payload,
            )
            commit(repository)
            result = self.checker.check_public_release(
                repository,
                history=False,
                local_home=None,
                require_clean=True,
                check_prior_suite=False,
            )
            self.assertFalse(result.ok)
            self.assertIn("runtime_state", result.codes)

        self.assertTrue(
            self.checker._runtime_json(
                payload.encode("utf-8"),
                "plugins/design-system-guardian/docs/selection.json",
            )
        )

    def test_raw_personal_discovery_is_blocked_in_current_and_history(self) -> None:
        discovery = {
            "schemaVersion": 1,
            "projectRoot": "C:\\workspaces\\private-client\\product",
            "targetFigmaFile": {
                "fileKey": "private-working-file",
                "version": "private-working-version",
                "name": "Private client checkout",
            },
            "discoveryComplete": True,
            "candidates": [
                {
                    "fileKey": "private-library-file",
                    "version": "private-library-version",
                    "name": "Private design system",
                    "published": True,
                    "decision": "use",
                }
            ],
            "adapters": {"figma": {"enabled": True}},
            "catalog": {"sourceAvailable": True, "sourceComplete": True},
            "catalogReadback": {
                "method": "figma_plugin_api_catalog_readback",
                "assets": [{"identity": "private-component"}],
            },
        }
        relative = "plugins/design-system-guardian/docs/discovery.json"
        for history in (False, True):
            with self.subTest(history=history), tempfile.TemporaryDirectory() as directory:
                repository = make_repo(Path(directory))
                write(repository, relative, json.dumps(discovery) + "\n")
                commit(repository, "add raw personal discovery")
                if history:
                    (repository / relative).unlink()
                    commit(repository, "remove raw personal discovery")

                result = self.checker.check_public_release(
                    repository,
                    history=history,
                    local_home=None,
                    require_clean=True,
                    check_prior_suite=False,
                )

                self.assertFalse(result.ok)
                self.assertIn(
                    "history_violation" if history else "runtime_state",
                    result.codes,
                )

    def test_personal_discovery_contracts_and_synthetic_fixtures_remain_public(self) -> None:
        discovery_shape = {
            "projectRoot": "C:\\Users\\fixture\\project",
            "targetFigmaFile": {},
            "discoveryComplete": True,
            "candidates": [],
            "adapters": {},
            "catalog": {},
            "catalogReadback": {},
        }
        payload = json.dumps(discovery_shape).encode("utf-8")
        for relative in (
            "plugins/design-system-guardian/schemas/discovery.schema.json",
            "plugins/design-system-guardian/tests/discovery-fixture.json",
            "plugins/design-system-guardian/benchmarks/discovery-fixture.json",
        ):
            with self.subTest(relative=relative):
                self.assertFalse(self.checker._runtime_json(payload, relative))

        wrapped_fixture = json.dumps(
            {"fixtureKind": "synthetic", "example": discovery_shape}
        ).encode("utf-8")
        self.assertFalse(
            self.checker._runtime_json(
                wrapped_fixture,
                "plugins/design-system-guardian/docs/discovery-example.json",
            )
        )

    def test_exact_generic_launcher_backup_is_not_company_data(self) -> None:
        launcher = "#!/usr/bin/env python3\n# synthetic public launcher\n"
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = make_repo(base)
            home = base / "local-home"
            write(
                repository,
                "plugins/design-system-guardian/scripts/generic_skill_launcher.py",
                launcher,
            )
            commit(repository, "add public launcher")
            write(
                home,
                "install-backups/backup/build-with-design-system/scripts/guardian.py",
                launcher,
            )

            result = self.checker.check_public_release(
                repository,
                history=False,
                local_home=home,
                require_clean=True,
                check_prior_suite=False,
            )
            self.assertTrue(result.ok)

            write(home, "personal/private-copy.txt", launcher)
            result = self.checker.check_public_release(
                repository, history=False, local_home=home, require_clean=True, check_prior_suite=False
            )
            self.assertFalse(result.ok)
            self.assertIn("local_file_match", result.codes)

    def test_selection_array_and_context_names_are_semantic_identifiers(self) -> None:
        document = {
            "targetFigmaFile": {
                "fileKey": "synthetic-working-file",
                "version": "synthetic-version",
                "name": "Synthetic working file",
            },
            "candidates": [
                {
                    "fileKey": "synthetic-library-file",
                    "version": "synthetic-library-version",
                    "name": "Synthetic library",
                }
            ],
            "selectedLibraryFileKeys": ["synthetic-library-file"],
            "excludedLibraryFileKeys": ["synthetic-excluded-file"],
        }
        identifiers = set(self.checker._walk_identifiers(document))
        self.assertTrue(
            {
                "synthetic-working-file",
                "Synthetic working file",
                "synthetic-library-file",
                "Synthetic library",
                "synthetic-excluded-file",
            }.issubset(identifiers)
        )


if __name__ == "__main__":
    unittest.main()
