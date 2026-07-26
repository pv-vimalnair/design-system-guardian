"""Immutable additive v0.3.3 cases for Guardian weighted Elo.

The module uses only Python's standard library and synthetic public fixtures.
Each case is isolated by the Elo worker and writes, when needed, only beneath a
temporary directory.
"""

from __future__ import annotations

import copy
import hashlib
import importlib
import json
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


PUBLIC_CATALOG_KEY = b"""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAjdA+63GIEQAoKEa7q4wVh4lpSKEEqQg+2DdDRSVanXc=
-----END PUBLIC KEY-----
"""


@contextmanager
def _target_import(root: Path) -> Iterator[None]:
    assert (root / "guardian_core").is_dir()
    sys.path.insert(0, str(root))
    try:
        yield
    finally:
        sys.path.remove(str(root))
        for name in tuple(sys.modules):
            if (
                name == "guardian_core"
                or name.startswith("guardian_core.")
                or name == "scripts.install_agent_skills"
            ):
                sys.modules.pop(name, None)


def _expect_error(error_type: type[BaseException], action: object) -> None:
    try:
        action()
    except error_type:
        return
    raise AssertionError("fail-closed operation was accepted")


def _figma_evidence(root: Path, adapter: object, canonical: object) -> tuple[dict, dict, dict]:
    project_binding = {
        "canonicalRoot": str(root.resolve()),
        "rootIdentity": "9" * 64,
        "gitCommit": None,
    }
    source_cut = {
        "figmaFiles": [
            {"fileKey": "synthetic-library", "version": "7"},
            {"fileKey": "synthetic-working-copy", "version": "11"},
        ],
        "catalogDigest": "c" * 64,
    }
    run_pin = {
        "schemaVersion": 1,
        "runId": "synthetic-figma-run",
        "profileId": "synthetic-public",
        "snapshotId": "d" * 64,
        "policyDigest": "a" * 64,
        "sourceCut": source_cut,
        "sourceState": "fresh",
        "projectBinding": project_binding,
    }
    working_instance = {
        "fileKey": "synthetic-working-copy",
        "nodeId": "20:4",
        "sourceVersion": "11",
        "nodeType": "INSTANCE",
        "canonicalAssetKey": "synthetic-component-key",
        "remote": True,
        "variant": "default",
        "properties": {"size": "medium"},
        "unapprovedOverrideFields": [],
    }
    snapshot = {
        "profileId": run_pin["profileId"],
        "snapshotId": run_pin["snapshotId"],
        "policyDigest": run_pin["policyDigest"],
        "sourceCut": source_cut,
        "sourceState": "fresh",
        "sourceAvailable": True,
        "sourceComplete": True,
        "tokens": {},
        "registry": {
            "components": [
                {
                    "identity": "component.synthetic.action",
                    "status": "approved",
                    "approved": True,
                    "sourceVersion": "7",
                    "figma": {
                        "fileKey": "synthetic-library",
                        "assetKey": "synthetic-component-key",
                        "published": True,
                    },
                    "variants": ["default"],
                    "properties": {"size": ["medium"]},
                    "workingFileInstances": [working_instance],
                }
            ],
            "icons": [],
        },
    }
    config = adapter.build_figma_adapter_config(
        run_pin=run_pin,
        verified_snapshot=snapshot,
    )
    observations = [
        {
            "kind": "asset",
            "category": "components",
            "nodeId": "20:4",
            "field": "instance",
            "identity": "component.synthetic.action",
            "figmaInstance": working_instance,
        },
        {
            "kind": "raw",
            "category": "colors",
            "nodeId": "20:5",
            "field": "fills.0",
            "valueDigest": "e" * 64,
            "inferredVariableKeys": [],
        },
    ]
    observations.sort(key=canonical.canonical_json_bytes)
    observation = {
        "schemaVersion": 1,
        "adapter": "figma",
        "adapterVersion": adapter.FIGMA_ADAPTER_VERSION,
        "status": "allowed",
        "binding": {
            "runId": run_pin["runId"],
            "profileId": run_pin["profileId"],
            "policyDigest": run_pin["policyDigest"],
            "snapshotId": run_pin["snapshotId"],
            "sourceCutDigest": canonical.sha256_digest(source_cut),
            "projectBindingDigest": canonical.sha256_digest(project_binding),
            "configDigest": config["configDigest"],
            "collectorDigest": config["collectorDigest"],
        },
        "source": {"state": "fresh", "available": True, "complete": True},
        "document": {
            "fileKey": "synthetic-working-copy",
            "sourceVersion": "11",
            "rootNodeIds": ["20:1"],
        },
        "analysis": {
            "method": "figma_plugin_api_readback",
            "complete": True,
            "assessedNodes": 2,
            "totalNodes": 2,
            "assessedFields": 2,
            "totalFields": 2,
        },
        "observations": observations,
    }
    return run_pin, snapshot, observation


def case_correctness_figma_bound_duplicates(root: Path) -> None:
    with _target_import(root):
        adapter = importlib.import_module("guardian_core.figma_adapter")
        canonical = importlib.import_module("guardian_core.canonical")
        run_pin, snapshot, observation = _figma_evidence(root, adapter, canonical)
        normalized = adapter.normalize_figma_observation(
            observation,
            run_pin=run_pin,
            verified_snapshot=snapshot,
        )
        assert normalized["categories"]["components"]["assessedItems"] == 1
        assert normalized["categories"]["components"]["status"] == "not_assessed"
        assert len(normalized["diagnostics"]) == 1
        diagnostic = normalized["diagnostics"][0]
        assert diagnostic["category"] == "colors"
        binding = diagnostic["evidence"]["binding"]
        assert binding["runId"] == run_pin["runId"]
        assert binding["projectBindingDigest"] == canonical.sha256_digest(
            run_pin["projectBinding"]
        )

        replayed_run = copy.deepcopy(run_pin)
        replayed_run["runId"] = "different-run"
        _expect_error(
            adapter.FigmaAdapterIntegrityError,
            lambda: adapter.normalize_figma_observation(
                observation,
                run_pin=replayed_run,
                verified_snapshot=snapshot,
            ),
        )
        replayed_project = copy.deepcopy(run_pin)
        replayed_project["projectBinding"]["rootIdentity"] = "8" * 64
        _expect_error(
            adapter.FigmaAdapterIntegrityError,
            lambda: adapter.normalize_figma_observation(
                observation,
                run_pin=replayed_project,
                verified_snapshot=snapshot,
            ),
        )


def case_reliability_ux_positive_downgrade(root: Path) -> None:
    with _target_import(root):
        ux = importlib.import_module("guardian_core.ux_evaluator")
        screen = "1" * 64
        flow = "2" * 64
        source_cut = {"figmaFiles": [{"fileKey": "synthetic", "version": "1"}]}
        observations = []
        for target, areas in (
            (screen, ux.REQUIRED_SCREEN_AREAS),
            (flow, ux.REQUIRED_FLOW_AREAS),
        ):
            for area in areas:
                observations.append(
                    {
                        "checkId": f"{target[:4]}-{area}",
                        "targetDigest": target,
                        "area": area,
                        "operator": "equals",
                        "observed": True,
                        "expected": True,
                        "evidenceDigest": hashlib.sha256(
                            f"{target}:{area}".encode("utf-8")
                        ).hexdigest(),
                    }
                )
        target = {"flowDigest": flow, "screenDigests": [screen]}
        evaluation = ux.evaluate_final_flow(
            target=target,
            observations=observations,
            source_cut=source_cut,
        )
        assert evaluation["status"] == "allowed"
        assert evaluation["complete"] is True
        assert evaluation["canAuthorizeProduction"] is False
        projected = ux.audit_checks_from_evaluation(
            evaluation,
            target=target,
            source_cut=source_cut,
        )
        assert projected
        assert all(item["status"] == "not_assessed" for item in projected)
        assert all(item["evidence"]["evidenceDigest"] is None for item in projected)


def case_safety_private_figma_evidence(root: Path) -> None:
    with _target_import(root):
        cli = importlib.import_module("guardian_core.cli")
        assert hasattr(cli, "_private_adapter_output")
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            home = base / "guardian-home"
            home.mkdir()
            inside = home / "private" / "figma-config.json"
            assert cli._private_adapter_output(home, str(inside)) == inside.absolute()
            _expect_error(
                ValueError,
                lambda: cli._private_adapter_output(
                    home, str(base / "public-figma-config.json")
                ),
            )

        adapter = importlib.import_module("guardian_core.figma_adapter")
        assert adapter._FIGMA_COLLECTOR_CONTRACT["productCopyCollected"] is False
        collector = (root / "adapters" / "figma" / "collector.js").read_text(
            encoding="utf-8"
        )
        properties = collector.split("function componentProperties", 1)[1].split(
            "function overrideFields", 1
        )[0]
        text_guard = 'if (property.type === "TEXT") continue;'
        value_read = "const value = property.value;"
        assert text_guard in properties and value_read in properties
        assert properties.index(text_guard) < properties.index(value_read)
        assert 'if (field === "characters") continue;' in collector


def case_usability_permission_bound_onboarding(root: Path) -> None:
    with _target_import(root):
        onboarding = importlib.import_module("guardian_core.onboarding")
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "catalog-authority.pem"
            key_path.write_bytes(PUBLIC_CATALOG_KEY)
            profile = {
                "schemaVersion": 1,
                "profileId": "synthetic-public",
                "displayName": "Synthetic Public",
                "figma": {
                    "allowlistedLibraryFiles": [
                        {"fileKey": "synthetic-library", "name": "Synthetic Library"}
                    ]
                },
                "adapters": {"flutter": {"enabled": False}},
            }
            catalog = {
                "schemaVersion": 1,
                "profileId": "synthetic-public",
                "fixture": "public-synthetic",
            }
            preview = onboarding.prepare_onboarding_permission(
                catalog_authority_public_key=key_path,
                profile_document=profile,
                catalog_document=catalog,
            )
            assert preview["status"] == "permission_required"
            assert preview["permissionRequired"] is True
            assert preview["localChangesPerformed"] is False
            bundle = {
                "schemaVersion": 1,
                "catalogAuthorityPublicKey": str(key_path.resolve()),
                "profile": profile,
                "catalog": catalog,
                "permission": {
                    **preview["permissionBinding"],
                    "granted": True,
                },
            }
            validated = onboarding.validate_onboarding_bundle(bundle)
            assert validated["permission"]["granted"] is True

            denied = copy.deepcopy(bundle)
            denied["permission"]["granted"] = False
            _expect_error(
                onboarding.OnboardingError,
                lambda: onboarding.validate_onboarding_bundle(denied),
            )
            mismatched = copy.deepcopy(bundle)
            mismatched["permission"]["figmaAuthorityDigest"] = "0" * 64
            _expect_error(
                onboarding.OnboardingError,
                lambda: onboarding.validate_onboarding_bundle(mismatched),
            )


def case_portability_permissioned_runtime_bootstrap(root: Path) -> None:
    with _target_import(root):
        installer = importlib.import_module("scripts.install_agent_skills")
        assert hasattr(installer, "provision_runtime")
        expected_pins = {
            "cffi": "2.1.0",
            "cryptography": "46.0.7",
            "pycparser": "3.0",
        }
        assert installer.REQUIRED_RUNTIME_PINS == expected_pins
        assert (
            installer.load_pinned_requirements(root / "requirements.txt")
            == expected_pins
        )
        help_text = installer.parser().format_help()
        assert "--bootstrap-runtime" in help_text
        assert "explicit permission" in help_text

        base_arguments = [
            "--target-root",
            str((root / "synthetic-unused-skills").resolve()),
            "--python",
            str(Path(sys.executable).resolve()),
        ]
        assert installer.parser().parse_args(base_arguments).bootstrap_runtime is False
        assert (
            installer.parser()
            .parse_args([*base_arguments, "--bootstrap-runtime"])
            .bootstrap_runtime
            is True
        )

        commands = []

        def fake_runner(command: list[str], **_: object) -> subprocess.CompletedProcess:
            arguments = [str(value) for value in command]
            commands.append(arguments)
            if arguments[1:5] == ["-I", "-m", "venv", "--copies"]:
                stage_python = installer.runtime_python_path(Path(arguments[-1]))
                stage_python.parent.mkdir(parents=True, exist_ok=True)
                stage_python.write_bytes(b"synthetic isolated python")
            return subprocess.CompletedProcess(
                arguments,
                0,
                stdout=b"",
                stderr=b"",
            )

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            project_root = base / "project-repository"
            target = project_root / ".agents" / "skills"
            runtime_base = base / "guardian-local" / "runtimes"
            assert not target.exists()
            installer.install(
                target,
                Path(sys.executable).resolve(),
                False,
                bootstrap_runtime=True,
                runtime_runner=fake_runner,
                runtime_base=runtime_base,
            )
            runtime_roots = list(runtime_base.iterdir())
            assert len(runtime_roots) == 1
            runtime_root = runtime_roots[0]
            assert runtime_root.resolve().is_relative_to(runtime_base.resolve())
            assert not runtime_root.resolve().is_relative_to(project_root.resolve())
            assert {path.name for path in target.parent.iterdir()} == {"skills"}
            runtime_python = installer.runtime_python_path(runtime_root)
            assert all(
                not installer._path_is_redirect(path)
                for path in (runtime_base, runtime_root, runtime_python)
            )
            marker = json.loads(
                (runtime_root / installer.RUNTIME_MARKER_NAME).read_text(
                    encoding="utf-8"
                )
            )
            assert marker["owner"] == "design-system-guardian"
            assert Path(marker["targetRoot"]).resolve() == target.resolve()
            assert marker["requirements"]["pins"] == expected_pins
            for name in installer.SKILL_NAMES:
                binding = json.loads(
                    (
                        target
                        / name
                        / "references"
                        / "guardian-install.json"
                    ).read_text(encoding="utf-8")
                )
                assert Path(binding["python"]["path"]).resolve() == runtime_python.resolve()

        pip_calls = [
            command for command in commands if command[1:4] == ["-I", "-m", "pip"]
        ]
        assert len(pip_calls) == 1
        assert pip_calls[0][4:] == [
            "--isolated",
            "--disable-pip-version-check",
            "install",
            "--no-input",
            "--no-deps",
            "--requirement",
            str((root / "requirements.txt").resolve()),
        ]
        assert all("==" not in argument for argument in pip_calls[0])
        verification_calls = [
            command
            for command in commands
            if command[1:3] == ["-I", "-c"]
            and installer.RUNTIME_VERIFICATION == command[3]
        ]
        assert len(verification_calls) >= 2
        for command in verification_calls:
            assert json.loads(command[4]) == expected_pins
            assert set(json.loads(command[5])) == set(installer.RUNTIME_IMPORTS)
            assert json.loads(command[6]) is True
            assert tuple(json.loads(command[7])) == tuple(
                installer.BOOTSTRAP_DISTRIBUTIONS
            )
