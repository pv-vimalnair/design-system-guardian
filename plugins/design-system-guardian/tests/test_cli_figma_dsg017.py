from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.catalog_authority_test_support import (
    DEFAULT_TEST_CATALOG_AUTHORITY,
    attest_catalog,
)
from tests.test_cli_lifecycle_dsg003 import file_state, invoke, write_canonical
from tests.test_profile_snapshot import NOW, sample_catalog, sample_profile


WORKING_FILE = "figma-working-copy"
WORKING_VERSION = "copy-17"


def working_instance() -> dict:
    return {
        "fileKey": WORKING_FILE,
        "nodeId": "220:41",
        "sourceVersion": WORKING_VERSION,
        "nodeType": "INSTANCE",
        "canonicalAssetKey": "component-key-primary",
        "remote": True,
        "variant": "loading",
        "properties": {"size": "large"},
        "unapprovedOverrideFields": [],
    }


def provision_figma_run(home: Path, root: Path, *, run_id: str) -> tuple[dict, dict, Path]:
    from guardian_core.policy import EXPECTED_POLICY_SHA256, install_policy_anchor
    from guardian_core.preflight import preflight_snapshot
    from guardian_core.profile import install_profile
    from guardian_core.snapshot import ingest_snapshot

    home.mkdir()
    public_key = root / f"{run_id}-catalog-authority.pem"
    public_key.write_bytes(DEFAULT_TEST_CATALOG_AUTHORITY.public_pem)
    install_policy_anchor(home, catalog_authority_public_key=public_key)

    profile = sample_profile()
    profile["figma"]["allowlistedWorkingFiles"] = [
        {"fileKey": WORKING_FILE, "name": "Approved working copy"}
    ]
    install_profile(home, profile)

    catalog = sample_catalog()
    catalog["sourceCut"]["figmaFiles"].append(
        {"fileKey": WORKING_FILE, "version": WORKING_VERSION}
    )
    catalog["tokens"]["color"]["action"]["primary"]["$extensions"] = {
        "guardian.figma": {
            "bindingType": "variable",
            "fileKey": "figma-brand",
            "sourceVersion": "42",
            "key": "variable-key-primary",
            "collectionKey": "collection-key-color",
            "resolvedType": "COLOR",
        }
    }
    catalog["tokens"]["space"]["200"]["$extensions"] = {
        "guardian.figma": {
            "bindingType": "variable",
            "fileKey": "figma-brand",
            "sourceVersion": "42",
            "key": "variable-key-space-200",
            "collectionKey": "collection-key-space",
            "resolvedType": "FLOAT",
        }
    }
    for assets in catalog["registry"].values():
        for asset in assets:
            asset["codeMappings"] = []
    catalog["registry"]["components"][0]["workingFileInstances"] = [
        working_instance()
    ]
    signed = attest_catalog(catalog, profile, sequence=1, issued_at=NOW)
    with patch("guardian_core.snapshot._utc_now", return_value=NOW):
        snapshot = ingest_snapshot(home, profile, signed)

    project = root / f"{run_id}-workspace"
    project.mkdir()
    (project / "readme.txt").write_text("local evidence workspace\n", encoding="utf-8")
    with patch("guardian_core.preflight._utc_now", return_value=NOW):
        pin = preflight_snapshot(
            home,
            profile_id=profile["profileId"],
            run_id=run_id,
            policy_digest=EXPECTED_POLICY_SHA256,
            project_root=project,
        )["pin"]
    return pin, snapshot, project


def figma_observation(pin: dict, snapshot: dict) -> dict:
    from guardian_core.canonical import canonical_json_bytes, sha256_digest
    from guardian_core.figma_adapter import build_figma_adapter_config

    config = build_figma_adapter_config(
        run_pin=pin,
        verified_snapshot=snapshot,
    )
    observations = sorted(
        [
            {
                "kind": "variable",
                "category": "colors",
                "nodeId": "100:1",
                "field": "fills.0.color",
                "identity": "color.action.primary",
                "variableKey": "variable-key-primary",
                "collectionKey": "collection-key-color",
                "resolvedType": "COLOR",
            },
            {
                "kind": "variable",
                "category": "spacing",
                "nodeId": "100:2",
                "field": "itemSpacing",
                "identity": "space.200",
                "variableKey": "variable-key-space-200",
                "collectionKey": "collection-key-space",
                "resolvedType": "FLOAT",
            },
            {
                "kind": "asset",
                "category": "components",
                "nodeId": "220:41",
                "field": "instance",
                "identity": "button.primary",
                "figmaInstance": working_instance(),
            },
        ],
        key=canonical_json_bytes,
    )
    return {
        "schemaVersion": 1,
        "adapter": "figma",
        "adapterVersion": "0.1.0",
        "status": "allowed",
        "binding": {
            "runId": pin["runId"],
            "profileId": pin["profileId"],
            "policyDigest": pin["policyDigest"],
            "snapshotId": pin["snapshotId"],
            "sourceCutDigest": config["sourceCutDigest"],
            "projectBindingDigest": sha256_digest(pin["projectBinding"]),
            "configDigest": config["configDigest"],
            "collectorDigest": config["collectorDigest"],
        },
        "source": {"state": "fresh", "available": True, "complete": True},
        "document": {
            "fileKey": WORKING_FILE,
            "sourceVersion": WORKING_VERSION,
            "rootNodeIds": ["100:0"],
        },
        "analysis": {
            "method": "figma_plugin_api_readback",
            "complete": True,
            "assessedNodes": 3,
            "totalNodes": 3,
            "assessedFields": 3,
            "totalFields": 3,
        },
        "observations": observations,
    }


def ux_evidence(target: dict | None = None) -> dict:
    from guardian_core.ux_evaluator import REQUIRED_FLOW_AREAS, REQUIRED_SCREEN_AREAS

    if target is None:
        target = {"flowDigest": "2" * 64, "screenDigests": ["1" * 64]}
    screen = target["screenDigests"][0]
    flow = target["flowDigest"]

    def item(target: str, area: str) -> dict:
        return {
            "checkId": f"{target[:8]}-{area}",
            "targetDigest": target,
            "area": area,
            "operator": "equals",
            "observed": True,
            "expected": True,
            "evidenceDigest": "3" * 64,
        }

    return {
        "target": target,
        "observations": [
            *(item(screen, area) for area in REQUIRED_SCREEN_AREAS),
            *(item(flow, area) for area in REQUIRED_FLOW_AREAS),
        ],
    }


class FigmaLifecycleCliTest(unittest.TestCase):
    def test_figma_config_checkpoint_audit_and_finalize_share_one_sealed_run(self) -> None:
        from guardian_core.canonical import read_canonical_json
        from guardian_core.run_artifacts import read_run_artifact

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            pin, snapshot, project = provision_figma_run(
                home, root, run_id="run-figma-clean"
            )
            from guardian_core.figma_adapter import expected_figma_ux_target

            observation = figma_observation(pin, snapshot)
            target = expected_figma_ux_target(
                observation, run_pin=pin, verified_snapshot=snapshot
            )
            before = file_state(project)

            config_path = home / "private" / "figma-config.json"
            code, configured = invoke(
                home,
                [
                    "adapter",
                    "figma",
                    "config",
                    "--profile",
                    pin["profileId"],
                    "--run-id",
                    pin["runId"],
                    "--output",
                    str(config_path),
                ],
            )
            self.assertEqual(code, 0)
            self.assertEqual(configured["adapter"], "figma")
            self.assertEqual(read_canonical_json(config_path)["runId"], pin["runId"])
            self.assertEqual(read_canonical_json(config_path)["configDigest"], configured["configDigest"])

            screen_target = {"screenDigest": target["screenDigests"][0]}
            checkpoint = ux_evidence(target)
            checkpoint_path = root / "ux-checkpoint.json"
            write_canonical(
                checkpoint_path,
                {
                    "schemaVersion": 1,
                    "target": screen_target,
                    "observations": [
                        item
                        for item in checkpoint["observations"]
                        if item["targetDigest"] == screen_target["screenDigest"]
                    ],
                },
            )
            code, checkpoint_result = invoke(
                home,
                [
                    "ux",
                    "checkpoint",
                    "--profile",
                    pin["profileId"],
                    "--run-id",
                    pin["runId"],
                    "--input",
                    str(checkpoint_path),
                ],
            )
            self.assertEqual(code, 0)
            self.assertFalse(checkpoint_result["canAuthorizeProduction"])

            request_path = root / "figma-audit.json"
            write_canonical(
                request_path,
                {
                    "schemaVersion": 2,
                    "adapter": "figma",
                    "projectRoot": str(project),
                    "resolutions": [],
                    "uxEvidence": ux_evidence(target),
                    "adapterEvidence": observation,
                },
            )
            code, audit = invoke(
                home,
                [
                    "audit",
                    "--profile",
                    pin["profileId"],
                    "--run-id",
                    pin["runId"],
                    "--input",
                    str(request_path),
                ],
            )
            self.assertEqual(code, 4)
            self.assertEqual(audit["coverage"]["adapter"], "figma")
            self.assertEqual(audit["designSystemLane"]["status"], "not_assessed")
            self.assertEqual(audit["uxAccessibilityLane"]["status"], "not_assessed")
            self.assertEqual(file_state(project), before)
            attestation = read_run_artifact(
                home,
                profile_id=pin["profileId"],
                run_id=pin["runId"],
                artifact_type="analysis-attestation",
            )["payload"]
            self.assertIn("uxEvaluationDigest", attestation)

            audit_path = root / "figma-audit-result.json"
            write_canonical(audit_path, audit)
            with patch("guardian_core.finalize._utc_now", return_value=NOW):
                code, finalized = invoke(
                    home,
                    [
                        "finalize",
                        "--profile",
                        pin["profileId"],
                        "--run-id",
                        pin["runId"],
                        "--audit-result",
                        str(audit_path),
                    ],
                )
            self.assertEqual(code, 4)
            self.assertFalse(finalized["productionReady"])
            report = (home / finalized["artifactPaths"]["readable-report"]).read_text(
                encoding="utf-8"
            )
            self.assertIn("Bound local evidence workspace", report)
            self.assertIn("Screen checks", report)
            self.assertIn("Final-flow checks", report)

    def test_raw_equal_value_and_detached_duplicate_fail_without_substitution(self) -> None:
        from guardian_core.canonical import canonical_json_bytes
        from guardian_core.figma_adapter import expected_figma_ux_target

        mutations = ("raw", "detached")
        for label in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                home = root / "guardian-home"
                pin, snapshot, project = provision_figma_run(
                    home, root, run_id=f"run-figma-{label}"
                )
                observation = figma_observation(pin, snapshot)
                if label == "raw":
                    target = next(
                        item for item in observation["observations"] if item["category"] == "colors"
                    )
                    observation["observations"].remove(target)
                    observation["observations"].append(
                        {
                            "kind": "raw",
                            "category": "colors",
                            "nodeId": target["nodeId"],
                            "field": target["field"],
                            "valueDigest": "4" * 64,
                            "inferredVariableKeys": ["variable-key-primary"],
                        }
                    )
                else:
                    target = next(
                        item for item in observation["observations"] if item["kind"] == "asset"
                    )
                    target["figmaInstance"]["nodeType"] = "FRAME"
                observation["observations"] = sorted(
                    observation["observations"], key=canonical_json_bytes
                )
                request_path = root / "audit.json"
                write_canonical(
                    request_path,
                    {
                        "schemaVersion": 2,
                        "adapter": "figma",
                        "projectRoot": str(project),
                        "resolutions": [],
                        "uxEvidence": ux_evidence(
                            expected_figma_ux_target(
                                observation, run_pin=pin, verified_snapshot=snapshot
                            )
                        ),
                        "adapterEvidence": observation,
                    },
                )
                code, audit = invoke(
                    home,
                    [
                        "audit",
                        "--profile",
                        pin["profileId"],
                        "--run-id",
                        pin["runId"],
                        "--input",
                        str(request_path),
                    ],
                )
                self.assertEqual(code, 1)
                self.assertEqual(audit["designSystemLane"]["status"], "conflict")
                self.assertEqual(len(audit["designSystemLane"]["violations"]), 1)
                self.assertNotIn("replacement", str(audit).lower())

    def test_figma_observation_cannot_replay_across_run_and_project(self) -> None:
        from guardian_core.adapter_dispatch import build_figma_runner_evidence
        from guardian_core.figma_adapter import FigmaAdapterIntegrityError
        from guardian_core.policy import EXPECTED_POLICY_SHA256
        from guardian_core.preflight import preflight_snapshot

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            pin_a, snapshot, _ = provision_figma_run(home, root, run_id="run-a")
            observation_a = figma_observation(pin_a, snapshot)
            project_b = root / "different-project"
            project_b.mkdir()
            (project_b / "different.txt").write_text(
                "different local project\n",
                encoding="utf-8",
            )
            with patch("guardian_core.preflight._utc_now", return_value=NOW):
                pin_b = preflight_snapshot(
                    home,
                    profile_id=pin_a["profileId"],
                    run_id="run-b",
                    policy_digest=EXPECTED_POLICY_SHA256,
                    project_root=project_b,
                )["pin"]

            with self.assertRaises(FigmaAdapterIntegrityError):
                build_figma_runner_evidence(
                    observation=observation_a,
                    run_pin=pin_b,
                    verified_snapshot=snapshot,
                    project_binding=pin_b["projectBinding"],
                )


if __name__ == "__main__":
    unittest.main()
