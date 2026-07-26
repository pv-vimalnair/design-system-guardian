from __future__ import annotations

import copy
import json
import subprocess
import unittest
from pathlib import Path


CATEGORIES = (
    "components",
    "icons",
    "colors",
    "typography",
    "spacing",
    "radii",
    "effects",
    "motion",
)
from guardian_core.figma_adapter import collector_digest


COLLECTOR_DIGEST = collector_digest()
POLICY_DIGEST = "a" * 64
SNAPSHOT_ID = "d" * 64
LIBRARY_FILE = "figma-brand"
LIBRARY_VERSION = "42"
WORKING_FILE = "figma-working-copy"
WORKING_VERSION = "copy-17"
PROJECT_ROOT = str((Path.cwd() / "guardian-fixture" / "project").resolve())
OTHER_PROJECT_ROOT = str(
    (Path.cwd() / "guardian-fixture" / "another-project").resolve()
)


def source_cut() -> dict:
    return {
        "figmaFiles": [
            {"fileKey": LIBRARY_FILE, "version": LIBRARY_VERSION},
            {"fileKey": WORKING_FILE, "version": WORKING_VERSION},
        ],
        "catalogDigest": "b" * 64,
        "codeConnectParseDigest": None,
        "repositoryCommit": None,
        "componentCatalogBuild": None,
    }


def run_pin(*, state: str = "fresh") -> dict:
    return {
        "schemaVersion": 1,
        "runId": "figma-run-1",
        "profileId": "example-company",
        "snapshotId": SNAPSHOT_ID,
        "policyDigest": POLICY_DIGEST,
        "sourceCut": source_cut(),
        "sourceState": state,
        "projectBinding": {
            "canonicalRoot": PROJECT_ROOT,
            "rootIdentity": "9" * 64,
            "gitCommit": None,
        },
    }


def token(
    identity: str,
    token_type: str,
    figma_binding: dict,
) -> dict:
    return {
        "identity": identity,
        "type": token_type,
        "value": "fixture-value",
        "alias": None,
        "deprecated": False,
        "deprecationReason": None,
        "description": None,
        "extensions": {"guardian.figma": figma_binding},
        "sourcePath": "#/tokens/" + identity.replace(".", "/"),
        "approved": True,
        "provenance": {
            "approval": "explicit",
            "source": LIBRARY_FILE,
            "sourceVersion": LIBRARY_VERSION,
            "published": True,
        },
    }


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


def asset() -> dict:
    return {
        "kind": "component",
        "identity": "button.primary",
        "status": "approved",
        "approved": True,
        "deprecated": False,
        "sourceVersion": LIBRARY_VERSION,
        "figma": {
            "fileKey": LIBRARY_FILE,
            "nodeId": "10:20",
            "assetKey": "component-key-primary",
            "published": True,
        },
        "variants": ["loading"],
        "properties": {"size": ["large"]},
        "codeMappings": [],
        "provenance": {
            "fileKey": LIBRARY_FILE,
            "nodeId": "10:20",
            "assetKey": "component-key-primary",
            "published": True,
            "sourceVersion": LIBRARY_VERSION,
        },
        "workingFileInstances": [working_instance()],
    }


def snapshot(*, state: str = "fresh", available: bool = True, complete: bool = True) -> dict:
    return {
        "profileId": "example-company",
        "snapshotId": SNAPSHOT_ID,
        "policyDigest": POLICY_DIGEST,
        "sourceCut": source_cut(),
        "sourceState": state,
        "sourceAvailable": available,
        "sourceComplete": complete,
        "tokens": {
            "color.brand.primary": token(
                "color.brand.primary",
                "color",
                {
                    "bindingType": "variable",
                    "fileKey": LIBRARY_FILE,
                    "sourceVersion": LIBRARY_VERSION,
                    "key": "variable-key-primary",
                    "collectionKey": "collection-key-color",
                    "resolvedType": "COLOR",
                },
            ),
            "text.body": token(
                "text.body",
                "typography",
                {
                    "bindingType": "style",
                    "fileKey": LIBRARY_FILE,
                    "sourceVersion": LIBRARY_VERSION,
                    "key": "style-key-body",
                    "styleType": "text",
                },
            ),
        },
        "registry": {"components": [asset()], "icons": []},
    }


def observations() -> list[dict]:
    from guardian_core.canonical import canonical_json_bytes

    values = [
        {
            "kind": "variable",
            "category": "colors",
            "nodeId": "100:1",
            "field": "fills.0.color",
            "identity": "color.brand.primary",
            "variableKey": "variable-key-primary",
            "collectionKey": "collection-key-color",
            "resolvedType": "COLOR",
        },
        {
            "kind": "style",
            "category": "typography",
            "nodeId": "100:2",
            "field": "textStyleId",
            "identity": "text.body",
            "styleKey": "style-key-body",
            "styleType": "text",
            "range": None,
        },
        {
            "kind": "asset",
            "category": "components",
            "nodeId": "220:41",
            "field": "instance",
            "identity": "button.primary",
            "figmaInstance": working_instance(),
        },
    ]
    return sorted(values, key=canonical_json_bytes)


def clean_observation(*, state: str = "fresh", status: str = "allowed") -> dict:
    from guardian_core.canonical import sha256_digest
    from guardian_core.figma_adapter import build_figma_adapter_config

    pin = run_pin(state=state)
    snap = snapshot(state=state)
    config = build_figma_adapter_config(
        run_pin=pin,
        verified_snapshot=snap,
        collector_digest=COLLECTOR_DIGEST,
    )
    values = observations()
    return {
        "schemaVersion": 1,
        "adapter": "figma",
        "adapterVersion": "0.1.0",
        "status": status,
        "binding": {
            "runId": pin["runId"],
            "profileId": pin["profileId"],
            "policyDigest": pin["policyDigest"],
            "snapshotId": pin["snapshotId"],
            "sourceCutDigest": sha256_digest(pin["sourceCut"]),
            "projectBindingDigest": sha256_digest(pin["projectBinding"]),
            "configDigest": config["configDigest"],
            "collectorDigest": COLLECTOR_DIGEST,
        },
        "source": {
            "state": state,
            "available": state != "source_unavailable",
            "complete": state not in {"source_incomplete", "source_unavailable"},
        },
        "document": {
            "fileKey": WORKING_FILE,
            "sourceVersion": WORKING_VERSION,
            "rootNodeIds": ["100:0"],
        },
        "analysis": {
            "method": "figma_plugin_api_readback",
            "complete": status == "allowed",
            "assessedNodes": 3 if status == "allowed" else 0,
            "totalNodes": 3,
            "assessedFields": len(values) if status == "allowed" else 0,
            "totalFields": len(values),
        },
        "observations": values if status == "allowed" else [],
    }


class FigmaAdapterTest(unittest.TestCase):
    def normalize(self, value: dict, *, pin: dict | None = None, snap: dict | None = None):
        from guardian_core.figma_adapter import normalize_figma_observation

        return normalize_figma_observation(
            value,
            run_pin=pin or run_pin(),
            verified_snapshot=snap or snapshot(),
            collector_digest=COLLECTOR_DIGEST,
        )

    def test_exact_bound_variable_style_and_signed_duplicate_instance_pass(self) -> None:
        normalized = self.normalize(clean_observation())

        self.assertEqual(normalized["adapter"], "figma")
        self.assertTrue(normalized["supported"])
        self.assertEqual(normalized["assessedFiles"], 3)
        self.assertEqual(normalized["totalFiles"], 3)
        self.assertEqual(normalized["diagnostics"], [])
        self.assertEqual(normalized["categories"]["colors"]["status"], "not_assessed")
        self.assertTrue(
            all(
                item["status"] == "not_assessed"
                for item in normalized["categories"].values()
            )
        )
        self.assertEqual(normalized["categories"]["typography"]["assessedItems"], 1)
        self.assertEqual(normalized["categories"]["components"]["totalItems"], 1)

    def test_only_the_shipped_collector_contract_can_bind_evidence(self) -> None:
        from guardian_core.canonical import sha256_digest
        from guardian_core.figma_adapter import (
            FigmaAdapterIntegrityError,
            build_figma_adapter_config,
            collector_digest,
        )

        config = build_figma_adapter_config(
            run_pin=run_pin(),
            verified_snapshot=snapshot(),
        )
        self.assertEqual(config["collectorDigest"], collector_digest())
        self.assertEqual(config["runId"], run_pin()["runId"])
        self.assertEqual(
            config["projectBindingDigest"],
            sha256_digest(run_pin()["projectBinding"]),
        )
        with self.assertRaises(FigmaAdapterIntegrityError):
            build_figma_adapter_config(
                run_pin=run_pin(),
                verified_snapshot=snapshot(),
                collector_digest="c" * 64,
            )

    def test_observation_cannot_replay_across_run_or_project(self) -> None:
        from guardian_core.figma_adapter import FigmaAdapterIntegrityError

        for label, mutate in (
            ("run", lambda pin: pin.update(runId="figma-run-2")),
            (
                "project",
                lambda pin: pin["projectBinding"].update(
                    canonicalRoot=OTHER_PROJECT_ROOT,
                    rootIdentity="8" * 64,
                ),
            ),
        ):
            with self.subTest(label=label):
                pin = run_pin()
                mutate(pin)
                with self.assertRaises(FigmaAdapterIntegrityError):
                    self.normalize(clean_observation(), pin=pin)

    def test_expected_ux_target_is_run_document_and_root_bound(self) -> None:
        from guardian_core.canonical import sha256_digest
        from guardian_core.figma_adapter import (
            build_figma_adapter_config,
            expected_figma_ux_target,
        )

        value = clean_observation()
        value["document"]["rootNodeIds"] = ["100:0", "200:0"]
        config = build_figma_adapter_config(
            run_pin=run_pin(),
            verified_snapshot=snapshot(),
        )
        document = {
            "fileKey": WORKING_FILE,
            "sourceVersion": WORKING_VERSION,
        }
        expected_screens = [
            sha256_digest(
                {
                    "kind": "figma_screen",
                    "runId": config["runId"],
                    "projectBindingDigest": config["projectBindingDigest"],
                    "configDigest": config["configDigest"],
                    "document": document,
                    "rootNodeId": root_id,
                }
            )
            for root_id in value["document"]["rootNodeIds"]
        ]
        expected = {
            "flowDigest": sha256_digest(
                {
                    "kind": "figma_flow",
                    "runId": config["runId"],
                    "projectBindingDigest": config["projectBindingDigest"],
                    "configDigest": config["configDigest"],
                    "document": document,
                    "screenDigests": expected_screens,
                }
            ),
            "screenDigests": expected_screens,
        }

        self.assertEqual(
            expected_figma_ux_target(
                value,
                run_pin=run_pin(),
                verified_snapshot=snapshot(),
            ),
            expected,
        )
        self.assertEqual(len(set(expected_screens)), 2)
        self.assertNotIn(expected["flowDigest"], expected_screens)

    def test_raw_and_inferred_equal_value_matches_are_violations(self) -> None:
        from guardian_core.canonical import canonical_json_bytes

        value = clean_observation()
        value["observations"] = sorted(
            value["observations"]
            + [
                {
                    "kind": "raw",
                    "category": "colors",
                    "nodeId": "100:3",
                    "field": "fills.0.color",
                    "valueDigest": "e" * 64,
                    "inferredVariableKeys": ["variable-key-primary"],
                },
                {
                    "kind": "raw",
                    "category": "spacing",
                    "nodeId": "100:4",
                    "field": "itemSpacing",
                    "valueDigest": "f" * 64,
                    "inferredVariableKeys": [],
                },
            ],
            key=canonical_json_bytes,
        )
        value["analysis"].update(
            assessedNodes=5,
            totalNodes=5,
            assessedFields=5,
            totalFields=5,
        )

        normalized = self.normalize(value)
        reasons = {item["evidence"]["reason"] for item in normalized["diagnostics"]}
        self.assertEqual(
            reasons,
            {"inferred_match_is_not_binding", "raw_value_not_bound"},
        )

    def test_wrong_variable_and_style_keys_are_violations_not_approval(self) -> None:
        value = clean_observation()
        for item in value["observations"]:
            if item["kind"] == "variable":
                item["variableKey"] = "same-looking-variable"
            elif item["kind"] == "style":
                item["styleKey"] = "same-looking-style"
        from guardian_core.canonical import canonical_json_bytes

        value["observations"] = sorted(value["observations"], key=canonical_json_bytes)
        normalized = self.normalize(value)
        self.assertEqual(
            {item["evidence"]["reason"] for item in normalized["diagnostics"]},
            {"variable_binding_not_exact", "style_binding_not_exact"},
        )

    def test_detached_local_wrong_variant_properties_and_overrides_fail(self) -> None:
        from guardian_core.canonical import canonical_json_bytes

        mutations = {
            "detached": ("nodeType", "FRAME"),
            "local": ("remote", False),
            "key": ("canonicalAssetKey", "component-key-lookalike"),
            "variant": ("variant", "default"),
            "properties": ("properties", {"size": "medium"}),
            "overrides": ("unapprovedOverrideFields", ["fills"]),
        }
        for label, (field, replacement) in mutations.items():
            with self.subTest(label=label):
                value = clean_observation()
                item = next(item for item in value["observations"] if item["kind"] == "asset")
                item["figmaInstance"][field] = replacement
                value["observations"] = sorted(value["observations"], key=canonical_json_bytes)
                normalized = self.normalize(value)
                self.assertEqual(len(normalized["diagnostics"]), 1)
                self.assertEqual(
                    normalized["diagnostics"][0]["evidence"]["reason"],
                    "working_instance_not_exactly_signed",
                )

    def test_signed_working_lineage_does_not_break_the_canonical_library_file(self) -> None:
        from guardian_core.canonical import canonical_json_bytes

        value = clean_observation()
        value["document"].update(
            fileKey=LIBRARY_FILE,
            sourceVersion=LIBRARY_VERSION,
        )
        item = next(item for item in value["observations"] if item["kind"] == "asset")
        item["nodeId"] = "10:21"
        item["figmaInstance"].update(
            fileKey=LIBRARY_FILE,
            nodeId="10:21",
            sourceVersion=LIBRARY_VERSION,
            remote=False,
        )
        value["observations"] = sorted(value["observations"], key=canonical_json_bytes)

        self.assertEqual(self.normalize(value)["diagnostics"], [])

    def test_document_and_instance_versions_are_pinned(self) -> None:
        from guardian_core.figma_adapter import FigmaAdapterSourceError

        document = clean_observation()
        document["document"]["sourceVersion"] = "copy-18"
        with self.assertRaises(FigmaAdapterSourceError) as raised:
            self.normalize(document)
        self.assertEqual(raised.exception.status, "stale")

        instance = clean_observation()
        item = next(item for item in instance["observations"] if item["kind"] == "asset")
        item["figmaInstance"]["sourceVersion"] = "copy-18"
        from guardian_core.canonical import canonical_json_bytes

        instance["observations"] = sorted(instance["observations"], key=canonical_json_bytes)
        normalized = self.normalize(instance)
        self.assertEqual(
            normalized["diagnostics"][0]["evidence"]["reason"],
            "working_instance_not_exactly_signed",
        )

    def test_source_states_remain_distinct_and_missing_is_never_collector_claim(self) -> None:
        from guardian_core.figma_adapter import (
            FigmaAdapterIntegrityError,
            FigmaAdapterSourceError,
        )

        for state in ("source_unavailable", "source_incomplete", "stale"):
            with self.subTest(state=state):
                pin = run_pin(state=state)
                snap = snapshot(
                    state=state,
                    available=state != "source_unavailable",
                    complete=state not in {"source_unavailable", "source_incomplete"},
                )
                if state == "stale":
                    snap["sourceAvailable"] = True
                    snap["sourceComplete"] = True
                value = clean_observation(state=state, status=state)
                with self.assertRaises(FigmaAdapterSourceError) as raised:
                    self.normalize(value, pin=pin, snap=snap)
                self.assertEqual(raised.exception.status, state)

        missing = clean_observation()
        missing["status"] = "missing"
        with self.assertRaises(FigmaAdapterIntegrityError):
            self.normalize(missing)

    def test_incomplete_binding_metadata_is_source_incomplete(self) -> None:
        from guardian_core.figma_adapter import FigmaAdapterSourceError

        snap = snapshot()
        snap["tokens"]["color.brand.primary"]["extensions"].clear()
        with self.assertRaises(FigmaAdapterSourceError) as raised:
            self.normalize(clean_observation(), snap=snap)
        self.assertEqual(raised.exception.status, "source_incomplete")

    def test_binding_drift_unknown_fields_order_and_duplicate_observations_fail(self) -> None:
        from guardian_core.figma_adapter import FigmaAdapterIntegrityError

        cases = []
        binding = clean_observation()
        binding["binding"]["profileId"] = "other-company"
        cases.append(binding)

        unknown = clean_observation()
        unknown["unexpected"] = True
        cases.append(unknown)

        unordered = clean_observation()
        unordered["observations"] = list(reversed(unordered["observations"]))
        cases.append(unordered)

        duplicate = clean_observation()
        duplicate["observations"].append(copy.deepcopy(duplicate["observations"][0]))
        cases.append(duplicate)

        counts = clean_observation()
        counts["analysis"]["assessedFields"] = 2
        cases.append(counts)

        for value in cases:
            with self.subTest(case=value), self.assertRaises(FigmaAdapterIntegrityError):
                self.normalize(value)

    def test_contract_schema_and_fixed_collector_contain_no_credentials_or_writes(self) -> None:
        from guardian_core.canonical import sha256_digest
        from guardian_core.figma_adapter import collector_digest
        from jsonschema import Draft202012Validator

        root = Path(__file__).resolve().parents[1]
        schema = json.loads(
            (root / "adapters/figma/contracts/figma-observation.schema.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(clean_observation())

        collector = (root / "adapters/figma/collector.js").read_text(encoding="utf-8")
        for forbidden in (
            "createVariable(",
            "createComponent(",
            "createFrame(",
            "setBoundVariable(",
            "setTextStyleIdAsync(",
            "fetch(",
            "Authorization",
            "accessToken",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, collector)
        self.assertIn("getMainComponentAsync", collector)
        self.assertIn("boundVariables", collector)
        self.assertIn("getStyleByIdAsync", collector)
        contract = subprocess.run(
            [
                "node",
                "-e",
                "process.stdout.write(JSON.stringify(require(process.argv[1]).CONTRACT))",
                str(root / "adapters/figma/collector.js"),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            sha256_digest(json.loads(contract.stdout)),
            collector_digest(),
        )

    def test_collector_never_emits_component_product_copy(self) -> None:
        from guardian_core.figma_adapter import build_figma_adapter_config

        root = Path(__file__).resolve().parents[1]
        collector_path = root / "adapters/figma/collector.js"
        config = build_figma_adapter_config(
            run_pin=run_pin(),
            verified_snapshot=snapshot(),
        )
        context = {
            "source": {"state": "fresh", "available": True, "complete": True},
            "document": {
                "fileKey": WORKING_FILE,
                "sourceVersion": WORKING_VERSION,
                "rootNodeIds": ["220:41"],
            },
        }
        product_copy = "PRIVATE CUSTOMER ACCOUNT COPY"
        script = r"""
const [collectorPath, configText, contextText, productCopy] = process.argv.slice(1);
const collector = require(collectorPath);
const config = JSON.parse(configText);
const context = JSON.parse(contextText);
const instance = {
  id: "220:41",
  type: "INSTANCE",
  componentProperties: {
    size: {type: "VARIANT", value: "large"},
    label: {type: "TEXT", value: productCopy}
  },
  overrides: [],
  getMainComponentAsync: async () => ({
    key: "component-key-primary",
    remote: true,
    name: "loading"
  })
};
const api = {
  fileKey: "figma-working-copy",
  mixed: Symbol("mixed"),
  getNodeByIdAsync: async () => instance,
  getStyleByIdAsync: async () => null,
  variables: {
    getVariableByIdAsync: async () => null,
    getVariableCollectionByIdAsync: async () => null
  }
};
collector.collectGuardianFigmaObservation(config, context, api).then((value) => {
  process.stdout.write(JSON.stringify(value));
}).catch((error) => {
  process.stderr.write(String(error));
  process.exit(1);
});
"""
        completed = subprocess.run(
            [
                "node",
                "-e",
                script,
                str(collector_path),
                json.dumps(config, separators=(",", ":")),
                json.dumps(context, separators=(",", ":")),
                product_copy,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertNotIn(product_copy, completed.stdout)
        observation = json.loads(completed.stdout)
        asset_observation = next(
            item for item in observation["observations"] if item["kind"] == "asset"
        )
        self.assertEqual(
            asset_observation["figmaInstance"]["properties"],
            {"size": "large"},
        )


if __name__ == "__main__":
    unittest.main()
