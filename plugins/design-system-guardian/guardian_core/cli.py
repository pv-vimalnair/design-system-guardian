"""Portable command surface for Design System Guardian."""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Sequence


from .adapter_dispatch import (
    AdapterDispatchError,
    build_figma_runner_evidence,
    build_pinned_adapter_config,
    select_adapter,
)
from .audit import _authoritatively_resolve, evaluate_audit
from .audit_attestation import build_analysis_attestation
from .canonical import atomic_write_json, canonical_json_text, read_canonical_json, read_json, sha256_digest
from .catalog_authority import verify_pinned_catalog_authority, verify_runtime_dependency
from .contracts import ExitCode, ResolutionStatus
from .dtcg import DtcgValidationError
from .elo import benchmark_elo, evaluate_elo, read_elo_state
from .errors import GuardianError, PolicyIntegrityError
from .finalize import finalize_run
from .figma_adapter import (
    FigmaAdapterIntegrityError,
    FigmaAdapterSourceError,
    expected_figma_ux_target,
)
from .flutter_adapter import normalize_flutter_adapter_result
from .flutter_config import (
    _generate_flutter_adapter_config_at_home,
    FlutterAdapterUnsupportedError,
    generate_flutter_adapter_config,
    write_flutter_adapter_config,
)
from .flutter_runner import FlutterRunnerUnsupportedError, run_flutter_analysis
from .migrations import default_migration_registry, migrate_to_current
from .onboarding import (
    OnboardingError,
    apply_onboarding,
    inspect_onboarding,
    prepare_onboarding_permission,
)
from .paths import GuardianPaths, assert_guardian_storage_path, default_guardian_home
from .policy import (
    ELO_ENROLLMENT_NAME,
    TRUST_SCHEMA_VERSION,
    install_policy_anchor,
    migrate_legacy_elo_genesis,
    verify_elo_enrollment,
    verify_policy_anchor,
)
from .preflight import PreflightError, load_run_pin, preflight_snapshot
from .project_binding import project_evidence_from_runner, require_requested_project
from .profile import ProfileValidationError, install_profile, load_profile, validate_profile
from .resolver import resolve_identity
from .rules import (
    RuleValidationError,
    invalid_report,
    load_description,
    load_known_identities,
    load_rule_artifact,
    parse_description_markers,
    validate_rules,
)
from .run_artifacts import read_run_artifact, seal_run_artifact, write_run_artifact
from .snapshot import SnapshotValidationError, ingest_snapshot
from .ux_evaluator import (
    UxEvaluationIntegrityError,
    audit_checks_from_evaluation,
    evaluate_final_flow,
    evaluate_screen_checkpoint,
)


_AUDIT_REQUEST_V1_KEYS = {"schemaVersion", "projectRoot", "resolutions", "uxChecks"}
_AUDIT_REQUEST_V2_KEYS = {
    "schemaVersion",
    "adapter",
    "projectRoot",
    "resolutions",
    "uxEvidence",
    "adapterEvidence",
}
_UX_EVIDENCE_KEYS = {"target", "observations"}
_UX_CHECKPOINT_KEYS = {"schemaVersion", "target", "observations"}
_ONBOARDING_CANDIDATE_KEYS = {
    "schemaVersion",
    "catalogAuthorityPublicKey",
    "profile",
    "catalog",
}


def _emit(value: dict[str, object], *, error: bool = False) -> None:
    stream = sys.stderr if error else sys.stdout
    stream.write(canonical_json_text(value))
    stream.flush()


def _exit_for_status(status: str) -> int:
    if status == ResolutionStatus.ALLOWED.value:
        return int(ExitCode.PASS)
    if status in {
        ResolutionStatus.MISSING.value,
        ResolutionStatus.AMBIGUOUS.value,
        ResolutionStatus.CONFLICT.value,
    }:
        return int(ExitCode.VIOLATION_OR_SENTINEL)
    if status == ResolutionStatus.INVALID.value:
        return int(ExitCode.INVALID_POLICY_CONFIG_OR_INTEGRITY)
    if status in {
        ResolutionStatus.STALE.value,
        ResolutionStatus.SOURCE_UNAVAILABLE.value,
        ResolutionStatus.SOURCE_INCOMPLETE.value,
    }:
        return int(ExitCode.SOURCE_UNAVAILABLE_STALE_OR_INCOMPLETE)
    return int(ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE)

def _status_for_exit(code: ExitCode) -> str:
    return {
        ExitCode.PASS: ResolutionStatus.ALLOWED.value,
        ExitCode.VIOLATION_OR_SENTINEL: ResolutionStatus.CONFLICT.value,
        ExitCode.INVALID_POLICY_CONFIG_OR_INTEGRITY: ResolutionStatus.INVALID.value,
        ExitCode.SOURCE_UNAVAILABLE_STALE_OR_INCOMPLETE: ResolutionStatus.SOURCE_UNAVAILABLE.value,
        ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE: ResolutionStatus.UNSUPPORTED.value,
    }[code]



def _setup_status(args: argparse.Namespace) -> int:
    result = inspect_onboarding(
        default_guardian_home(),
        profile_id=args.profile,
    )
    _emit(result)
    status = str(result["status"])
    if status == "ready":
        return int(ExitCode.PASS)
    if status in {
        ResolutionStatus.STALE.value,
        ResolutionStatus.SOURCE_UNAVAILABLE.value,
        ResolutionStatus.SOURCE_INCOMPLETE.value,
    }:
        return int(ExitCode.SOURCE_UNAVAILABLE_STALE_OR_INCOMPLETE)
    if status == ResolutionStatus.INVALID.value:
        return int(ExitCode.INVALID_POLICY_CONFIG_OR_INTEGRITY)
    return int(ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE)


def _setup_preview(args: argparse.Namespace) -> int:
    candidate = _canonical_object(
        args.input,
        keys=_ONBOARDING_CANDIDATE_KEYS,
        label="Onboarding candidate",
    )
    if candidate.get("schemaVersion") != 1:
        raise OnboardingError("Onboarding candidate schemaVersion must be exactly 1.")
    public_key = candidate.get("catalogAuthorityPublicKey")
    if not isinstance(public_key, str):
        raise OnboardingError("Onboarding catalog authority key path must be a string.")
    result = prepare_onboarding_permission(
        catalog_authority_public_key=Path(public_key),
        profile_document=candidate.get("profile"),
        catalog_document=candidate.get("catalog"),
    )
    _emit(result)
    return int(ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE)


def _setup_apply(args: argparse.Namespace) -> int:
    bundle = _canonical_object(
        args.input,
        keys=None,
        label="Onboarding bundle",
    )
    result = apply_onboarding(default_guardian_home(), bundle)
    _emit(result)
    status = str(result["status"])
    if status == ResolutionStatus.ALLOWED.value:
        return int(ExitCode.PASS)
    return _exit_for_status(status)


def _doctor(args: argparse.Namespace) -> int:
    home = default_guardian_home()
    supplied_key = (
        Path(args.catalog_authority_public_key)
        if args.catalog_authority_public_key is not None
        else None
    )
    if args.install_policy:
        installation = install_policy_anchor(
            home,
            catalog_authority_public_key=supplied_key,
        )
        digest = installation.digest
        installed = installation.created
        key_id = installation.catalog_authority_key_id
    else:
        if supplied_key is not None:
            raise PolicyIntegrityError(
                "--catalog-authority-public-key is valid only with --install-policy."
            )
        digest = verify_policy_anchor(home)
        installed = False
        _, key_id = verify_pinned_catalog_authority(home)
    dependency_version = verify_runtime_dependency()
    _emit(
        {
            "policyDigest": digest,
            "policyInstalled": installed,
            "schemaVersion": 1,
            "status": ResolutionStatus.ALLOWED.value,
            "trustSchemaVersion": TRUST_SCHEMA_VERSION,
            "snapshotAuthorityReady": True,
            "catalogAuthorityKeyId": key_id,
            "runtimeDependencies": {"cryptography": dependency_version},
        }
    )
    return int(ExitCode.PASS)


def _profile_validate(args: argparse.Namespace) -> int:
    home = default_guardian_home()
    policy_digest = verify_policy_anchor(home)
    profile = validate_profile(read_json(Path(args.input)))
    installed_path = install_profile(home, profile) if args.install else None
    _emit(
        {
            "schemaVersion": 1,
            "status": ResolutionStatus.ALLOWED.value,
            "profileId": profile["profileId"],
            "profileDigest": sha256_digest(profile),
            "policyDigest": policy_digest,
            "installed": installed_path is not None,
            "installedPath": str(installed_path) if installed_path is not None else None,
        }
    )
    return int(ExitCode.PASS)


def _snapshot_ingest(args: argparse.Namespace) -> int:
    home = default_guardian_home()
    policy_digest = verify_policy_anchor(home)
    profile = load_profile(home, args.profile)
    snapshot = ingest_snapshot(home, profile, read_json(Path(args.input)))
    source_state = snapshot["sourceState"]
    status = "allowed" if source_state in {"fresh", "offline_grace"} else source_state
    if snapshot.get("schemaVersion") == 2:
        rule_evidence = snapshot.get("ruleEvidence")
        rule_validation = snapshot.get("ruleValidation")
        if not isinstance(rule_evidence, dict) or not isinstance(rule_validation, dict):
            raise SnapshotValidationError("Rule-snapshot evidence is missing or malformed.")
        if rule_evidence.get("sourceComplete") is not True:
            source_state = ResolutionStatus.SOURCE_INCOMPLETE.value
            status = source_state
        elif rule_validation.get("status") != ResolutionStatus.ALLOWED.value:
            status = str(rule_validation.get("status"))
    result = {
        "schemaVersion": 1,
        "status": status,
        "profileId": snapshot["profileId"],
        "profileDigest": snapshot["profileDigest"],
        "snapshotId": snapshot["snapshotId"],
        "catalogDigest": snapshot["catalogDigest"],
        "approvalSequence": snapshot["approvalSequence"],
        "policyDigest": policy_digest,
        "sourceState": source_state,
        "sourceCut": snapshot["sourceCut"],
        "degraded": source_state == "offline_grace",
        "snapshotUsable": status == "allowed",
    }
    _emit(result)
    return _exit_for_status(status)


def _preflight(args: argparse.Namespace) -> int:
    home = default_guardian_home()
    policy_digest = verify_policy_anchor(home)
    result = preflight_snapshot(
        home,
        profile_id=args.profile,
        run_id=args.run_id,
        policy_digest=policy_digest,
        project_root=Path(args.project_root),
    )
    _emit(result)
    return _exit_for_status(str(result["status"]))


def _resolve(args: argparse.Namespace) -> int:
    request = read_json(Path(args.request))
    if not isinstance(request, dict):
        raise ValueError("Resolution request must be a JSON object.")
    result = resolve_identity(
        profile_id=args.profile,
        run_id=args.run_id,
        request=request,
    )
    _emit(result)
    return _exit_for_status(str(result["status"]))


def _canonical_object(path: str, *, keys: set[str] | None, label: str) -> dict[str, object]:
    value = read_canonical_json(Path(path))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a canonical JSON object.")
    if keys is not None and set(value) != keys:
        raise ValueError(f"{label} has unknown or missing fields.")
    return value


def _audit_command(args: argparse.Namespace) -> int:
    home = default_guardian_home()
    policy_digest = verify_policy_anchor(home)
    context = load_run_pin(
        home,
        profile_id=args.profile,
        run_id=args.run_id,
        policy_digest=policy_digest,
    )
    request = _canonical_object(
        args.input,
        keys=None,
        label="Audit request",
    )
    schema_version = request.get("schemaVersion")
    if schema_version == 1:
        if set(request) != _AUDIT_REQUEST_V1_KEYS:
            raise ValueError("Version 1 audit request has unknown or missing fields.")
        requested_adapter = "flutter"
        legacy_ux_checks = request.get("uxChecks")
        ux_evidence = None
        adapter_evidence = None
    elif schema_version == 2:
        if set(request) != _AUDIT_REQUEST_V2_KEYS:
            raise ValueError("Version 2 audit request has unknown or missing fields.")
        requested_adapter = select_adapter(context["profile"], request.get("adapter"))
        legacy_ux_checks = []
        ux_evidence = request.get("uxEvidence")
        adapter_evidence = request.get("adapterEvidence")
        if not isinstance(ux_evidence, dict) or set(ux_evidence) != _UX_EVIDENCE_KEYS:
            raise ValueError("Version 2 audit uxEvidence has unknown or missing fields.")
        if not isinstance(ux_evidence.get("target"), dict) or not isinstance(
            ux_evidence.get("observations"), list
        ):
            raise ValueError("Version 2 audit UX target and observations are invalid.")
    else:
        raise ValueError("Audit request schemaVersion must be exactly 1 or 2.")

    project_root = request.get("projectRoot")
    if (
        not isinstance(project_root, str)
        or not project_root.strip()
        or project_root.strip() != project_root
    ):
        raise ValueError("Audit request projectRoot must be one exact non-empty path.")
    project_binding = require_requested_project(
        context["pin"]["projectBinding"], project_root
    )
    resolutions = request.get("resolutions")
    if not isinstance(resolutions, list) or not isinstance(legacy_ux_checks, list):
        raise ValueError("Audit resolutions and legacy uxChecks must be arrays.")
    authoritative, _, _ = _authoritatively_resolve(
        resolutions,
        pin=context["pin"],
        verified_snapshot=context["snapshot"],
    )

    if requested_adapter == "flutter":
        if schema_version == 2 and adapter_evidence is not None:
            raise ValueError("Flutter audit adapterEvidence must be null.")
        expected_config = _generate_flutter_adapter_config_at_home(
            home,
            profile_id=args.profile,
            run_id=args.run_id,
        )
        expected_sentinels = tuple(
            {
                "requestId": item["sentinel"]["requestId"],
                "kind": item["sentinel"]["kind"],
                "policyDigest": context["pin"]["policyDigest"],
            }
            for item in authoritative
            if item.get("sentinel") is not None
        )
        with tempfile.TemporaryDirectory(prefix="design-system-guardian-audit-") as directory:
            config_path = Path(directory) / "flutter-adapter.json"
            write_flutter_adapter_config(expected_config, output_path=config_path)
            runner_evidence = run_flutter_analysis(
                project_root=Path(project_root),
                adapter_config_path=config_path,
                run_pin=context["pin"],
                expected_sentinels=expected_sentinels,
            )
        normalized = normalize_flutter_adapter_result(
            runner_evidence.get("adapterResult"),
            adapter_config=expected_config,
            run_pin=context["pin"],
        )
        # Bind the already-derived audit projection into the sealed runner
        # evidence. Finalization still re-normalizes the raw analyzer result.
        runner_evidence["normalizedAdapterResult"] = normalized
    else:
        if not isinstance(adapter_evidence, dict):
            raise ValueError("Figma audit requires one fixed collector observation object.")
        runner_evidence, normalized, expected_config = build_figma_runner_evidence(
            observation=adapter_evidence,
            run_pin=context["pin"],
            verified_snapshot=context["snapshot"],
            project_binding=project_binding,
        )

    project_evidence = project_evidence_from_runner(
        project_binding, runner_evidence.get("project")
    )
    trusted_ux_checks = None
    ux_target = None
    ux_evaluation = None
    if schema_version == 2:
        if not isinstance(ux_evidence, dict):
            raise RuntimeError("Validated v2 UX evidence is unavailable.")
        ux_target = ux_evidence["target"]
        if requested_adapter == "figma":
            expected_target = expected_figma_ux_target(
                adapter_evidence,
                run_pin=context["pin"],
                verified_snapshot=context["snapshot"],
            )
            if ux_target != expected_target:
                raise UxEvaluationIntegrityError(
                    "Figma UX target is not bound to the exact audited document roots."
                )
        ux_evaluation = evaluate_final_flow(
            target=ux_target,
            observations=ux_evidence["observations"],
            source_cut=context["pin"]["sourceCut"],
        )
        trusted_ux_checks = audit_checks_from_evaluation(
            ux_evaluation,
            target=ux_target,
            source_cut=context["pin"]["sourceCut"],
        )

    runner_digest = sha256_digest(runner_evidence)
    evaluation = evaluate_audit(
        run_pin=context["pin"],
        adapter_result=normalized,
        resolutions=authoritative,
        ux_checks=legacy_ux_checks,
        trusted_ux_checks=trusted_ux_checks,
        verified_snapshot=context["snapshot"],
        analysis_attestation_digest=runner_digest,
        project_evidence=project_evidence,
    )
    attestation = build_analysis_attestation(
        run_pin=context["pin"],
        config_digest=expected_config["configDigest"],
        runner_evidence=runner_evidence,
        audit_result=evaluation.result,
        ux_target=ux_target,
        ux_evaluation=ux_evaluation,
        adapter_config=expected_config,
        verified_snapshot=context["snapshot"],
    )
    envelope = seal_run_artifact(
        home,
        artifact_type="analysis-attestation",
        profile_id=args.profile,
        run_id=args.run_id,
        payload=attestation,
    )
    write_run_artifact(home, envelope)
    _emit(evaluation.result)
    return int(evaluation.exit_code)

def _private_adapter_output(home: Path, requested: str) -> Path:
    """Keep design-system allowlists inside Guardian host-owned local state."""

    if not isinstance(requested, str) or not requested.strip():
        raise ValueError("Adapter config output must be one exact non-empty path.")
    return assert_guardian_storage_path(
        home, Path(requested).expanduser().absolute()
    )


def _flutter_config_command(args: argparse.Namespace) -> int:
    home = default_guardian_home()
    config = generate_flutter_adapter_config(
        profile_id=args.profile,
        run_id=args.run_id,
    )
    output_path = _private_adapter_output(home, args.output)
    written_path = write_flutter_adapter_config(config, output_path=output_path)
    _emit(
        {
            "schemaVersion": 1,
            "status": ResolutionStatus.ALLOWED.value,
            "profileId": config["profileId"],
            "runId": args.run_id,
            "adapter": config["adapter"],
            "adapterVersion": config["adapterVersion"],
            "configDigest": config["configDigest"],
            "outputPath": str(written_path),
        }
    )
    return int(ExitCode.PASS)


def _figma_config_command(args: argparse.Namespace) -> int:
    home = default_guardian_home()
    _, config = build_pinned_adapter_config(
        home,
        profile_id=args.profile,
        run_id=args.run_id,
        adapter="figma",
    )
    output_path = _private_adapter_output(home, args.output)
    atomic_write_json(output_path, config)
    if read_canonical_json(output_path) != config:
        raise ValueError("Written Figma adapter config is not canonical.")
    _emit(
        {
            "schemaVersion": 1,
            "status": ResolutionStatus.ALLOWED.value,
            "profileId": config["profileId"],
            "runId": args.run_id,
            "adapter": config["adapter"],
            "adapterVersion": config["adapterVersion"],
            "configDigest": config["configDigest"],
            "collectorDigest": config["collectorDigest"],
            "outputPath": str(output_path),
        }
    )
    return int(ExitCode.PASS)


def _ux_checkpoint_command(args: argparse.Namespace) -> int:
    home = default_guardian_home()
    context = load_run_pin(
        home,
        profile_id=args.profile,
        run_id=args.run_id,
        policy_digest=verify_policy_anchor(home),
    )
    request = _canonical_object(
        args.input,
        keys=_UX_CHECKPOINT_KEYS,
        label="UX checkpoint request",
    )
    if request.get("schemaVersion") != 1:
        raise UxEvaluationIntegrityError(
            "UX checkpoint schemaVersion must be exactly 1."
        )
    target = request.get("target")
    observations = request.get("observations")
    if not isinstance(target, dict) or not isinstance(observations, list):
        raise UxEvaluationIntegrityError(
            "UX checkpoint target and observations are invalid."
        )
    result = evaluate_screen_checkpoint(
        target=target,
        observations=observations,
        source_cut=context["pin"]["sourceCut"],
    )
    _emit(result)
    if result["status"] == ResolutionStatus.ALLOWED.value:
        return int(ExitCode.PASS)
    if result["status"] == ResolutionStatus.CONFLICT.value:
        return int(ExitCode.VIOLATION_OR_SENTINEL)
    return int(ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE)

def _finalize_command(args: argparse.Namespace) -> int:
    home = default_guardian_home()
    verify_policy_anchor(home)
    audit_result = _canonical_object(
        args.audit_result,
        keys=None,
        label="Audit result",
    )
    build_plan = (
        _canonical_object(args.build_plan, keys=None, label="Build plan")
        if args.build_plan is not None
        else None
    )
    result = finalize_run(
        home,
        profile_id=args.profile,
        run_id=args.run_id,
        audit_result=audit_result,
        build_plan=build_plan,
    )
    paths = {
        artifact_type: path.relative_to(home).as_posix()
        for artifact_type, path in sorted(result.artifact_paths.items())
    }
    _emit(
        {
            "schemaVersion": 1,
            "status": _status_for_exit(result.exit_code),
            "profileId": args.profile,
            "runId": args.run_id,
            "exitCode": int(result.exit_code),
            "productionReady": result.production_ready,
            "manifest": result.manifest,
            "postRunAssessment": result.post_run_assessment,
            "artifactPaths": paths,
        }
    )
    return int(result.exit_code)


def _self_check_command(args: argparse.Namespace) -> int:
    home = default_guardian_home()
    verify_policy_anchor(home)
    envelope = read_run_artifact(
        home,
        profile_id=args.profile,
        run_id=args.run_id,
        artifact_type="post-run-assessment",
    )
    assessment = envelope["payload"]
    statuses = assessment.get("statuses")
    run_status = statuses.get("run") if isinstance(statuses, dict) else None
    exit_codes = {
        "passed": ExitCode.PASS,
        "violation": ExitCode.VIOLATION_OR_SENTINEL,
        "invalid": ExitCode.INVALID_POLICY_CONFIG_OR_INTEGRITY,
        "source_blocked": ExitCode.SOURCE_UNAVAILABLE_STALE_OR_INCOMPLETE,
        "unsupported": ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE,
    }
    if run_status not in exit_codes:
        raise ValueError("Sealed post-run assessment has an unsupported run status.")
    _emit(assessment)
    return int(exit_codes[run_status])


def _migrate_command(args: argparse.Namespace) -> int:
    home = default_guardian_home()
    policy_digest = verify_policy_anchor(home)
    supplied = Path(args.artifact)
    artifact_path = (
        supplied
        if supplied.is_absolute()
        else GuardianPaths(home).profile(args.profile) / supplied
    )
    registry = default_migration_registry()
    result = migrate_to_current(
        home,
        profile_id=args.profile,
        artifact_path=artifact_path,
        registry=registry,
    )
    _emit(
        {
            "schemaVersion": 1,
            "status": ResolutionStatus.ALLOWED.value,
            "profileId": args.profile,
            "policyDigest": policy_digest,
            "artifactPath": artifact_path.absolute().relative_to(home.absolute()).as_posix(),
            "currentVersion": registry.current_version,
            "changed": result.changed,
            "appliedMigrationIds": [item["migrationId"] for item in result.applied],
            "backupPaths": [
                path.absolute().relative_to(home.absolute()).as_posix()
                for path in result.backup_paths
            ],
        }
    )
    return int(ExitCode.PASS)


def _elo_migrate_legacy_command(args: argparse.Namespace) -> int:
    del args
    home = default_guardian_home()
    changed = migrate_legacy_elo_genesis(home)
    state = read_elo_state(home)
    enrollment = verify_elo_enrollment(
        home,
        read_canonical_json(GuardianPaths(home).trust / ELO_ENROLLMENT_NAME),
    )
    _emit(
        {
            "schemaVersion": 1,
            "status": ResolutionStatus.ALLOWED.value,
            "policyDigest": verify_policy_anchor(home),
            "changed": changed,
            "ledgerId": enrollment["ledgerId"],
            "continuityReset": True,
            "continuityFromPriorLedgerProven": False,
            "newLedger": True,
            "score": state["score"],
            "sequence": state["sequence"],
        }
    )
    return int(ExitCode.PASS)


def _elo_show_command(args: argparse.Namespace) -> int:
    del args
    _emit(read_elo_state(default_guardian_home()))
    return int(ExitCode.PASS)


def _elo_benchmark_command(args: argparse.Namespace) -> int:
    result = benchmark_elo(default_guardian_home(), Path(args.target_root))
    if args.output is not None:
        atomic_write_json(Path(args.output), result)
    _emit(result)
    return int(ExitCode.PASS)


def _elo_evaluate_command(args: argparse.Namespace) -> int:
    result = evaluate_elo(
        default_guardian_home(),
        read_canonical_json(Path(args.baseline_result)),
        read_canonical_json(Path(args.candidate_result)),
    )
    _emit(result)
    return int(ExitCode.PASS)


def _rules_validate_command(args: argparse.Namespace) -> int:
    source_type = "artifact" if args.rule_format == "artifact" else "figma_description"
    try:
        known_identities = (
            load_known_identities(Path(args.known_identities))
            if args.known_identities is not None
            else None
        )
        if source_type == "artifact":
            candidates = load_rule_artifact(Path(args.input))
        else:
            metadata = (
                args.host_kind,
                args.host_identity,
                args.figma_file_key,
                args.figma_node_id,
                args.figma_source_version,
            )
            if any(value is None for value in metadata):
                report = invalid_report(source_type, "missing_metadata")
                _emit(report)
                return int(ExitCode.INVALID_POLICY_CONFIG_OR_INTEGRITY)
            candidates = parse_description_markers(
                load_description(Path(args.input)),
                host_kind=args.host_kind,
                host_identity=args.host_identity,
                figma={
                    "fileKey": args.figma_file_key,
                    "nodeId": args.figma_node_id,
                    "sourceVersion": args.figma_source_version,
                },
            )
        result = validate_rules(
            candidates,
            known_identities=known_identities,
            source_type=source_type,
        )
        report = result["report"]
    except RuleValidationError as error:
        report = invalid_report(source_type, error.reason_code)
    _emit(report)
    status = str(report["status"])
    if status == ResolutionStatus.ALLOWED.value:
        return int(ExitCode.PASS)
    if status == ResolutionStatus.NOT_ASSESSED.value:
        return int(ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE)
    return int(ExitCode.INVALID_POLICY_CONFIG_OR_INTEGRITY)


def _rules_activate_preview_command(args: argparse.Namespace) -> int:
    from .rule_activation import preview_rule_activation

    result = preview_rule_activation(
        default_guardian_home(),
        profile_id=args.profile,
        catalog_document=read_json(Path(args.input)),
    )
    _emit(result)
    return int(ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE)


def _rules_activate_apply_command(args: argparse.Namespace) -> int:
    from .rule_activation import apply_rule_activation

    result = apply_rule_activation(
        default_guardian_home(),
        read_json(Path(args.input)),
    )
    _emit(result)
    return int(ExitCode.PASS)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="guardian")
    commands = parser.add_subparsers(dest="command", required=True)

    setup = commands.add_parser(
        "setup",
        help="Inspect or apply permission-bound local Guardian onboarding.",
    )
    setup_commands = setup.add_subparsers(dest="setup_command", required=True)
    setup_status = setup_commands.add_parser(
        "status",
        help="Inspect local readiness without changing files.",
    )
    setup_status.add_argument("--profile")
    setup_status.set_defaults(handler=_setup_status)
    setup_preview = setup_commands.add_parser(
        "preview",
        help="Validate one local candidate and return the exact permission request.",
    )
    setup_preview.add_argument("--input", required=True)
    setup_preview.set_defaults(handler=_setup_preview)
    setup_apply = setup_commands.add_parser(
        "apply",
        help="Apply a candidate only when its exact permission binding is granted.",
    )
    setup_apply.add_argument("--input", required=True)
    setup_apply.set_defaults(handler=_setup_apply)

    doctor = commands.add_parser("doctor", help="Verify Guardian integrity and environment readiness.")
    doctor.add_argument("--install-policy", action="store_true", help="Create the immutable policy anchor once.")
    doctor.add_argument(
        "--catalog-authority-public-key",
        help="Ed25519 public PEM to pin when installing a new trust anchor.",
    )
    doctor.set_defaults(handler=_doctor)

    profile = commands.add_parser("profile", help="Manage one explicitly selected company profile.")
    profile_commands = profile.add_subparsers(dest="profile_command", required=True)
    profile_validate = profile_commands.add_parser("validate")
    profile_validate.add_argument("--input", required=True)
    profile_validate.add_argument("--install", action="store_true")
    profile_validate.set_defaults(handler=_profile_validate)

    snapshot = commands.add_parser("snapshot", help="Manage immutable catalog snapshots.")
    snapshot_commands = snapshot.add_subparsers(dest="snapshot_command", required=True)
    snapshot_ingest = snapshot_commands.add_parser("ingest")
    snapshot_ingest.add_argument("--profile", required=True)
    snapshot_ingest.add_argument("--input", required=True)
    snapshot_ingest.set_defaults(handler=_snapshot_ingest)

    preflight = commands.add_parser("preflight")
    preflight.add_argument("--profile", required=True)
    preflight.add_argument("--run-id", required=True)
    preflight.add_argument("--project-root", required=True)
    preflight.set_defaults(handler=_preflight)

    resolve = commands.add_parser("resolve")
    resolve.add_argument("--profile", required=True)
    resolve.add_argument("--run-id", required=True)
    resolve.add_argument("--request", required=True)
    resolve.set_defaults(handler=_resolve)

    audit = commands.add_parser("audit")
    audit.add_argument("--profile", required=True)
    audit.add_argument("--run-id", required=True)
    audit.add_argument("--input", required=True)
    audit.set_defaults(handler=_audit_command)

    adapter = commands.add_parser("adapter", help="Generate trusted adapter inputs.")
    adapter_commands = adapter.add_subparsers(dest="adapter_command", required=True)
    flutter = adapter_commands.add_parser("flutter")
    flutter_commands = flutter.add_subparsers(dest="flutter_command", required=True)
    flutter_config = flutter_commands.add_parser("config")
    flutter_config.add_argument("--profile", required=True)
    flutter_config.add_argument("--run-id", required=True)
    flutter_config.add_argument("--output", required=True)
    flutter_config.set_defaults(handler=_flutter_config_command)

    figma = adapter_commands.add_parser("figma")
    figma_commands = figma.add_subparsers(dest="figma_command", required=True)
    figma_config = figma_commands.add_parser("config")
    figma_config.add_argument("--profile", required=True)
    figma_config.add_argument("--run-id", required=True)
    figma_config.add_argument("--output", required=True)
    figma_config.set_defaults(handler=_figma_config_command)

    ux = commands.add_parser(
        "ux",
        help="Run built-in UX/accessibility evidence checks.",
    )
    ux_commands = ux.add_subparsers(dest="ux_command", required=True)
    ux_checkpoint = ux_commands.add_parser(
        "checkpoint",
        help="Evaluate one completed screen without production authority.",
    )
    ux_checkpoint.add_argument("--profile", required=True)
    ux_checkpoint.add_argument("--run-id", required=True)
    ux_checkpoint.add_argument("--input", required=True)
    ux_checkpoint.set_defaults(handler=_ux_checkpoint_command)

    finalize = commands.add_parser("finalize")
    finalize.add_argument("--profile", required=True)
    finalize.add_argument("--run-id", required=True)
    finalize.add_argument("--audit-result", required=True)
    finalize.add_argument("--build-plan")
    finalize.set_defaults(handler=_finalize_command)

    self_check = commands.add_parser("self-check")
    self_check.add_argument("--profile", required=True)
    self_check.add_argument("--run-id", required=True)
    self_check.set_defaults(handler=_self_check_command)

    elo = commands.add_parser("elo", help="Inspect or evaluate the public synthetic Elo ledger.")
    elo_commands = elo.add_subparsers(dest="elo_command", required=True)
    elo_show = elo_commands.add_parser("show")
    elo_show.set_defaults(handler=_elo_show_command)
    elo_migrate_legacy = elo_commands.add_parser(
        "migrate",
        help="Migrate one exact pre-Elo 0.2 trust home to sealed score-one genesis.",
    )
    elo_migrate_legacy.set_defaults(handler=_elo_migrate_legacy_command)
    elo_benchmark = elo_commands.add_parser("benchmark")
    elo_benchmark.add_argument("--target-root", required=True)
    elo_benchmark.add_argument("--output")
    elo_benchmark.set_defaults(handler=_elo_benchmark_command)
    elo_evaluate = elo_commands.add_parser("evaluate")
    elo_evaluate.add_argument("--baseline-result", required=True)
    elo_evaluate.add_argument("--candidate-result", required=True)
    elo_evaluate.set_defaults(handler=_elo_evaluate_command)

    rules = commands.add_parser(
        "rules",
        help="Validate local usage rules as a non-authoritative preview.",
    )
    rules_commands = rules.add_subparsers(dest="rules_command", required=True)
    rules_validate = rules_commands.add_parser("validate")
    rules_validate.add_argument(
        "--format",
        dest="rule_format",
        choices=("artifact", "figma-description"),
        required=True,
    )
    rules_validate.add_argument("--input", required=True)
    rules_validate.add_argument("--known-identities")
    rules_validate.add_argument(
        "--host-kind",
        choices=("system", "category", "component", "icon", "token"),
    )
    rules_validate.add_argument("--host-identity")
    rules_validate.add_argument("--figma-file-key")
    rules_validate.add_argument("--figma-node-id")
    rules_validate.add_argument("--figma-source-version")
    rules_validate.set_defaults(handler=_rules_validate_command)
    rules_activate = rules_commands.add_parser(
        "activate",
        help="Preview or apply one permission-bound v2 rule-snapshot activation.",
    )
    rules_activate_commands = rules_activate.add_subparsers(
        dest="rules_activate_command",
        required=True,
    )
    rules_activate_preview = rules_activate_commands.add_parser(
        "preview",
        help="Verify one signed catalog v2 and return an exact permission request.",
    )
    rules_activate_preview.add_argument("--profile", required=True)
    rules_activate_preview.add_argument("--input", required=True)
    rules_activate_preview.set_defaults(handler=_rules_activate_preview_command)
    rules_activate_apply = rules_activate_commands.add_parser(
        "apply",
        help="Apply a previously previewed activation only with exact granted permission.",
    )
    rules_activate_apply.add_argument("--input", required=True)
    rules_activate_apply.set_defaults(handler=_rules_activate_apply_command)

    migrate = commands.add_parser("migrate")
    migrate.add_argument("--profile", required=True)
    migrate.add_argument("--artifact", required=True)
    migrate.set_defaults(handler=_migrate_command)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
        return int(args.handler(args))
    except (
        AdapterDispatchError,
        FlutterAdapterUnsupportedError,
        FlutterRunnerUnsupportedError,
    ) as error:
        _emit(
            {
                "error": error.__class__.__name__,
                "message": str(error),
                "status": ResolutionStatus.UNSUPPORTED.value,
            },
            error=True,
        )
        return int(ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE)
    except FigmaAdapterSourceError as error:
        _emit(
            {
                "schemaVersion": 1,
                "status": error.status,
                "stage": "figma_source",
                "reasonCode": f"figma_{error.status}",
                "message": str(error),
                "localChangesPerformed": False,
                "nextAction": "refresh_the_exact_allowlisted_figma_source",
            },
            error=True,
        )
        return int(ExitCode.SOURCE_UNAVAILABLE_STALE_OR_INCOMPLETE)
    except (FigmaAdapterIntegrityError, UxEvaluationIntegrityError) as error:
        stage = (
            "figma_audit"
            if isinstance(error, FigmaAdapterIntegrityError)
            else "ux_evaluation"
        )
        _emit(
            {
                "schemaVersion": 1,
                "status": ResolutionStatus.INVALID.value,
                "stage": stage,
                "reasonCode": f"{stage}_invalid",
                "message": str(error),
                "localChangesPerformed": False,
                "nextAction": "collect_complete_evidence_with_the_shipped_guardian_contract",
            },
            error=True,
        )
        return int(ExitCode.INVALID_POLICY_CONFIG_OR_INTEGRITY)
    except OnboardingError as error:
        _emit(
            {
                "schemaVersion": 1,
                "status": ResolutionStatus.INVALID.value,
                "stage": "setup",
                "reasonCode": "onboarding_invalid",
                "message": str(error),
                "permissionRequired": False,
                "localChangesPerformed": False,
                "nextAction": "correct_or_replace_the_local_onboarding_bundle",
            },
            error=True,
        )
        return int(ExitCode.INVALID_POLICY_CONFIG_OR_INTEGRITY)
    except GuardianError as error:
        _emit(error.evidence(), error=True)
        return int(error.exit_code)
    except (ProfileValidationError, SnapshotValidationError, DtcgValidationError, PreflightError, ValueError) as error:
        wrapped = PolicyIntegrityError(f"Guardian configuration is invalid: {error}")
        _emit(wrapped.evidence(), error=True)
        return int(wrapped.exit_code)
    except OSError as error:
        wrapped = PolicyIntegrityError(f"Guardian filesystem operation failed: {error}")
        _emit(wrapped.evidence(), error=True)
        return int(wrapped.exit_code)


if __name__ == "__main__":
    raise SystemExit(main())
