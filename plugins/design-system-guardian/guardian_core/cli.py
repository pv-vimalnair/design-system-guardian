"""Portable command surface for Design System Guardian."""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Sequence


from .audit import _authoritatively_resolve, evaluate_audit
from .audit_attestation import build_analysis_attestation
from .canonical import canonical_json_text, read_canonical_json, read_json, sha256_digest
from .catalog_authority import verify_pinned_catalog_authority, verify_runtime_dependency
from .contracts import ExitCode, ResolutionStatus
from .dtcg import DtcgValidationError
from .errors import GuardianError, PolicyIntegrityError
from .finalize import finalize_run
from .flutter_adapter import normalize_flutter_adapter_result
from .flutter_config import (
    _generate_flutter_adapter_config_at_home,
    FlutterAdapterUnsupportedError,
    generate_flutter_adapter_config,
    write_flutter_adapter_config,
)
from .flutter_runner import FlutterRunnerUnsupportedError, run_flutter_analysis
from .migrations import default_migration_registry, migrate_to_current
from .paths import GuardianPaths, default_guardian_home
from .policy import TRUST_SCHEMA_VERSION, install_policy_anchor, verify_policy_anchor
from .preflight import PreflightError, load_run_pin, preflight_snapshot
from .project_binding import project_evidence_from_runner, require_requested_project
from .profile import ProfileValidationError, install_profile, load_profile, validate_profile
from .resolver import resolve_identity
from .run_artifacts import seal_run_artifact, write_run_artifact
from .snapshot import SnapshotValidationError, ingest_snapshot


_AUDIT_REQUEST_KEYS = {"schemaVersion", "projectRoot", "resolutions", "uxChecks"}


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
        keys=_AUDIT_REQUEST_KEYS,
        label="Audit request",
    )
    if request.get("schemaVersion") != 1:
        raise ValueError("Audit request schemaVersion must be exactly 1.")
    project_root = request.get("projectRoot")
    if not isinstance(project_root, str) or not project_root.strip() or project_root.strip() != project_root:
        raise ValueError("Audit request projectRoot must be one exact non-empty path.")
    project_binding = require_requested_project(
        context["pin"]["projectBinding"], project_root
    )
    expected_config = _generate_flutter_adapter_config_at_home(
        home,
        profile_id=args.profile,
        run_id=args.run_id,
    )
    resolutions = request.get("resolutions")
    ux_checks = request.get("uxChecks")
    if not isinstance(resolutions, list) or not isinstance(ux_checks, list):
        raise ValueError("Audit resolutions and uxChecks must be arrays.")
    authoritative, _, _ = _authoritatively_resolve(
        resolutions,
        pin=context["pin"],
        verified_snapshot=context["snapshot"],
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
    project_evidence = project_evidence_from_runner(
        project_binding, runner_evidence.get("project")
    )
    normalized = normalize_flutter_adapter_result(
        runner_evidence.get("adapterResult"),
        adapter_config=expected_config,
        run_pin=context["pin"],
    )
    runner_digest = sha256_digest(runner_evidence)
    evaluation = evaluate_audit(
        run_pin=context["pin"],
        adapter_result=normalized,
        resolutions=authoritative,
        ux_checks=ux_checks,
        verified_snapshot=context["snapshot"],
        analysis_attestation_digest=runner_digest,
        project_evidence=project_evidence,
    )
    attestation = build_analysis_attestation(
        run_pin=context["pin"],
        config_digest=expected_config["configDigest"],
        runner_evidence=runner_evidence,
        audit_result=evaluation.result,
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


def _flutter_config_command(args: argparse.Namespace) -> int:
    config = generate_flutter_adapter_config(
        profile_id=args.profile,
        run_id=args.run_id,
    )
    output_path = Path(args.output).expanduser().absolute()
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
            "artifactPaths": paths,
        }
    )
    return int(result.exit_code)


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="guardian")
    commands = parser.add_subparsers(dest="command", required=True)

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

    finalize = commands.add_parser("finalize")
    finalize.add_argument("--profile", required=True)
    finalize.add_argument("--run-id", required=True)
    finalize.add_argument("--audit-result", required=True)
    finalize.add_argument("--build-plan")
    finalize.set_defaults(handler=_finalize_command)

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
    except (FlutterAdapterUnsupportedError, FlutterRunnerUnsupportedError) as error:
        _emit(
            {
                "error": error.__class__.__name__,
                "message": str(error),
                "status": ResolutionStatus.UNSUPPORTED.value,
            },
            error=True,
        )
        return int(ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE)
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
