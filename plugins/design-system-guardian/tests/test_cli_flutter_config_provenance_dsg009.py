import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tests.test_audit_dsg003 import allowed_ux_check
from tests.test_cli_lifecycle_dsg003 import invoke, write_canonical
from tests.test_flutter_adapter_normalization_dsg003 import clean_flutter_result
from tests.test_flutter_config_dsg008 import fully_mapped_catalog, provision_pin


class FlutterConfigProvenanceTest(unittest.TestCase):
    def test_audit_rejects_self_consistent_hand_broadened_config(self) -> None:
        from guardian_core.canonical import sha256_digest
        from guardian_core.cli import main

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            home.mkdir()
            pin = provision_pin(home, fully_mapped_catalog(), run_id="run-forged-config")
            output = home / "private" / "generated.json"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                patch("guardian_core.cli.default_guardian_home", return_value=home),
                patch("guardian_core.flutter_config.default_guardian_home", return_value=home),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                generate_code = main(
                    [
                        "adapter",
                        "flutter",
                        "config",
                        "--profile",
                        "example-company",
                        "--run-id",
                        "run-forged-config",
                        "--output",
                        str(output),
                    ]
                )
            self.assertEqual(generate_code, 0, stderr.getvalue())
            generated = json.loads(output.read_text(encoding="utf-8"))

            forged = copy.deepcopy(generated)
            forged["approvedIdentities"]["colors"].append(
                "package:outside/outside.dart#OutsideColors.sameBlue"
            )
            forged["approvedIdentities"]["colors"].sort()
            unsigned = copy.deepcopy(forged)
            unsigned.pop("configDigest")
            forged["configDigest"] = sha256_digest(unsigned)

            raw = clean_flutter_result(pin)
            raw["binding"]["configDigest"] = forged["configDigest"]
            request_path = root / "forged-audit-request.json"
            write_canonical(
                request_path,
                {
                    "schemaVersion": 1,
                    "adapterConfig": forged,
                    "adapterResult": raw,
                    "resolutions": [],
                    "uxChecks": [allowed_ux_check()],
                },
            )

            audit_code, evidence = invoke(
                home,
                [
                    "audit",
                    "--profile",
                    "example-company",
                    "--run-id",
                    "run-forged-config",
                    "--input",
                    str(request_path),
                ],
            )
            self.assertEqual(audit_code, 2, evidence)
            self.assertEqual(evidence["status"], "invalid")


if __name__ == "__main__":
    unittest.main()
