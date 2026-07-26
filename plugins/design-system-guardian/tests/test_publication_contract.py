from __future__ import annotations

import hashlib
import json
import struct
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = PLUGIN_ROOT.parents[1]
POLICY_DIGEST = "3bf2913583cee2d791aed5093bc1df905b26dcdbb0c4d945f0ae5b2eddaaa99f"


class PublicationContractTests(unittest.TestCase):
    def test_g2_brand_assets_are_sealed(self) -> None:
        brand = PLUGIN_ROOT / "assets/brand"
        names = (
            "guardian-mark.svg",
            "guardian-mark-dark.svg",
            "guardian-lockup.svg",
            "guardian-avatar.png",
            "guardian-social-preview.png",
        )
        manifest = json.loads((brand / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(set(manifest["assets"]), set(names))
        for name in names:
            payload = (brand / name).read_bytes()
            self.assertEqual(hashlib.sha256(payload).hexdigest(), manifest["assets"][name])

    def test_g2_mark_preserves_approved_semantics(self) -> None:
        svg = (PLUGIN_ROOT / "assets/brand/guardian-mark.svg").read_text(encoding="utf-8")
        ET.fromstring(svg)
        self.assertIn('viewBox="0 0 240 240"', svg)
        self.assertEqual(svg.count('data-role="token"'), 12)
        self.assertEqual(svg.count('data-kind="approved"'), 11)
        self.assertEqual(svg.count('data-kind="sentinel"'), 1)
        self.assertEqual(svg.count("<circle"), 3)
        for color in ("#3157D8", "#6D28D9", "#FF4D67", "#FFCCD4", "#C7D2FE", "#D8E0EF"):
            self.assertIn(color, svg)
        self.assertNotIn("filter=", svg)

    def test_brand_png_dimensions_are_exact(self) -> None:
        def png_size(path: Path) -> tuple[int, int]:
            payload = path.read_bytes()
            self.assertEqual(payload[:8], b"\x89PNG\r\n\x1a\n")
            return struct.unpack(">II", payload[16:24])

        brand = PLUGIN_ROOT / "assets/brand"
        self.assertEqual(png_size(brand / "guardian-avatar.png"), (512, 512))
        self.assertEqual(png_size(brand / "guardian-social-preview.png"), (1280, 640))
    def test_test_requirements_are_exact(self) -> None:
        self.assertEqual(
            (PLUGIN_ROOT / "requirements-test.txt").read_text(encoding="utf-8"),
            "-r requirements.txt\njsonschema==4.26.0\nPyYAML==6.0.3\n",
        )
        ignored = set(
            (REPOSITORY_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        )
        self.assertTrue(
            {
                "docs/superpowers/",
                ".venv/",
                "node_modules/",
                ".dart_tool/",
                "build/",
                "dist/",
                "coverage/",
                "*.log",
                ".superpowers/brainstorm/",
                ".superpowers/sdd/",
            }.issubset(ignored)
        )

    def test_marketplace_manifest_version_and_skill_surface(self) -> None:
        marketplace = json.loads(
            (REPOSITORY_ROOT / ".agents/plugins/marketplace.json").read_text(encoding="utf-8")
        )
        self.assertEqual(marketplace["name"], "pv-vimalnair-design-system-guardian")
        self.assertEqual(marketplace["interface"], {"displayName": "Design System Guardian"})
        self.assertEqual(len(marketplace["plugins"]), 1)
        entry = marketplace["plugins"][0]
        self.assertEqual(entry["name"], "design-system-guardian")
        self.assertEqual(entry["source"], {"source": "local", "path": "./plugins/design-system-guardian"})
        self.assertEqual(entry["policy"], {"installation": "AVAILABLE", "authentication": "ON_INSTALL"})
        self.assertEqual(entry["category"], "Developer Tools")

        manifest = json.loads(
            (PLUGIN_ROOT / ".codex-plugin/plugin.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["name"], "design-system-guardian")
        self.assertEqual(manifest["version"], "0.3.4")
        self.assertEqual(manifest["license"], "MIT")
        self.assertNotIn("hooks", manifest)
        self.assertEqual(manifest["interface"]["brandColor"], "#3157D8")
        for key in ("composerIcon", "logo", "logoDark"):
            target = (PLUGIN_ROOT / manifest["interface"][key]).resolve()
            self.assertTrue(target.is_file())
            self.assertTrue(target.is_relative_to(PLUGIN_ROOT.resolve()))

        skills = sorted(path.name for path in (PLUGIN_ROOT / "skills").iterdir() if path.is_dir())
        self.assertEqual(skills, ["audit-design-system", "build-with-design-system"])
        from guardian_core.release import RUNTIME_VERSION
        self.assertEqual(RUNTIME_VERSION, manifest["version"])
        pubspec = (PLUGIN_ROOT / "adapters/flutter/pubspec.yaml").read_text(encoding="utf-8")
        self.assertIn("version: 0.3.4", pubspec)
        self.assertIn("analyzer_testing: 0.3.3", pubspec)

    def test_v034_release_page_describes_supported_lanes_and_preview_scope(self) -> None:
        readme = (REPOSITORY_ROOT / "README.md").read_text(encoding="utf-8")
        for phrase in (
            "exact Figma binding",
            "approved duplicate",
            "quick screen checkpoint",
            "final-flow",
            "protected production authority",
            "preview-only",
            "guardian rules validate",
            "not consumed by audit or finalization",
            "productionReady=false",
            "Skills are portable; automatic routing is not.",
            "Guardian cannot prevent raw-tool bypass",
            "Clean caller-carried Figma or UX evidence remains `not_assessed` until protected host attestation.",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, readme)

        plugin_readme = (PLUGIN_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("inside Guardian local state", plugin_readme)
        self.assertIn("guardian rules validate", plugin_readme)
        self.assertIn("not consumed by audit or finalization", plugin_readme)
        self.assertNotIn('"projectRoot": null', plugin_readme)

        changelog = (PLUGIN_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertLess(changelog.index("## 0.3.4"), changelog.index("## 0.3.3"))

    def test_release_pages_describe_opt_in_runtime_bootstrap_honestly(self) -> None:
        pages = {
            "root": (REPOSITORY_ROOT / "README.md").read_text(encoding="utf-8"),
            "plugin": (PLUGIN_ROOT / "README.md").read_text(encoding="utf-8"),
        }
        for page_name, page in pages.items():
            with self.subTest(page=page_name):
                self.assertIn("--bootstrap-runtime", page)
                self.assertIn("explicit permission", page)
                self.assertIn("Python 3.11", page)
                self.assertIn("isolated Guardian-owned virtual environment", page)
                self.assertIn("bundled `requirements.txt`", page)
                self.assertIn("host remains `unsupported`", page)
                self.assertIn("fail closed", page)
                self.assertIn("does not create an always-on protected route", page)
                self.assertNotIn("zero prerequisites", page.lower())
                self.assertNotIn("no prerequisites", page.lower())

    def test_repository_page_and_mit_license(self) -> None:
        readme = (REPOSITORY_ROOT / "README.md").read_text(encoding="utf-8")
        headings = (
            "## The rule that cannot be overwritten",
            "## Two skills, one guardian",
            "## Build and audit workflow",
            "## Missing means conspicuous",
            "## Architecture and trust boundary",
            "## Flutter-first support",
            "## Install on Codex and other agents",
            "## CLI and exit codes",
            "## Verification",
            "## Security and private data",
            "## Versioning and license",
        )
        positions = [readme.index(heading) for heading in headings]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("source publication is not a trusted stable release", readme.lower())
        self.assertIn(POLICY_DIGEST, readme)
        self.assertIn("<picture>", readme)
        self.assertIn('media="(prefers-color-scheme: dark)"', readme)
        self.assertIn("plugins/design-system-guardian/assets/brand/guardian-mark-dark.svg", readme)
        self.assertIn("plugins/design-system-guardian/assets/brand/guardian-mark.svg", readme)
        self.assertIn('width="180"', readme)

        license_text = (REPOSITORY_ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertTrue(license_text.startswith("MIT License\n\nCopyright (c) 2026 Pv Vimal Nair"))
        self.assertIn("THE SOFTWARE IS PROVIDED \"AS IS\"", license_text)

    def test_ci_whitespace_gate_checks_the_event_range(self) -> None:
        workflow = (REPOSITORY_ROOT / ".github/workflows/validate.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("fetch-depth: 0", workflow)
        self.assertIn("- name: Reject whitespace errors in changed range", workflow)
        self.assertIn("${{ github.event_name }}", workflow)
        self.assertIn("${{ github.event.pull_request.base.sha }}", workflow)
        self.assertIn("${{ github.event.pull_request.head.sha }}", workflow)
        self.assertIn("${{ github.event.before }}", workflow)
        self.assertIn("${{ github.sha }}", workflow)
        self.assertIn("0000000000000000000000000000000000000000", workflow)
        self.assertIn("git hash-object -t tree /dev/null", workflow)
        self.assertIn('git diff --check "$base" "$head"', workflow)
        self.assertNotIn("run: git diff --check", workflow)
if __name__ == "__main__":
    unittest.main()
