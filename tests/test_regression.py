"""Frozen Phase 1 behavior remains a contract across architecture changes."""

import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from eits.cli import serialize
from eits.evaluation import evaluate
from eits.model import digest

ROOT = Path(__file__).resolve().parents[1]


class PhaseOneRegressionTests(unittest.TestCase):
    def test_saved_findings_scores_and_input_hashes_are_reproduced(self):
        # Runtime hashes/versions must describe the refactor, not impersonate the
        # original implementation. All observable detection results stay exact.
        manifest_path = ROOT / "fixtures/aws/synthetic/manifest.json"
        manifest_bytes = manifest_path.read_bytes()
        self.assertEqual(json.loads(manifest_bytes)["license"], "LicenseRef-Proprietary")
        # Only the license label changed since Phase 1. Reconstruct the historical
        # bytes in memory so the frozen report still guards every other field.
        historical_manifest_bytes = manifest_bytes.replace(
            b'"license": "LicenseRef-Proprietary"', b'"license": "MIT"', 1
        )
        preserved_fields = (
            "rule_revision",
            "split",
            "dataset_id",
            "ground_truth_sha256",
            "ingestion",
            "sql_sha256",
            "evidence_events_verified",
            "rules",
            "findings",
        )
        for revision in ("baseline", "restart-aware"):
            with self.subTest(revision=revision):
                expected = json.loads((ROOT / f"evaluation/phase1-{revision}.json").read_text())
                result = evaluate(
                    manifest_path,
                    ROOT / "evaluation/ground_truth.json",
                    revision=revision,
                )
                actual = json.loads(json.dumps(result, default=serialize))
                self.assertEqual(actual["manifest_sha256"], digest(manifest_bytes))
                self.assertEqual(expected["manifest_sha256"], digest(historical_manifest_bytes))
                for field in preserved_fields:
                    with self.subTest(field=field):
                        self.assertEqual(actual[field], expected[field])

    def test_published_reports_remain_immutable(self):
        expected = {
            "baseline": "199302289a73e846477c8d830f219ccbd41a919f1b10cf3846aaf05cf0050a2d",
            "restart-aware": "fe134db14bedcda58c5bdd3d427d5de25e238b8e3a9fcb6eabfe71ca5e13b84e",
        }
        for revision, sha in expected.items():
            with self.subTest(revision=revision):
                path = ROOT / f"evaluation/phase1-{revision}.json"
                self.assertEqual(digest(path.read_bytes()), sha)

    def test_generator_recreates_original_corpus_and_labels(self):
        spec = importlib.util.spec_from_file_location(
            "phase1_generator", ROOT / "scripts/generate_synthetic.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            generated = Path(directory)
            (generated / "fixtures/aws/synthetic").mkdir(parents=True)
            (generated / "evaluation").mkdir()
            module.ROOT = generated
            with redirect_stdout(io.StringIO()):
                module.main()
            expected_paths = list((ROOT / "fixtures/aws/synthetic").glob("*.json"))
            expected_paths.append(ROOT / "evaluation/ground_truth.json")
            for expected_path in expected_paths:
                relative = expected_path.relative_to(ROOT)
                with self.subTest(path=str(relative)):
                    self.assertEqual(
                        (generated / relative).read_bytes(), expected_path.read_bytes()
                    )


if __name__ == "__main__":
    unittest.main()
