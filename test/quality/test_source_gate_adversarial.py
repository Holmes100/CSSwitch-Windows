"""Private fault-injection matrix for source adapter transport/supervision."""
from __future__ import annotations

import os
import hashlib
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from test.quality.run_evidence import attempt0_runner
from test.quality.run_evidence.attempt0_runner import (
    Attempt0RunnerError,
    copy_snapshot_bound_file,
    supervise_raw_command,
)
from test.quality.run_evidence.atomic_store import create_run_layout
from test.quality.run_evidence.manifest_contracts import canonical_json_bytes


FRAME_VALUE = {"schema": "fake-observation.v1", "value": "PASS"}
FRAME_RAW = canonical_json_bytes(FRAME_VALUE)
FRAME = len(FRAME_RAW).to_bytes(4, "big") + FRAME_RAW
CONFIG = len(b"{}\n").to_bytes(4, "big") + b"{}\n"
REPO_ROOT = Path(__file__).resolve().parents[2]


class SourceGateAdversarial(unittest.TestCase):
    def _run(self, program, *, timeout=1.0):
        return supervise_raw_command(
            argv=(
                os.path.realpath(os.sys.executable),
                "-I",
                "-S",
                "-c",
                program,
            ),
            environment={"PATH": os.defpath},
            timeout_seconds=timeout,
            output_limit_bytes=4096,
            framed_config=CONFIG,
        )

    def test_01_missing_malformed_extra_and_replayed_observations_fail(self):
        cases = {
            "missing": "raise SystemExit(12)",
            "malformed": (
                "import os;os.write(199,b'\\x00\\x00\\x00\\x01x')"
            ),
            "extra": (
                "import os;"
                f"os.write(199,{FRAME + FRAME!r})"
            ),
            "replayed": (
                "import os;"
                f"os.write(199,{FRAME!r});"
                f"os.write(199,{FRAME!r})"
            ),
        }
        for name, program in cases.items():
            with self.subTest(name=name):
                result = self._run(program)
                self.assertFalse(result.observation_acked)
                self.assertIn(
                    result.observation_error,
                    {"ADAPTER_MISSING", "ADAPTER_MALFORMED"},
                )

    def test_02_note_exit_makes_descendant_observation_late(self):
        program = (
            "import os,time\n"
            "if os.fork()==0:\n"
            " time.sleep(0.08)\n"
            f" os.write(199,{FRAME!r})\n"
            " time.sleep(0.02)\n"
            " os._exit(0)\n"
            "os.close(199)\n"
            "os._exit(0)\n"
        )
        signal_calls = []
        with mock.patch.object(
            attempt0_runner,
            "_signal_group",
            side_effect=lambda pid, sig: signal_calls.append((pid, sig)),
        ):
            result = self._run(program)
        self.assertTrue(signal_calls)
        self.assertEqual(result.observation_error, "ADAPTER_LATE")
        self.assertFalse(result.observation_acked)

    def test_03_descendant_fd_holder_is_killed_and_terminally_drained(self):
        program = (
            "import os,time\n"
            f"os.write(199,{FRAME!r})\n"
            "assert os.read(199,4)==b'ACK!'\n"
            "if os.fork()==0:\n"
            " time.sleep(5)\n"
            " os._exit(0)\n"
            "os._exit(0)\n"
        )
        started = time.monotonic()
        result = self._run(program)
        elapsed = time.monotonic() - started
        self.assertEqual(result.observation, FRAME_VALUE)
        self.assertTrue(result.observation_acked)
        self.assertLess(elapsed, 1.0)

    def test_04_escaped_fd_holder_causes_incomplete_terminal_drain(self):
        program = (
            "import os,time\n"
            f"os.write(199,{FRAME!r})\n"
            "assert os.read(199,4)==b'ACK!'\n"
            "if os.fork()==0:\n"
            " os.setsid()\n"
            " time.sleep(0.55)\n"
            " os._exit(0)\n"
            "os._exit(0)\n"
        )
        with self.assertRaises(Attempt0RunnerError) as raised:
            self._run(program)
        self.assertEqual(
            raised.exception.code, "TERMINAL_DRAIN_INCOMPLETE",
        )
        time.sleep(0.35)

    def test_05_stdout_pass_text_is_never_observation_authority(self):
        result = self._run(
            "import sys;sys.stdout.write('PASS\\n');raise SystemExit(7)",
        )
        self.assertEqual(
            result.raw_process, {"state": "EXITED", "process_exit": 7},
        )
        self.assertEqual(result.stdout, b"PASS\n")
        self.assertIsNone(result.observation)
        self.assertEqual(result.observation_error, "ADAPTER_MISSING")

    def test_06_bound_adapter_fd_defeats_cache_name_rebind(self):
        with tempfile.TemporaryDirectory(
            dir=os.path.realpath(tempfile.gettempdir()),
        ) as temp:
            root = Path(temp)
            state_root = root / "state"
            evidence_root = root / "evidence"
            state_root.mkdir(mode=0o700)
            evidence_root.mkdir(mode=0o700)
            layout = create_run_layout(
                str(state_root), str(evidence_root),
            )
            adapter_path = (
                REPO_ROOT / "test/quality/source_gate/adapter.py"
            )
            adapter_raw = adapter_path.read_bytes()
            adapter_stat = adapter_path.stat()
            logical = "test/quality/source_gate/adapter.py"
            snapshot = {
                "schema": "source-snapshot-manifest.v1",
                "run_id": layout.run_id,
                "head_sha": "a" * 40,
                "snapshot_mode": "clean-commit",
                "entry_count": 1,
                "total_bytes": len(adapter_raw),
                "entries": [{
                    "path": logical,
                    "type": "file",
                    "mode": (
                        "100755"
                        if adapter_stat.st_mode & 0o111
                        else "100644"
                    ),
                    "size": len(adapter_raw),
                    "sha256": hashlib.sha256(adapter_raw).hexdigest(),
                }],
            }
            with layout.snapshot_capture_lease() as lease:
                ticket = layout.publish_snapshot_manifest(
                    snapshot,
                    expected_head_sha="a" * 40,
                    lease=lease,
                )
                layout.linearize_snapshot_success(ticket, lease=lease)
            held_fd = copy_snapshot_bound_file(
                repo_root=str(REPO_ROOT),
                layout=layout,
                snapshot=snapshot,
                logical_path=logical,
                cache_leaf="source-adapter.py",
            )
            try:
                cache = Path(layout.state_path) / "cache"
                replacement = cache / "replacement"
                replacement.write_text("raise SystemExit(99)\n")
                os.chmod(replacement, 0o600)
                os.replace(replacement, cache / "source-adapter.py")
                config = {
                    "schema": "source-adapter-config.v1",
                    "run_id": "0123456789abcdef0123456789abcdef",
                    "suite_id": "SUITE-QUALITY-METADATA",
                    "entrypoint_id": "ENTRY-SOURCE-QUALITY-METADATA",
                    "kind": "meta",
                    "argv": ["/usr/bin/true"],
                    "environment": {"PATH": os.defpath},
                    "timeout_seconds": 1,
                    "output_limit_bytes": 4096,
                    "expected_test_ids": ["command:metadata-validator"],
                    "approved_skipped_test_ids": [],
                    "approved_ignored_test_ids": [],
                    "approved_ignored_tests": {},
                    "command_argv_sha256": "0" * 64,
                    "environment_sha256": "0" * 64,
                    "tool_identity_sha256": "0" * 64,
                    "driver_config": None,
                }
                config_raw = canonical_json_bytes(config)
                bootstrap = (
                    "import os;"
                    "os.lseek(198,0,0);"
                    "p='/dev/fd/198';"
                    "exec(compile(open(p,'rb').read(),p,'exec'))"
                )
                result = supervise_raw_command(
                    argv=(
                        os.path.realpath(os.sys.executable),
                        "-I",
                        "-c",
                        bootstrap,
                        "--config-fd",
                        "197",
                        "--observation-fd",
                        "199",
                    ),
                    environment={
                        "HOME": str(root),
                        "PATH": os.defpath,
                    },
                    timeout_seconds=3,
                    output_limit_bytes=4096,
                    framed_config=(
                        len(config_raw).to_bytes(4, "big") + config_raw
                    ),
                    inherited_fds=((held_fd, 198),),
                )
                self.assertEqual(
                    result.raw_process,
                    {"state": "EXITED", "process_exit": 0},
                )
                self.assertTrue(result.observation_acked)
                self.assertEqual(
                    result.observation["raw_process"],
                    {"state": "EXITED", "process_exit": 0},
                )
            finally:
                os.close(held_fd)
                layout.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
