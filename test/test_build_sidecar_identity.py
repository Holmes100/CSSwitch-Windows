import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class BuildSidecarIdentityTest(unittest.TestCase):
    def test_external_target_dir_cannot_stage_stale_default_gateway(self):
        rustc = os.environ.get("RUSTC") or shutil.which("rustc")
        self.assertIsNotNone(rustc, "controlled test PATH must provide rustc")
        target = "aarch64-apple-darwin"
        with tempfile.TemporaryDirectory(prefix="csswitch-build-sidecar-") as raw:
            temp = Path(raw)
            manifest_dir = temp / "desktop" / "src-tauri"
            gateway_dir = temp / "desktop" / "gateway"
            manifest_dir.mkdir(parents=True)
            (gateway_dir / "src").mkdir(parents=True)
            (gateway_dir / "Cargo.toml").write_text(
                "[package]\nname='fake-gateway'\nversion='0.0.0'\n",
                encoding="utf-8",
            )

            stub = temp / "tauri_build.rs"
            stub.write_text("pub fn build() {}\n", encoding="utf-8")
            stub_rlib = temp / "libtauri_build.rlib"
            subprocess.run(
                [
                    rustc,
                    "--edition=2021",
                    "--crate-name",
                    "tauri_build",
                    "--crate-type",
                    "rlib",
                    str(stub),
                    "-o",
                    str(stub_rlib),
                ],
                check=True,
                cwd=ROOT,
                capture_output=True,
            )
            build_script = temp / "desktop-build-script"
            subprocess.run(
                [
                    rustc,
                    "--edition=2021",
                    str(ROOT / "desktop" / "src-tauri" / "build.rs"),
                    "--extern",
                    f"tauri_build={stub_rlib}",
                    "-o",
                    str(build_script),
                ],
                check=True,
                cwd=ROOT,
                capture_output=True,
            )

            current_bytes = b"CURRENT-NESTED-GATEWAY\n"
            decoy_bytes = b"STALE-DEFAULT-GATEWAY\n"
            default_binary = (
                gateway_dir
                / "target"
                / target
                / "release"
                / "csswitch-gateway"
            )
            default_binary.parent.mkdir(parents=True)
            default_binary.write_bytes(decoy_bytes)

            fake_cargo = temp / "fake-cargo"
            fake_cargo.write_text(
                """#!/usr/bin/python3
import os
from pathlib import Path
import sys

args = sys.argv[1:]
target = args[args.index("--target") + 1]
target_root = Path(os.environ["CARGO_TARGET_DIR"])
binary = target_root / target / "release" / "csswitch-gateway"
binary.parent.mkdir(parents=True, exist_ok=True)
binary.write_bytes(b"CURRENT-NESTED-GATEWAY\\n")
binary.chmod(0o700)
""",
                encoding="utf-8",
            )
            fake_cargo.chmod(
                fake_cargo.stat().st_mode
                | stat.S_IXUSR
                | stat.S_IXGRP
                | stat.S_IXOTH
            )

            out_dir = temp / "desktop-out"
            external_target = temp / "external-parent-target"
            env = os.environ.copy()
            env.update(
                {
                    "CARGO": str(fake_cargo),
                    "CARGO_MANIFEST_DIR": str(manifest_dir),
                    "CARGO_TARGET_DIR": str(external_target),
                    "OUT_DIR": str(out_dir),
                    "TARGET": target,
                }
            )
            subprocess.run(
                [str(build_script)],
                check=True,
                cwd=manifest_dir,
                env=env,
                capture_output=True,
            )

            built = (
                out_dir
                / "gateway-target"
                / target
                / "release"
                / "csswitch-gateway"
            )
            staged = (
                manifest_dir
                / "binaries"
                / f"csswitch-gateway-{target}"
            )
            self.assertTrue(built.is_file(), "this Desktop build must own one nested target root")
            self.assertEqual(built.read_bytes(), current_bytes)
            self.assertEqual(staged.read_bytes(), current_bytes)
            self.assertNotEqual(staged.read_bytes(), decoy_bytes)
            self.assertEqual(default_binary.read_bytes(), decoy_bytes)


if __name__ == "__main__":
    unittest.main()
