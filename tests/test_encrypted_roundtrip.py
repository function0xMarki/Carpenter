import os
import hashlib
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "carpenter.py"
HAS_7Z = shutil.which("7z") is not None
HAS_PYZIPPER = importlib.util.find_spec("pyzipper") is not None


@unittest.skipUnless(HAS_PYZIPPER, "pyzipper is required for encrypted roundtrip tests")
class EncryptedRoundtripTest(unittest.TestCase):
    def run_cli(self, args, user_input):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            input=user_input,
            text=True,
            capture_output=True,
            cwd=REPO_ROOT,
            timeout=120,
            start_new_session=True,
        )
        if proc.returncode != 0:
            self.fail(
                "CLI command failed:\n"
                f"args={args}\n"
                f"stdout:\n{proc.stdout}\n"
                f"stderr:\n{proc.stderr}"
            )
        return proc

    def run_7z(self, args):
        proc = subprocess.run(
            ["7z", *args],
            text=True,
            capture_output=True,
            cwd=REPO_ROOT,
            timeout=120,
        )
        if proc.returncode != 0:
            self.fail(
                "7z command failed:\n"
                f"args={args}\n"
                f"stdout:\n{proc.stdout}\n"
                f"stderr:\n{proc.stderr}"
            )
        return proc

    def test_encrypted_split_and_join_roundtrip_for_multiple_files(self):
        password = "s3cure-P@ss!123"
        fixtures = [
            ("alpha.txt", (b"The quick brown fox jumps over the lazy dog.\n" * 700)),
            ("blob.bin", os.urandom(65536)),
        ]

        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)

            for filename, payload in fixtures:
                source_path = tmpdir / filename
                source_path.write_bytes(payload)

                split_input = f"3\ny\n{password}\n{password}\n"
                self.run_cli(["-split", str(source_path)], split_input)

                parts_dir = source_path.parent / source_path.stem
                self.assertTrue(parts_dir.is_dir(), f"Expected split output dir: {parts_dir}")

                first_data_part = parts_dir / f"{source_path.stem}_1.zip"
                self.assertTrue(first_data_part.exists(), f"Missing first part: {first_data_part}")

                if HAS_7Z:
                    for zip_part in sorted(parts_dir.glob("*.zip")):
                        self.run_7z(["t", f"-p{password}", str(zip_part)])

                # Ensure join has to recreate the file from fragments.
                source_path.unlink()
                self.assertFalse(source_path.exists())

                # Prompts expected in encrypted join flow:
                # 1) password, 2) change name (blank=keep original), 3) delete fragments.
                join_input = f"{password}\n\nn\n"
                self.run_cli(["-join", str(first_data_part)], join_input)

                restored_path = parts_dir / source_path.name
                restored = restored_path.read_bytes()
                self.assertEqual(
                    restored,
                    payload,
                    f"Roundtrip mismatch for {filename}",
                )

    @unittest.skipUnless(HAS_7Z, "7z is required for 7z interoperability test")
    def test_join_can_read_7z_generated_encrypted_sequence(self):
        password = "7z-interop-pass!"
        source_name = "interop.bin"
        payload = os.urandom(98304) + b"\nINTEROP\n"
        num_parts = 3
        part_size = len(payload) // num_parts
        data_parts = [payload[i * part_size:(i + 1) * part_size] for i in range(num_parts - 1)]
        data_parts.append(payload[(num_parts - 1) * part_size:])

        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            base_name = Path(source_name).stem
            output_dir = tmpdir / base_name
            output_dir.mkdir()

            width = len(str(num_parts))
            md5 = hashlib.md5(payload).hexdigest()
            md5_bytes = f"{md5}  {source_name}\n".encode("utf-8")

            def make_7z_zip(part_index, content):
                part_name = f"{base_name}_{str(part_index).zfill(width)}.zip"
                zip_path = output_dir / part_name
                temp_raw = output_dir / f".tmp_{part_index}"
                temp_raw.write_bytes(content)
                self.run_7z([
                    "a",
                    "-tzip",
                    "-bso0",
                    "-bsp0",
                    f"-p{password}",
                    "-mem=AES256",
                    str(zip_path),
                    str(temp_raw),
                ])
                temp_raw.unlink()

            make_7z_zip(0, md5_bytes)
            for idx, part_bytes in enumerate(data_parts, start=1):
                make_7z_zip(idx, part_bytes)

            join_input = f"{password}\n\nn\n"
            first_data_part = output_dir / f"{base_name}_{str(1).zfill(width)}.zip"
            self.run_cli(["-join", str(first_data_part)], join_input)

            restored_path = output_dir / source_name
            self.assertTrue(restored_path.exists(), f"Missing restored file: {restored_path}")
            self.assertEqual(restored_path.read_bytes(), payload, "Interop roundtrip mismatch")


if __name__ == "__main__":
    unittest.main()
