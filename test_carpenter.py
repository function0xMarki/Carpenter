#!/usr/bin/env python3
"""Black-box test suite for carpenter.py.

Runs carpenter as a subprocess feeding scripted stdin, covering split/join
round-trips (plain and AES ZIP), error paths, sequence-detection edge cases
and the security fixes. Requires pyzipper for the password tests.

Usage:
    python3 test_carpenter.py [path-to-carpenter.py] [--baseline]

With no path, tests the carpenter.py next to this file. --baseline skips
checks for behavior added after the 2026-07 review, so the suite can also
run against older versions (e.g. for cross-version compatibility work).
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CARPENTER = None
BASELINE = False
PASSED = []
FAILED = []


def md5(path):
    h = hashlib.md5()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def run(args, stdin_lines, cwd, timeout=60):
    """Run carpenter with scripted stdin. Returns CompletedProcess.

    On POSIX the child is detached from the controlling terminal (setsid) so
    getpass cannot read from /dev/tty and falls back to the piped stdin.
    """
    inp = "".join(line + "\n" for line in stdin_lines)
    return subprocess.run(
        [sys.executable, CARPENTER] + args,
        input=inp, capture_output=True, text=True, cwd=cwd, timeout=timeout,
        preexec_fn=os.setsid if os.name == "posix" else None,
    )


def make_file(path, size, seed=0):
    data = bytes((i * 7 + seed) % 256 for i in range(size))
    Path(path).write_bytes(data)
    return data


def check(name, cond, detail=""):
    if cond:
        PASSED.append(name)
        print(f"  PASS {name}")
    else:
        FAILED.append(name)
        print(f"  FAIL {name} {detail}")


def fresh_dir():
    return Path(tempfile.mkdtemp(prefix="carp_", dir=os.environ.get("CARP_TMP", None)))


# ---------------------------------------------------------------- tests

def test_plain_roundtrip(nparts, size, label):
    d = fresh_dir()
    src = d / "photo.jpg"
    make_file(src, size)
    orig = md5(src)

    r = run(["--split", str(src)], [str(nparts), "n"], d)
    parts_dir = d / "photo"
    width = len(str(nparts))
    expected = [parts_dir / f"photo_{str(i).zfill(width)}.part" for i in range(nparts + 1)]
    ok = r.returncode == 0 and all(p.exists() for p in expected)
    check(f"{label}: split creates {nparts + 1} files", ok, r.stdout[-300:] + r.stderr[-300:])
    if not ok:
        return

    total = sum(p.stat().st_size for p in expected[1:])
    check(f"{label}: data parts sum to original size", total == size, f"{total} != {size}")

    # join from part 1, keep original name, don't delete fragments
    src.unlink()
    r = run(["--join", str(expected[1])], ["", "n", "n"], d)
    out = parts_dir / "photo.jpg"
    check(f"{label}: join exit 0", r.returncode == 0, r.stdout[-400:] + r.stderr[-200:])
    check(f"{label}: reconstructed md5 matches", out.exists() and md5(out) == orig)
    check(f"{label}: integrity verified in output", "Integrity verified successfully" in r.stdout)
    shutil.rmtree(d)


def test_zip_roundtrip(password, label):
    d = fresh_dir()
    src = d / "video.mp4"
    make_file(src, 50_000, seed=3)
    orig = md5(src)

    r = run(["--split", str(src)], ["4", "y", password, password], d)
    parts_dir = d / "video"
    expected = [parts_dir / f"video_{i}.zip" for i in range(5)]
    ok = r.returncode == 0 and all(p.exists() for p in expected)
    check(f"{label}: split zip ok", ok, r.stdout[-400:] + r.stderr[-200:])
    if not ok:
        return

    src.unlink()
    # join from a middle part; prompts: password, keep name, delete fragments? n
    r = run(["--join", str(expected[2])], [password, "", "n", "n"], d)
    out = parts_dir / "video.mp4"
    check(f"{label}: join zip exit 0", r.returncode == 0, r.stdout[-400:] + r.stderr[-200:])
    check(f"{label}: md5 matches", out.exists() and md5(out) == orig)
    shutil.rmtree(d)


def test_wrong_password():
    d = fresh_dir()
    src = d / "doc.pdf"
    make_file(src, 9_000, seed=5)
    run(["--split", str(src)], ["3", "y", "clave", "clave"], d)
    parts_dir = d / "doc"
    r = run(["--join", str(parts_dir / "doc_1.zip")], ["MALA", "", "n", "n"], d)
    check("wrong password: exit 1", r.returncode == 1, r.stdout[-300:])
    check("wrong password: message", "Wrong password" in r.stdout, r.stdout[-300:])
    check("wrong password: no output file left", not (parts_dir / "doc.pdf").exists())
    shutil.rmtree(d)


def test_join_without_part0(mode):
    d = fresh_dir()
    src = d / "song.mp3"
    make_file(src, 12_345, seed=9)
    orig = md5(src)
    if mode == "zip":
        run(["--split", str(src)], ["3", "y", "pw", "pw"], d)
        ext = ".zip"
        stdin = ["pw", "song.mp3", "n", "n"]
    else:
        run(["--split", str(src)], ["3", "n"], d)
        ext = ".part"
        stdin = ["song.mp3", "n", "n"]
    parts_dir = d / "song"
    (parts_dir / f"song_0{ext}").unlink()
    src.unlink()
    r = run(["--join", str(parts_dir / f"song_1{ext}")], stdin, d)
    out = parts_dir / "song.mp3"
    check(f"no part0 ({mode}): join exit 0", r.returncode == 0, r.stdout[-400:] + r.stderr[-200:])
    check(f"no part0 ({mode}): warning shown", "Checksum file (part 0) not found" in r.stdout)
    check(f"no part0 ({mode}): md5 matches", out.exists() and md5(out) == orig)
    shutil.rmtree(d)


def test_split_errors():
    d = fresh_dir()
    src = d / "tiny.bin"
    make_file(src, 3)
    r = run(["--split", str(src)], ["10", "n"], d)
    check("too many parts: exit 1", r.returncode == 1 and "too small" in r.stdout, r.stdout[-200:])

    empty = d / "empty.bin"
    empty.write_bytes(b"")
    r = run(["--split", str(empty)], [], d)
    check("empty file: exit 1", r.returncode == 1 and "File is empty" in r.stdout, r.stdout[-200:])

    r = run(["--split", str(d / "nope.bin")], [], d)
    check("missing file: exit 1", r.returncode == 1 and "does not exist" in r.stdout, r.stdout[-200:])

    r = run(["--join", str(d / "nofmt.part")], [], d)
    check("join missing file: exit 1", r.returncode == 1, r.stdout[-200:])

    bad = d / "badname.part"
    bad.write_bytes(b"x")
    r = run(["--join", str(bad)], [], d)
    check("join bad pattern: exit 1",
          r.returncode == 1 and "expected pattern" in r.stdout, r.stdout[-200:])
    shutil.rmtree(d)


def test_gap_md5_mismatch():
    """Gap before the given part with part 0 present: MD5 must catch it."""
    d = fresh_dir()
    src = d / "data.bin"
    make_file(src, 30_000, seed=1)
    run(["--split", str(src)], ["5", "n"], d)
    parts_dir = d / "data"
    (parts_dir / "data_3.part").unlink()
    src.unlink()
    r = run(["--join", str(parts_dir / "data_1.part")], ["", "n", "n"], d)
    check("gap: exit 1", r.returncode == 1, r.stdout[-400:])
    check("gap: checksum mismatch reported", "do NOT match" in r.stdout, r.stdout[-400:])
    shutil.rmtree(d)


def test_join_from_part_after_gap():
    """Give a part that sits AFTER a gap. New code must refuse; old code
    silently reconstructs a truncated file ignoring the given part."""
    d = fresh_dir()
    src = d / "data.bin"
    make_file(src, 30_000, seed=2)
    run(["--split", str(src)], ["5", "n"], d)
    parts_dir = d / "data"
    (parts_dir / "data_3.part").unlink()
    src.unlink()
    r = run(["--join", str(parts_dir / "data_5.part")], ["", "n", "n"], d)
    check("gap-after: exit 1", r.returncode == 1, r.stdout[-400:])
    if not BASELINE:
        check("gap-after: refuses before writing",
              "not part of the detected sequence" in r.stdout, r.stdout[-400:])
        check("gap-after: no output file created", not (parts_dir / "data.bin").exists())
    shutil.rmtree(d)


def test_cross_width_contamination():
    """9-part (width 1) and 12-part (width 2) splits of the same base name
    coexist. Joining the width-1 sequence must NOT absorb width-2 parts
    10-12. New code stops at the width boundary and the join succeeds."""
    d = fresh_dir()
    src = d / "mix.bin"
    make_file(src, 40_000, seed=4)
    orig = md5(src)
    r = run(["--split", str(src)], ["12", "n"], d)
    assert r.returncode == 0, r.stdout
    r = run(["--split", str(src)], ["9", "n"], d)
    src.unlink()
    parts_dir = d / "mix"
    r = run(["--join", str(parts_dir / "mix_1.part")], ["", "n", "n"], d)
    if BASELINE:
        # old code appends mix_10..mix_12 -> corruption caught by MD5
        check("cross-width (old): corruption detected", r.returncode == 1
              and "do NOT match" in r.stdout, r.stdout[-400:])
    else:
        out = parts_dir / "mix.bin"
        check("cross-width: join exit 0", r.returncode == 0, r.stdout[-500:])
        check("cross-width: md5 matches", out.exists() and md5(out) == orig)
    shutil.rmtree(d)


def test_stale_parts_prompt():
    """Split into 5, then into 3 (same width): new code must detect stale
    parts 4-5 and offer to delete them."""
    d = fresh_dir()
    src = d / "st.bin"
    make_file(src, 20_000, seed=6)
    orig = md5(src)
    run(["--split", str(src)], ["5", "n"], d)
    parts_dir = d / "st"
    # second split: overwrite yes; stale prompt (new code): delete yes
    r = run(["--split", str(src)], ["3", "n", "y", "y"], d)
    check("stale: second split exit 0", r.returncode == 0, r.stdout[-400:])
    if not BASELINE:
        check("stale: warning shown", "stale" in r.stdout.lower(), r.stdout[-500:])
        check("stale: old parts removed",
              not (parts_dir / "st_4.part").exists() and not (parts_dir / "st_5.part").exists())
        src.unlink()
        r = run(["--join", str(parts_dir / "st_1.part")], ["", "n", "n"], d)
        out = parts_dir / "st.bin"
        check("stale: join md5 ok", r.returncode == 0 and out.exists() and md5(out) == orig,
              r.stdout[-300:])
    shutil.rmtree(d)


def test_unicode_digit_filename():
    """photo_².part: '²'.isdigit() is True but int('²') raises. Old code
    crashes with a traceback; new code errors cleanly."""
    d = fresh_dir()
    f = d / "photo_².part"
    f.write_bytes(b"x")
    r = run(["--join", str(f)], [], d)
    check("unicode digit: exit code 1", r.returncode == 1, f"rc={r.returncode}")
    if not BASELINE:
        check("unicode digit: no traceback", "Traceback" not in r.stderr, r.stderr[-300:])
    shutil.rmtree(d)


def test_path_traversal_metadata():
    """Crafted part 0 with '../evil.txt' as stored name must not escape the
    fragment directory."""
    d = fresh_dir()
    src = d / "trav.bin"
    make_file(src, 6_000, seed=7)
    run(["--split", str(src)], ["2", "n"], d)
    parts_dir = d / "trav"
    payload = md5(src) + "  ../evil.txt\n"
    (parts_dir / "trav_0.part").write_text(payload)
    src.unlink()
    r = run(["--join", str(parts_dir / "trav_1.part")], ["", "n", "n"], d)
    outside = d / "evil.txt"
    check("traversal: nothing written outside fragment dir", not outside.exists())
    if not BASELINE:
        inside = parts_dir / "evil.txt"
        check("traversal: sanitized name used inside dir", inside.exists(), r.stdout[-400:])
    shutil.rmtree(d)


def test_output_over_fragment():
    """Typing a fragment's own name as output must be refused (new code);
    old code destroys the fragment."""
    if BASELINE:
        return
    d = fresh_dir()
    src = d / "frag.bin"
    make_file(src, 8_000, seed=8)
    run(["--split", str(src)], ["2", "n"], d)
    parts_dir = d / "frag"
    src.unlink()
    r = run(["--join", str(parts_dir / "frag_1.part")], ["frag_2.part", "y", "", "n", "n"], d)
    check("output-over-fragment: refused", r.returncode == 1
          and "fragment" in r.stdout.lower(), r.stdout[-400:])
    check("output-over-fragment: fragment intact",
          (parts_dir / "frag_2.part").stat().st_size > 0)
    shutil.rmtree(d)


def test_delete_fragments():
    d = fresh_dir()
    src = d / "del.bin"
    make_file(src, 5_000, seed=10)
    run(["--split", str(src)], ["2", "n"], d)
    parts_dir = d / "del"
    src.unlink()
    # prompts: keep name (Enter), delete fragments? y
    r = run(["--join", str(parts_dir / "del_1.part")], ["", "y"], d)
    check("delete fragments: exit 0", r.returncode == 0, r.stdout[-300:])
    check("delete fragments: parts gone",
          not any(parts_dir.glob("del_*.part")), str(list(parts_dir.iterdir())))
    check("delete fragments: output kept", (parts_dir / "del.bin").exists())
    shutil.rmtree(d)


def test_join_only_part0():
    """Only part 0 on disk: new code must refuse instead of writing an
    empty output file."""
    d = fresh_dir()
    src = d / "solo.bin"
    make_file(src, 4_000, seed=11)
    run(["--split", str(src)], ["2", "n"], d)
    parts_dir = d / "solo"
    (parts_dir / "solo_1.part").unlink()
    (parts_dir / "solo_2.part").unlink()
    src.unlink()
    r = run(["--join", str(parts_dir / "solo_0.part")], ["", "n", "n"], d)
    check("only part0: exit 1", r.returncode == 1, r.stdout[-300:])
    if not BASELINE:
        check("only part0: no empty output", not (parts_dir / "solo.bin").exists())
    shutil.rmtree(d)


def test_unicode_filename_and_join_from_part0():
    d = fresh_dir()
    src = d / "cañón fotográfico.dat"
    make_file(src, 7_777, seed=12)
    orig = md5(src)
    r = run(["--split", str(src)], ["3", "n"], d)
    parts_dir = d / "cañón fotográfico"
    check("unicode name: split ok", r.returncode == 0 and parts_dir.is_dir(),
          r.stdout[-300:])
    src.unlink()
    r = run(["--join", str(parts_dir / "cañón fotográfico_0.part")], ["", "n", "n"], d)
    out = parts_dir / "cañón fotográfico.dat"
    check("unicode name: join from part0 ok",
          r.returncode == 0 and out.exists() and md5(out) == orig, r.stdout[-400:])
    shutil.rmtree(d)


def test_rename_on_join():
    d = fresh_dir()
    src = d / "ren.bin"
    make_file(src, 3_000, seed=13)
    orig = md5(src)
    run(["--split", str(src)], ["2", "n"], d)
    parts_dir = d / "ren"
    r = run(["--join", str(parts_dir / "ren_1.part")], ["nuevo_nombre.bin", "n", "n"], d)
    out = parts_dir / "nuevo_nombre.bin"
    check("rename: join ok", r.returncode == 0 and out.exists() and md5(out) == orig,
          r.stdout[-300:])
    shutil.rmtree(d)


def main():
    global CARPENTER, BASELINE
    args = [a for a in sys.argv[1:] if a != "--baseline"]
    BASELINE = "--baseline" in sys.argv
    CARPENTER = args[0] if args else str(Path(__file__).parent / "carpenter.py")
    print(f"Testing {CARPENTER} (baseline={BASELINE})\n")

    test_plain_roundtrip(3, 10, "plain 10B/3p")
    test_plain_roundtrip(7, 1_000_000, "plain 1MB/7p")
    test_plain_roundtrip(12, 100_000, "plain 100KB/12p (width 2)")
    test_zip_roundtrip("contraseña€ñÑ", "zip unicode pw")
    test_zip_roundtrip("simple123", "zip ascii pw")
    test_wrong_password()
    test_join_without_part0("plain")
    test_join_without_part0("zip")
    test_split_errors()
    test_gap_md5_mismatch()
    test_join_from_part_after_gap()
    test_cross_width_contamination()
    test_stale_parts_prompt()
    test_unicode_digit_filename()
    test_path_traversal_metadata()
    test_output_over_fragment()
    test_delete_fragments()
    test_join_only_part0()
    test_unicode_filename_and_join_from_part0()
    test_rename_on_join()

    print(f"\n{'=' * 50}\nPASSED: {len(PASSED)}  FAILED: {len(FAILED)}")
    for f in FAILED:
        print(f"  FAILED: {f}")
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()
