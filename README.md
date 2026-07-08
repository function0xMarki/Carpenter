# Carpenter
Command-line tool to split files into multiple parts and reconstruct them later. Supports ZIP compression with AES-256 encryption.

<div align="center">
  
![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![danifus-pyzipper](https://img.shields.io/badge/danifus-pyzipper-green.svg)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
</div>


## Features

- Split any file into N equal parts
- Optional ZIP compression with AES-256 encryption
- Full Unicode password support (including special characters like `ñ`, `Ñ`, `é`, etc.)
- Cross-platform: files split on Linux, macOS or Windows can be joined on any of them
- Automatic MD5 integrity verification
- Automatically detects all parts in a sequence (provide any part, not just the first)
- Refuses to join if parts before the one you provided are missing
- Warns about leftover parts from a previous split that would corrupt the join
- Automatically detects if ZIP files require a password
- Low memory usage: plain parts are streamed in 1 MiB chunks (with password
  protection, one part at a time is held in memory — pick a part count that
  keeps parts reasonably sized for very large files)
- Fully interactive mode
- Option to delete fragments after reconstruction

## Requirements

- Python 3.8+
- [`pyzipper`](https://github.com/danifus/pyzipper) — only needed for password protection. **Offered for installation** on first run if missing.

### Manual installation

```bash
pip install pyzipper
```

No other external tools needed. `p7zip` / `7-Zip` are no longer required.

## Installation

```bash
git clone https://github.com/function0xmarki/carpenter.git
cd carpenter
chmod +x carpenter.py
```

## Usage

### Split a file

```bash
python3 carpenter.py --split file.jpg
```

The program will ask interactively:

1. **How many parts?** (minimum 2)
2. **Password protection?** (y/n)
   - **Yes** → asks for password and confirmation, generates `.zip` files with AES-256
   - **No** → generates plain `.part` files

A subdirectory named after the file is created with all parts inside:

```
photo/
  photo_0.zip   ← metadata (MD5 + original filename), encrypted
  photo_1.zip   ← data part 1, encrypted
  photo_2.zip   ← data part 2, encrypted
```

Or without password:

```
photo/
  photo_0.part  ← metadata (MD5 + original filename)
  photo_1.part  ← data part 1
  photo_2.part  ← data part 2
```

### Join parts

```bash
python3 carpenter.py --join photo_2.zip
```

> You can provide **any part** from the sequence — the program finds all parts automatically.

The program will:
1. Locate all parts in the directory (refusing if any part before the one you provided is missing)
2. Ask for the password if the files are encrypted
3. Reconstruct the original file
4. Verify MD5 integrity
5. Offer to delete the fragment files

### Help

```bash
python3 carpenter.py --help
```

## Tests

```bash
python3 test_carpenter.py
```

Runs 60 black-box checks covering split/join round-trips (plain and
encrypted), Unicode passwords and filenames, error paths and edge cases.
Optionally pass a path to test another copy of `carpenter.py`; the
`--baseline` flag skips checks for behavior added in the 2026-07 review so
the suite can also run against older versions.

## File structure

When splitting `photo.jpg` into 3 parts:

| File | Content |
|------|---------|
| `photo_0.part` / `photo_0.zip` | MD5 checksum + original filename |
| `photo_1.part` / `photo_1.zip` | Data (part 1 of 3) |
| `photo_2.part` / `photo_2.zip` | Data (part 2 of 3) |
| `photo_3.part` / `photo_3.zip` | Data (part 3 of 3) |

Part `_0` contains metadata only. Parts `_1` onward contain the actual data.

## Arguments

| Argument | Description |
|----------|-------------|
| `--split <file>` | Split a file (interactive) |
| `--join <part>` | Reconstruct from any part in the sequence |
| `-h, --help` | Show help |

## Security

- Passwords are entered interactively and never displayed on screen
- Password confirmation required when splitting
- AES-256 encryption via [pyzipper](https://github.com/danifus/pyzipper) (WinZip AES format)
- Passwords are always encoded as UTF-8 before key derivation, ensuring identical results across Linux, macOS, and Windows
- MD5 checksum verifies file integrity after reconstruction
- The filename stored in part 0 is reduced to its base name when joining, so a
  crafted archive cannot write outside the fragment directory

> **Note:** Files created with password protection are only compatible with Carpenter or tools that support WinZip AES-256 encryption (such as 7-Zip or WinZip). Files created **without** a password are standard raw binary parts with no container format.
