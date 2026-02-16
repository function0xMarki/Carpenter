# Carpenter
---
- 🇪🇸 [Español](https://github.com/function0xMarki/Carpenter/edit/main/Spanish/README_ES.md)
---
Command-line tool to split files into multiple parts and reconstruct them later. Supports ZIP compression with AES-256 encryption.

## Features

- Split any file into N equal parts
- Optional ZIP compression with AES-256 encryption
- Automatic MD5 integrity verification
- Automatically detects all parts in a sequence
- Automatically detects if ZIP files require a password
- Fully interactive mode
- Option to delete fragments after reconstruction

## Requirements

- Python 3.6+
- `p7zip` (only if using password protection)

### Installing p7zip

**macOS:**
```bash
brew install p7zip
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt install p7zip-full
```

**Linux (Fedora/RHEL):**
```bash
sudo dnf install p7zip p7zip-plugins
```

**Linux (Arch):**
```bash
sudo pacman -S p7zip
```

## Installation

```bash
# Clone the repository
git clone https://github.com/function0xmarki/carpenter.git
cd carpenter

# Make executable
chmod +x carpenter.py
```

## Usage

### Split files (-split)

```bash
python3 carpenter.py -split file.jpg
```

The script will interactively ask:
1. How many parts to split into?
2. Protect with password? (y/n)
   - If **yes**: asks for password and confirmation, generates `.zip` files with AES-256
   - If **no**: generates uncompressed `.part` files

### Join files (-join)

```bash
python3 carpenter.py -join file_01.part
```

> **Note:** You can specify any part in the sequence (not necessarily part 0). The script will automatically find all parts and detect if a password is needed.

When finished, it will ask if you want to delete the fragments.

### View help

```bash
python3 carpenter.py --help
```

## Generated file structure

When splitting `photo.jpg` into 3 parts:

| File | Content |
|------|---------|
| `photo_0.part` | MD5 checksum + original filename |
| `photo_1.part` | Data (part 1) |
| `photo_2.part` | Data (part 2) |
| `photo_3.part` | Data (part 3) |

Part `_0` contains metadata to verify integrity and restore the original filename.

## Options

| Argument | Description |
|----------|-------------|
| `-split` | Split file (interactive mode) |
| `-join` | Join parts into original file |
| `-h, --help` | Show help |

## Security

- Passwords are requested interactively and not shown on screen
- When splitting with password, confirmation is required
- When joining, it automatically detects if the file requires a password
- Encryption uses AES-256 via 7-Zip
- MD5 checksum verifies the file has not been modified

## License

MIT License
