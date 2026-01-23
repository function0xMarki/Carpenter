# Installation

## Requirements

- Python 3.8+
- p7zip (optional, only for password protection)

## Python Dependencies

No external packages required. Uses only Python standard library.

## System Dependencies

### p7zip (optional)

Only required if you want to use password protection.

#### macOS (Homebrew)
```bash
brew install p7zip
```

#### Ubuntu / Debian
```bash
sudo apt update
sudo apt install p7zip-full
```

#### Fedora / RHEL / CentOS
```bash
sudo dnf install p7zip p7zip-plugins
```

#### Arch Linux
```bash
sudo pacman -S p7zip
```

#### openSUSE
```bash
sudo zypper install p7zip
```

## Verify Installation

```bash
# Check Python version
python3 --version

# Check 7z installation (optional)
7z --help
```

## Usage

```bash
# Split a file
python3 carpenter.py -cut file.jpg

# Join files
python3 carpenter.py -glue file_01.part
```
