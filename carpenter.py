#!/usr/bin/env python3
"""
Carpenter - File splitter and joiner with optional ZIP compression
"""

import argparse
import getpass
import hashlib
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


def calculate_md5(filepath):
    """Calculate MD5 hash of a file."""
    hash_md5 = hashlib.md5()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def get_os_info():
    """Detect operating system."""
    system = platform.system().lower()
    if system == "darwin":
        return "macos"
    elif system == "linux":
        return "linux"
    else:
        return system


_7Z_CMD = None


def find_7z_cmd():
    """Find available 7z command (7z from p7zip or 7zz from modern 7-Zip)."""
    for cmd in ["7z", "7zz"]:
        if shutil.which(cmd) is not None:
            return cmd
    return None


def get_install_command():
    """Return the install command for p7zip based on the detected package manager."""
    candidates = [
        ("apt-get", ["sudo", "apt-get", "install", "-y", "p7zip-full"]),
        ("apt",     ["sudo", "apt", "install", "-y", "p7zip-full"]),
        ("dnf",     ["sudo", "dnf", "install", "-y", "p7zip", "p7zip-plugins"]),
        ("pacman",  ["sudo", "pacman", "-S", "--noconfirm", "p7zip"]),
        ("zypper",  ["sudo", "zypper", "install", "-y", "p7zip"]),
        ("brew",    ["brew", "install", "p7zip"]),
    ]
    for mgr, cmd in candidates:
        if shutil.which(mgr):
            return cmd
    return None


def run_7z(cmd, **kwargs):
    """Run 7z command with proper UTF-8 encoding for passwords with special chars."""
    if _7Z_CMD is None:
        empty = "" if kwargs.get("text") else b""
        return subprocess.CompletedProcess(cmd, 1, empty, empty)
    if cmd and cmd[0] in ("7z", "7zz"):
        cmd = [_7Z_CMD] + cmd[1:]
    env = os.environ.copy()
    env['LC_ALL'] = 'en_US.UTF-8'
    env['LANG'] = 'en_US.UTF-8'
    kwargs.setdefault('stdin', subprocess.DEVNULL)
    return subprocess.run(cmd, env=env, **kwargs)


def check_7z_installed():
    """Check if 7z is available (set by check_dependencies at startup)."""
    if _7Z_CMD is not None:
        return True
    print("Error: 7z is not installed. Password protection is not available.")
    print("       Restart the program to be prompted for installation.")
    return False


def check_dependencies():
    """Check all dependencies at startup. Silent if everything is OK."""
    global _7Z_CMD

    cmd = find_7z_cmd()
    if cmd:
        _7Z_CMD = cmd
        return

    print("Warning: 7z is not installed.")
    print("         Password protection will not be available without it.")
    print()

    install_cmd = get_install_command()
    if install_cmd:
        try:
            response = input("Install p7zip now? (y/n): ").strip().lower()
        except EOFError:
            response = ""
        if response in ['y', 'yes']:
            print(f"Running: {' '.join(install_cmd)}")
            result = subprocess.run(install_cmd)
            if result.returncode == 0:
                cmd = find_7z_cmd()
                if cmd:
                    _7Z_CMD = cmd
                    print("p7zip installed successfully!")
                    print()
                    return
            # On macOS, p7zip may be deprecated — try 7-zip as fallback
            if install_cmd[0] == "brew" and "p7zip" in install_cmd:
                print("Trying 7-zip as alternative...")
                result2 = subprocess.run(["brew", "install", "7-zip"])
                if result2.returncode == 0:
                    cmd = find_7z_cmd()
                    if cmd:
                        _7Z_CMD = cmd
                        print("7-zip installed successfully!")
                        print()
                        return
            print("Installation failed. Continuing without password protection.")
        print()
    else:
        os_type = get_os_info()
        print("No package manager detected. Install p7zip manually:")
        if os_type == "macos":
            print("  brew install p7zip")
            print("  (or: brew install 7-zip)")
        elif os_type == "linux":
            print("  sudo apt install p7zip-full   (Debian/Ubuntu)")
            print("  sudo dnf install p7zip p7zip-plugins   (Fedora/RHEL)")
            print("  sudo pacman -S p7zip   (Arch)")
        print()


def get_padding_width(num_parts):
    """Calculate the padding width based on number of parts."""
    return len(str(num_parts))


def generate_part_names(base_name, num_parts, extension):
    """Generate list of part filenames with proper padding.
    Part 0 is reserved for metadata (MD5), parts 1-N are data parts.
    """
    width = get_padding_width(num_parts)
    # Part 0 is the MD5 checksum file
    names = [f"{base_name}_{str(0).zfill(width)}{extension}"]
    # Parts 1-N are the data parts
    names.extend([f"{base_name}_{str(i).zfill(width)}{extension}" for i in range(1, num_parts + 1)])
    return names


def ask_overwrite(filepath):
    """Ask user if they want to overwrite an existing file."""
    if os.path.exists(filepath):
        response = input(f"File '{filepath}' already exists. Overwrite? (y/n): ").strip().lower()
        return response in ['y', 'yes']
    return True


def check_existing_files(filepaths):
    """Check if any output files exist and ask for confirmation."""
    existing = [f for f in filepaths if os.path.exists(f)]
    if existing:
        print("The following files already exist:")
        for f in existing:
            print(f"  - {f}")
        response = input("Overwrite all? (y/n): ").strip().lower()
        return response in ['y', 'yes']
    return True


def get_password(confirm=True):
    """Get password interactively without showing it."""
    while True:
        password = getpass.getpass("Enter password: ")
        if not password:
            print("Password cannot be empty.")
            continue

        if confirm:
            password2 = getpass.getpass("Confirm password: ")
            if password != password2:
                print("Passwords do not match. Try again.")
                continue

        return password


def split_file(filepath):
    """Split a file into multiple parts (interactive mode)."""
    filepath = Path(filepath)

    if not filepath.exists():
        print(f"Error: File '{filepath}' does not exist.")
        return False

    if not filepath.is_file():
        print(f"Error: '{filepath}' is not a valid file.")
        return False

    file_size = filepath.stat().st_size
    if file_size == 0:
        print("Error: File is empty.")
        return False

    # Ask for number of parts
    while True:
        try:
            num_parts_str = input("How many parts to split into? ").strip()
            num_parts = int(num_parts_str)
            if num_parts < 2:
                print("Error: Number of parts must be at least 2.")
                continue
            break
        except ValueError:
            print("Error: Enter a valid number.")
            continue

    # Calculate part size
    part_size = file_size // num_parts
    if part_size == 0:
        print(f"Error: File is too small to split into {num_parts} parts.")
        return False

    # Ask if user wants password protection
    use_password_response = input("Protect with password? (y/n): ").strip().lower()
    use_password = use_password_response in ['y', 'yes']

    # Determine extension and get password if needed
    extension = ".zip" if use_password else ".part"
    password = None
    if use_password:
        if not check_7z_installed():
            return False
        password = get_password(confirm=True)

    # Generate output filenames (includes part 0 for MD5)
    base_name = filepath.stem
    original_name = filepath.name
    output_dir = filepath.parent / base_name  # Create subdirectory with file name
    part_names = generate_part_names(base_name, num_parts, extension)
    part_paths = [output_dir / name for name in part_names]

    # Create output directory if it doesn't exist
    if output_dir.exists() and not output_dir.is_dir():
        print(f"Error: '{output_dir}' exists but is not a directory.")
        return False

    # Check for existing files
    if not check_existing_files([str(p) for p in part_paths]):
        print("Operation cancelled.")
        return False

    # Calculate MD5 before splitting
    print(f"Calculating MD5 of '{filepath.name}'...")
    file_md5 = calculate_md5(filepath)
    print(f"  MD5: {file_md5}")
    print()

    # Create output directory
    output_dir.mkdir(exist_ok=True)
    print(f"Output directory: {output_dir}")
    print()

    # Read and split the file
    print(f"Splitting '{filepath.name}' into {num_parts} parts...")

    try:
        # Create part 0 with MD5 and original filename
        md5_part_path = part_paths[0]
        md5_content = f"{file_md5}  {original_name}\n".encode('utf-8')

        print(f"  [  0.0%] Creating {md5_part_path.name} (checksum)...", end="", flush=True)

        if use_password:
            temp_part = output_dir / ".temp_part_md5"
            with open(temp_part, 'wb') as pf:
                pf.write(md5_content)

            cmd = ["7z", "a", "-tzip"]
            if password:
                cmd.extend([f"-p{password}", "-mem=AES256"])
            cmd.extend([str(md5_part_path), str(temp_part)])

            result = run_7z(cmd, capture_output=True)
            temp_part.unlink()

            if result.returncode != 0:
                print(" Error!")
                print(f"Compression error: {result.stderr.decode()}")
                return False
        else:
            with open(md5_part_path, 'wb') as pf:
                pf.write(md5_content)

        print(" OK")

        # Create data parts (parts 1 to N)
        data_part_paths = part_paths[1:]
        with open(filepath, 'rb') as f:
            for i, part_path in enumerate(data_part_paths):
                # Calculate size for this part (last part may be larger)
                if i == num_parts - 1:
                    # Last part: read everything remaining
                    data = f.read()
                else:
                    data = f.read(part_size)

                if not data:
                    break

                # Progress
                progress = (i + 1) / num_parts * 100
                print(f"  [{progress:5.1f}%] Creating {part_path.name}...", end="", flush=True)

                if use_password:
                    # Create temporary file for the part
                    temp_part = output_dir / f".temp_part_{i}"
                    with open(temp_part, 'wb') as pf:
                        pf.write(data)

                    # Compress with 7z
                    cmd = ["7z", "a", "-tzip"]
                    if password:
                        cmd.extend([f"-p{password}", "-mem=AES256"])
                    cmd.extend([str(part_path), str(temp_part)])

                    result = run_7z(cmd, capture_output=True)

                    # Remove temp file
                    temp_part.unlink()

                    if result.returncode != 0:
                        print(" Error!")
                        print(f"Compression error: {result.stderr.decode()}")
                        return False
                else:
                    # Write raw part
                    with open(part_path, 'wb') as pf:
                        pf.write(data)

                print(" OK")

        print()
        print(f"Done! Created {num_parts + 1} files in '{output_dir}':")
        for p in part_paths:
            print(f"  - {p.name}")

        return True

    except IOError as e:
        print(f"Read/write error: {e}")
        return False


def find_sequence_files(any_file):
    """Find all files in a sequence based on any file from the sequence.
    The user can provide any part (e.g., part 3) and we'll find all parts.
    """
    filepath = Path(any_file)

    if not filepath.exists():
        print(f"Error: File '{filepath}' does not exist.")
        return None, None, None

    filename = filepath.stem
    extension = filepath.suffix
    parent = filepath.parent

    # Try to extract base name and number pattern
    # Expected format: basename_01.ext or basename_001.ext etc.
    parts = filename.rsplit('_', 1)
    if len(parts) != 2:
        print(f"Error: File does not follow expected pattern (name_number{extension}).")
        return None, None, None

    base_name, num_str = parts

    if not num_str.isdigit():
        print(f"Error: File does not follow expected pattern (name_number{extension}).")
        return None, None, None

    padding_width = len(num_str)

    # Find all files in the sequence (starting from 0, regardless of which part was provided)
    sequence_files = []
    has_part_0 = False

    # First, check if part 0 exists
    part_0_name = f"{base_name}_{str(0).zfill(padding_width)}{extension}"
    part_0_path = parent / part_0_name
    if part_0_path.exists():
        has_part_0 = True
        sequence_files.append(part_0_path)

    # Then find all data parts (1, 2, 3, ...)
    i = 1
    while True:
        part_name = f"{base_name}_{str(i).zfill(padding_width)}{extension}"
        part_path = parent / part_name
        if part_path.exists():
            sequence_files.append(part_path)
            i += 1
        else:
            break

    if not sequence_files:
        print("Error: No files found in sequence.")
        return None, None, None, False

    # Warn if part 0 (MD5) is missing
    if not has_part_0:
        print("Warning: Checksum file (part 0) not found.")
        print("         File integrity cannot be verified.")
        print()

    return sequence_files, base_name, extension, has_part_0



def extract_md5_info(md5_part_path, is_compressed, password=None):
    """Extract MD5 and original filename from part 0.
    Returns: (md5_hash, filename, needs_password)
    """
    try:
        if is_compressed:
            temp_dir = md5_part_path.parent / ".temp_extract_md5"
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
            temp_dir.mkdir()

            try:
                pwd_flag = f"-p{password}" if password else "-p"
                cmd = ["7z", "e", pwd_flag, f"-o{temp_dir}", "-y", str(md5_part_path)]
                result = run_7z(cmd, capture_output=True, text=True)

                if result.returncode != 0:
                    error_output = result.stdout + result.stderr
                    if "Wrong password" in error_output or "Cannot open encrypted" in error_output:
                        return None, None, True  # Needs password
                    return None, None, False

                extracted_files = list(temp_dir.iterdir())
                content = extracted_files[0].read_text('utf-8').strip() if extracted_files else None
            finally:
                shutil.rmtree(temp_dir, ignore_errors=True)
        else:
            content = md5_part_path.read_text('utf-8').strip()

        if content:
            parts = content.split('  ', 1)
            if len(parts) == 2:
                return parts[0], parts[1], False

        return None, None, False

    except Exception:
        return None, None, False


def join_files(first_file):
    """Join split files back into the original."""
    sequence_files, base_name, extension, has_part_0 = find_sequence_files(first_file)

    if sequence_files is None or base_name is None or extension is None:
        return False

    is_compressed = extension.lower() == ".zip"

    # Check if 7z is needed
    if is_compressed and not check_7z_installed():
        return False

    print(f"Found {len(sequence_files)} files in sequence:")
    for f in sequence_files:
        print(f"  - {f.name}")
    print()

    original_md5 = None
    original_name = None
    password = None

    # Part 0 (if it exists) is always metadata — never data.
    # Set data_files now so we never accidentally include part 0 in reconstruction.
    data_files = sequence_files[1:] if has_part_0 else sequence_files

    if has_part_0:
        # Try to extract MD5 from part 0 (first without password)
        md5_hash, stored_name, needs_password = extract_md5_info(sequence_files[0], is_compressed, None)

        # If needs password, ask for it and retry
        if is_compressed and needs_password:
            print("File is password protected.")
            password = get_password(confirm=False)
            md5_hash, stored_name, needs_password = extract_md5_info(sequence_files[0], is_compressed, password)

            if needs_password:
                print("Error: Wrong password.")
                return False

        if md5_hash and stored_name:
            original_md5 = md5_hash
            original_name = stored_name
            print(f"Detected MD5 checksum: {original_md5}")
            print(f"Original filename: {original_name}")
            print()

    # Determine output filename
    if original_name:
        output_name = original_name
        print(f"Using original filename: {output_name}")
        response = input("Change name? (Enter to keep, or type new name): ").strip()
        if response:
            output_name = response
    else:
        user_input = input(f"Output filename (e.g.: {base_name}.jpg): ").strip()
        output_name = user_input if user_input else base_name

    output_path = Path(first_file).parent / output_name

    # Check if output exists
    if output_path.exists():
        if not ask_overwrite(str(output_path)):
            print("Operation cancelled.")
            return False

    print()
    print(f"Reconstructing '{output_name}'...")

    try:
        with open(output_path, 'wb') as outfile:
            for i, part_path in enumerate(data_files):
                progress = (i + 1) / len(data_files) * 100
                print(f"  [{progress:5.1f}%] Processing {part_path.name}...", end="", flush=True)

                if is_compressed:
                    # Use a unique temp dir per part to avoid leftover files from previous parts
                    temp_dir = part_path.parent / f".temp_extract_{i}"
                    if temp_dir.exists():
                        shutil.rmtree(temp_dir)
                    temp_dir.mkdir()

                    pwd_flag = f"-p{password}" if password else "-p"
                    cmd = ["7z", "e", pwd_flag, f"-o{temp_dir}", "-y", str(part_path)]

                    result = run_7z(cmd, capture_output=True)

                    if result.returncode != 0:
                        print(" Error!")
                        error_msg = result.stderr.decode()
                        if "Wrong password" in error_msg or "password" in error_msg.lower():
                            print("Error: Wrong password.")
                        else:
                            print(f"Decompression error: {error_msg}")
                        shutil.rmtree(temp_dir, ignore_errors=True)
                        output_path.unlink(missing_ok=True)
                        return False

                    extracted_files = list(temp_dir.iterdir())
                    if extracted_files:
                        with open(extracted_files[0], 'rb') as pf:
                            outfile.write(pf.read())

                    shutil.rmtree(temp_dir, ignore_errors=True)
                else:
                    # Read raw part
                    with open(part_path, 'rb') as pf:
                        outfile.write(pf.read())

                print(" OK")

        print()
        print(f"File reconstructed: {output_path}")

        # Verify MD5 if available
        if original_md5:
            print()
            print("Verifying integrity...")
            reconstructed_md5 = calculate_md5(output_path)
            print(f"  Original MD5:      {original_md5}")
            print(f"  Reconstructed MD5: {reconstructed_md5}")

            if original_md5 == reconstructed_md5:
                print()
                print("  [OK] Integrity verified successfully")
            else:
                print()
                print("  [ERROR] Checksums do NOT match. File may be corrupted.")
                return False

        print()

        # Ask if user wants to delete the fragment files
        response = input("Delete fragment files? (y/n): ").strip().lower()
        if response in ['y', 'yes']:
            print()
            print("Deleting fragments...")
            for fragment in sequence_files:
                try:
                    fragment.unlink()
                    print(f"  - {fragment.name} deleted")
                except OSError as e:
                    print(f"  - Error deleting {fragment.name}: {e}")
            print()
            print("Fragments deleted.")

        return True

    except IOError as e:
        print(f"Read/write error: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Carpenter - File splitter and joiner tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --split file.jpg          Split file (interactive mode)
  %(prog)s --join file_01.part       Join fragmented files
        """
    )

    # Mode arguments (mutually exclusive)
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--split", action="store_true",
                           help="Split file (interactive mode)")
    mode_group.add_argument("--join", action="store_true",
                           help="Join fragmented files")

    # File argument (positional, at the end)
    parser.add_argument("file", help="File to process")

    args = parser.parse_args()

    check_dependencies()

    if args.split:
        success = split_file(args.file)
    else:
        success = join_files(args.file)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
