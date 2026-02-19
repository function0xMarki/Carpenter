#!/usr/bin/env python3
"""
Carpenter - File splitter and joiner with optional ZIP compression
"""

import argparse
import getpass
import hashlib
import os
import sys
import zipfile
from pathlib import Path

try:
    import pyzipper
except ImportError:
    pyzipper = None


def calculate_md5(filepath):
    """Calculate MD5 hash of a file."""
    hash_md5 = hashlib.md5()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def check_pyzipper_installed():
    """Check if pyzipper is available for encrypted ZIP support."""
    if pyzipper is not None:
        return True

    print("Error: pyzipper is not installed.")
    print()
    print("To enable password-protected ZIP parts, run:")
    print("  pip install pyzipper")
    return False


def is_password_error(exc):
    """Return True when an exception message indicates a password failure."""
    message = str(exc).lower()
    markers = (
        "password",
        "decrypt",
        "authentication code",
        "bad password",
    )
    return any(marker in message for marker in markers)


def zip_requires_password(zip_path):
    """Check if a ZIP archive has encrypted entries."""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            infos = zf.infolist()
            return any(info.flag_bits & 0x1 for info in infos)
    except (OSError, zipfile.BadZipFile):
        return False


def write_zip_part(zip_path, inner_name, content, password):
    """Write one encrypted ZIP member using AES-256."""
    if pyzipper is None:
        raise RuntimeError("pyzipper is required for encrypted ZIP support.")

    with pyzipper.AESZipFile(
        zip_path,
        'w',
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as zf:
        zf.setpassword(password.encode('utf-8'))
        zf.setencryption(pyzipper.WZ_AES, nbits=256)
        zf.writestr(inner_name, content)


def read_first_zip_member(zip_path, password=None):
    """Read and return the first non-directory member from a ZIP archive."""
    if pyzipper is None:
        raise RuntimeError("pyzipper is required for encrypted ZIP support.")

    with pyzipper.AESZipFile(zip_path, 'r') as zf:
        names = [name for name in zf.namelist() if not name.endswith('/')]
        if not names:
            return None, None

        if password is not None:
            zf.setpassword(password.encode('utf-8'))

        return zf.read(names[0]), names[0]


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
        if not check_pyzipper_installed():
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

        print(f"  [  0.0%] Creating {md5_part_path.name} (checksum)...", end="")

        if use_password:
            try:
                write_zip_part(md5_part_path, ".part_md5", md5_content, password)
            except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as e:
                print(" Error!")
                print(f"Compression error: {e}")
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
                print(f"  [{progress:5.1f}%] Creating {part_path.name}...", end="")

                if use_password:
                    try:
                        write_zip_part(part_path, f".part_{i}", data, password)
                    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as e:
                        print(" Error!")
                        print(f"Compression error: {e}")
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
        return None, None, None

    # Warn if part 0 (MD5) is missing
    if not has_part_0:
        print("Warning: Checksum file (part 0) not found.")
        print("         File integrity cannot be verified.")
        print()

    return sequence_files, base_name, extension


def detect_original_extension(first_zip_path, password=None):
    """Try to detect the original file extension from the first zip."""
    try:
        _, inner_name = read_first_zip_member(first_zip_path, password=password)
        if inner_name:
            return Path(inner_name).suffix or None
    except Exception:
        return None

    return None


def check_zip_needs_password(zip_path):
    """Check if a ZIP file requires a password to extract."""
    return zip_requires_password(zip_path)


def extract_md5_info(md5_part_path, is_compressed, password=None):
    """Extract MD5 and original filename from part 0.
    Returns: (md5_hash, filename, needs_password)
    """
    try:
        if is_compressed:
            try:
                content_bytes, _ = read_first_zip_member(md5_part_path, password=password)
            except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as e:
                if zip_requires_password(md5_part_path) and (password is None or is_password_error(e)):
                    return None, None, True  # Needs password
                return None, None, False

            if content_bytes is None:
                content = None
            else:
                content = content_bytes.decode('utf-8').strip()
        else:
            content = md5_part_path.read_text('utf-8').strip()

        if content:
            # Format: "md5hash  filename"
            parts = content.split('  ', 1)
            if len(parts) == 2:
                return parts[0], parts[1], False

        return None, None, False

    except Exception:
        return None, None, False


def safe_output_path(base_dir, filename):
    """Build a safe output path inside base_dir from an untrusted filename."""
    candidate = (filename or "").strip()
    if not candidate:
        raise ValueError("Output filename cannot be empty.")

    user_path = Path(candidate)
    if user_path.is_absolute():
        raise ValueError("Absolute output paths are not allowed.")

    if len(user_path.parts) != 1:
        raise ValueError("Output filename cannot include directory components.")

    safe_name = user_path.name
    if safe_name in {"", ".", ".."}:
        raise ValueError("Invalid output filename.")

    base_resolved = Path(base_dir).resolve()
    output_path = (base_resolved / safe_name).resolve()

    try:
        output_path.relative_to(base_resolved)
    except ValueError as exc:
        raise ValueError("Output path escapes the working directory.") from exc

    if output_path.exists() and output_path.is_symlink():
        raise ValueError("Refusing to write to a symlink.")

    return output_path


def join_files(first_file):
    """Join split files back into the original."""
    sequence_files, base_name, extension = find_sequence_files(first_file)

    if sequence_files is None or base_name is None or extension is None:
        return False

    is_compressed = extension.lower() == ".zip"

    # Check if pyzipper is needed
    if is_compressed and not check_pyzipper_installed():
        return False

    print(f"Found {len(sequence_files)} files in sequence:")
    for f in sequence_files:
        print(f"  - {f.name}")
    print()

    # Check if first file (part 0) contains MD5 info
    original_md5 = None
    original_name = None
    data_files = sequence_files
    password = None

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
        data_files = sequence_files[1:]  # Skip part 0 for data reconstruction
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

    base_dir = Path(first_file).parent
    while True:
        try:
            output_path = safe_output_path(base_dir, output_name)
            break
        except ValueError as e:
            print(f"Error: {e}")
            output_name = input(f"Output filename (e.g.: {base_name}.jpg): ").strip()
            if not output_name:
                print("Operation cancelled.")
                return False

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
                print(f"  [{progress:5.1f}%] Processing {part_path.name}...", end="")

                if is_compressed:
                    try:
                        part_bytes, _ = read_first_zip_member(part_path, password=password)
                    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as e:
                        print(" Error!")
                        if zip_requires_password(part_path) and (password is None or is_password_error(e)):
                            print("Error: Wrong password.")
                        else:
                            print(f"Decompression error: {e}")
                        output_path.unlink(missing_ok=True)
                        return False

                    if part_bytes is None:
                        print(" Error!")
                        print("Decompression error: ZIP part contains no files.")
                        output_path.unlink(missing_ok=True)
                        return False

                    outfile.write(part_bytes)
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
  %(prog)s -split file.jpg          Split file (interactive mode)
  %(prog)s -join file_01.part       Join fragmented files
        """
    )

    # Mode arguments (mutually exclusive)
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("-split", action="store_true",
                           help="Split file (interactive mode)")
    mode_group.add_argument("-join", action="store_true",
                           help="Join fragmented files")

    # File argument (positional, at the end)
    parser.add_argument("file", help="File to process")

    args = parser.parse_args()

    if args.split:
        success = split_file(args.file)
    else:
        success = join_files(args.file)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
