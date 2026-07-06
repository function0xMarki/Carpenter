#!/usr/bin/env python3
"""
Carpenter - File splitter and joiner with optional ZIP compression
"""

import argparse
import getpass
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

# Chunk size for streaming file copies (1 MiB) so parts are never
# fully loaded into memory in plain (.part) mode.
COPY_CHUNK_SIZE = 1024 * 1024


def ask(prompt):
    """input() that exits cleanly if stdin ends (non-interactive misuse)."""
    try:
        return input(prompt)
    except EOFError:
        print()
        print("Error: Unexpected end of input.")
        sys.exit(1)


def copy_bytes(src, dst, nbytes):
    """Copy exactly nbytes from src to dst in chunks. Returns bytes copied."""
    copied = 0
    while copied < nbytes:
        buf = src.read(min(COPY_CHUNK_SIZE, nbytes - copied))
        if not buf:
            break
        dst.write(buf)
        copied += len(buf)
    return copied


def calculate_md5(filepath):
    """Calculate MD5 hash of a file."""
    hash_md5 = hashlib.md5()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def check_pyzipper_installed():
    """Check if pyzipper is available for password protection."""
    try:
        import pyzipper  # noqa: F401
        return True
    except ImportError:
        print("Error: 'pyzipper' is not installed. Password protection is not available.")
        print("       Restart the program to be prompted for installation.")
        return False


def check_dependencies():
    """Check all dependencies at startup. Silent if everything is OK."""
    try:
        import pyzipper  # noqa: F401
        return
    except ImportError:
        pass

    print("Warning: 'pyzipper' is not installed.")
    print("         Password protection will not be available without it.")
    print()

    try:
        response = input("Install pyzipper now? (y/n): ").strip().lower()
    except EOFError:
        response = ""

    if response in ['y', 'yes']:
        print(f"Running: {sys.executable} -m pip install pyzipper")
        result = subprocess.run([sys.executable, '-m', 'pip', 'install', 'pyzipper'])
        if result.returncode == 0:
            print("pyzipper installed successfully!")
            print()
            return
        print("Installation failed. Continuing without password protection.")
    print()


def _zip_compress(data_bytes, output_path, password):
    """Compress bytes to an AES-256 ZIP.
    Password is always encoded as UTF-8, ensuring cross-platform consistency.
    """
    import pyzipper
    with pyzipper.AESZipFile(str(output_path), 'w',
                              compression=pyzipper.ZIP_DEFLATED,
                              encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password.encode('utf-8'))
        zf.writestr('data', data_bytes)


def _zip_extract(zip_path, password=None):
    """Extract data from an AES-256 ZIP.
    Returns (data_bytes, needs_password).
    needs_password=True when the file is encrypted and no/wrong password was supplied.
    """
    import pyzipper
    try:
        with pyzipper.AESZipFile(str(zip_path), 'r') as zf:
            if password is not None:
                zf.setpassword(password.encode('utf-8'))
            names = zf.namelist()
            if not names:
                return None, False
            data = zf.read(names[0])
            return data, False
    except RuntimeError as e:
        msg = str(e).lower()
        if 'bad password' in msg or 'encrypted' in msg or 'password' in msg:
            return None, True
        return None, False
    except Exception:
        return None, False


def get_padding_width(num_parts):
    """Calculate the padding width based on number of parts."""
    return len(str(num_parts))


def generate_part_names(base_name, num_parts, extension):
    """Generate list of part filenames with proper padding.
    Part 0 is reserved for metadata (MD5), parts 1-N are data parts.
    """
    width = get_padding_width(num_parts)
    names = [f"{base_name}_{str(0).zfill(width)}{extension}"]
    names.extend([f"{base_name}_{str(i).zfill(width)}{extension}" for i in range(1, num_parts + 1)])
    return names


def ask_overwrite(filepath):
    """Ask user if they want to overwrite an existing file."""
    if os.path.exists(filepath):
        response = ask(f"File '{filepath}' already exists. Overwrite? (y/n): ").strip().lower()
        return response in ['y', 'yes']
    return True


def check_existing_files(filepaths):
    """Check if any output files exist and ask for confirmation."""
    existing = [f for f in filepaths if os.path.exists(f)]
    if existing:
        print("The following files already exist:")
        for f in existing:
            print(f"  - {f}")
        response = ask("Overwrite all? (y/n): ").strip().lower()
        return response in ['y', 'yes']
    return True


def get_password(confirm=True):
    """Get password interactively without showing it."""
    while True:
        try:
            password = getpass.getpass("Enter password: ")
        except EOFError:
            print()
            print("Error: Cannot read password in non-interactive mode.")
            sys.exit(1)

        if not password:
            print("Password cannot be empty.")
            continue

        if confirm:
            try:
                password2 = getpass.getpass("Confirm password: ")
            except EOFError:
                print()
                print("Error: Cannot read password in non-interactive mode.")
                sys.exit(1)
            if password != password2:
                print("Passwords do not match. Try again.")
                continue

        return password


def handle_stale_parts(output_dir, base_name, num_parts, extension):
    """Detect leftover parts from a previous, larger split of the same file.

    Files continuing the new sequence (indexes num_parts+1 onward, same
    padding width) would be silently absorbed when joining, corrupting the
    reconstruction. Offer to delete them. Returns False to cancel the split.
    """
    width = get_padding_width(num_parts)
    stale = []
    i = num_parts + 1
    while len(str(i)) <= width:
        part_path = output_dir / f"{base_name}_{str(i).zfill(width)}{extension}"
        if not part_path.exists():
            break
        stale.append(part_path)
        i += 1

    if not stale:
        return True

    print("Warning: stale part files from a previous split were found:")
    for p in stale:
        print(f"  - {p.name}")
    print("         If kept, they would corrupt the file when joining.")
    response = ask("Delete them? (y/n): ").strip().lower()
    if response not in ['y', 'yes']:
        return False

    for p in stale:
        try:
            p.unlink()
        except OSError as e:
            print(f"Error deleting {p.name}: {e}")
            return False
    print("Stale parts deleted.")
    print()
    return True


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

    while True:
        try:
            num_parts_str = ask("How many parts to split into? ").strip()
            num_parts = int(num_parts_str)
            if num_parts < 2:
                print("Error: Number of parts must be at least 2.")
                continue
            break
        except ValueError:
            print("Error: Enter a valid number.")
            continue

    part_size = file_size // num_parts
    if part_size == 0:
        print(f"Error: File is too small to split into {num_parts} parts.")
        return False

    use_password_response = ask("Protect with password? (y/n): ").strip().lower()
    use_password = use_password_response in ['y', 'yes']

    extension = ".zip" if use_password else ".part"
    password = None
    if use_password:
        if not check_pyzipper_installed():
            return False
        password = get_password(confirm=True)

    base_name = filepath.stem
    original_name = filepath.name
    output_dir = filepath.parent / base_name
    part_names = generate_part_names(base_name, num_parts, extension)
    part_paths = [output_dir / name for name in part_names]

    if output_dir.exists() and not output_dir.is_dir():
        print(f"Error: '{output_dir}' exists but is not a directory.")
        return False

    if not check_existing_files([str(p) for p in part_paths]):
        print("Operation cancelled.")
        return False

    if not handle_stale_parts(output_dir, base_name, num_parts, extension):
        print("Operation cancelled.")
        return False

    print(f"Calculating MD5 of '{filepath.name}'...")
    file_md5 = calculate_md5(filepath)
    print(f"  MD5: {file_md5}")
    print()

    try:
        output_dir.mkdir(exist_ok=True)
    except OSError as e:
        print(f"Error: Could not create output directory: {e}")
        return False
    print(f"Output directory: {output_dir}")
    print()

    print(f"Splitting '{filepath.name}' into {num_parts} parts...")

    try:
        md5_part_path = part_paths[0]
        md5_content = f"{file_md5}  {original_name}\n".encode('utf-8')

        print(f"  [  0.0%] Creating {md5_part_path.name} (checksum)...", end="", flush=True)

        if use_password:
            try:
                _zip_compress(md5_content, md5_part_path, password)
            except Exception as e:
                print(" Error!")
                print(f"Compression error: {e}")
                return False
        else:
            with open(md5_part_path, 'wb') as pf:
                pf.write(md5_content)

        print(" OK")

        # Parts 1..N-1 get part_size bytes; the last part gets the remainder.
        part_sizes = [part_size] * (num_parts - 1)
        part_sizes.append(file_size - part_size * (num_parts - 1))

        data_part_paths = part_paths[1:]
        with open(filepath, 'rb') as f:
            for i, (part_path, size) in enumerate(zip(data_part_paths, part_sizes)):
                progress = (i + 1) / num_parts * 100
                print(f"  [{progress:5.1f}%] Creating {part_path.name}...", end="", flush=True)

                if use_password:
                    data = f.read(size)
                    try:
                        _zip_compress(data, part_path, password)
                    except Exception as e:
                        print(" Error!")
                        print(f"Compression error: {e}")
                        return False
                else:
                    with open(part_path, 'wb') as pf:
                        copy_bytes(f, pf, size)

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
        return None, None, None, False

    filename = filepath.stem
    extension = filepath.suffix
    parent = filepath.parent

    parts = filename.rsplit('_', 1)
    if len(parts) != 2:
        print(f"Error: File does not follow expected pattern (name_number{extension}).")
        return None, None, None, False

    base_name, num_str = parts

    # isdigit() alone accepts non-ASCII digits like '²' that int() rejects.
    if not (num_str.isascii() and num_str.isdigit()):
        print(f"Error: File does not follow expected pattern (name_number{extension}).")
        return None, None, None, False

    padding_width = len(num_str)

    sequence_files = []
    has_part_0 = False

    part_0_name = f"{base_name}_{str(0).zfill(padding_width)}{extension}"
    part_0_path = parent / part_0_name
    if part_0_path.exists():
        has_part_0 = True
        sequence_files.append(part_0_path)

    i = 1
    while True:
        # Indexes inside a sequence never have more digits than the padding
        # width (width is derived from the part count when splitting), so a
        # longer name can only belong to a different split of the same file.
        if len(str(i)) > padding_width:
            break
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

    # The provided file must be inside the detected sequence; if it is not,
    # there is a gap (missing parts) between the sequence start and it.
    given = filepath.resolve()
    if all(p.resolve() != given for p in sequence_files):
        print(f"Error: '{filepath.name}' is not part of the detected sequence.")
        print("       One or more earlier parts are missing.")
        return None, None, None, False

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
            data, needs_pw = _zip_extract(md5_part_path, password)
            if needs_pw:
                return None, None, True
            if data is None:
                return None, None, False
            content = data.decode('utf-8').strip()
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

    if is_compressed and not check_pyzipper_installed():
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

    if not data_files:
        print("Error: No data parts found (only the checksum file exists).")
        return False

    if has_part_0:
        md5_hash, stored_name, needs_password = extract_md5_info(sequence_files[0], is_compressed, None)

        if is_compressed and needs_password:
            print("File is password protected.")
            password = get_password(confirm=False)
            md5_hash, stored_name, needs_password = extract_md5_info(sequence_files[0], is_compressed, password)

            if needs_password:
                print("Error: Wrong password.")
                return False

        if md5_hash and stored_name:
            original_md5 = md5_hash
            # Keep only the base name: a crafted part 0 could otherwise carry
            # path separators and make the output land outside this directory.
            safe_name = os.path.basename(stored_name.replace('\\', '/'))
            if safe_name != stored_name:
                print(f"Warning: stored filename '{stored_name}' contains a path;"
                      f" using '{safe_name}' instead.")
            original_name = safe_name or None
            print(f"Detected MD5 checksum: {original_md5}")
            if original_name:
                print(f"Original filename: {original_name}")
            print()

    elif is_compressed and data_files:
        # No part 0, but files are ZIP — probe first data part to detect encryption.
        _, _, needs_password = extract_md5_info(data_files[0], is_compressed, None)
        if needs_password:
            print("File is password protected.")
            password = get_password(confirm=False)

    if original_name:
        output_name = original_name
        print(f"Using original filename: {output_name}")
        response = ask("Change name? (Enter to keep, or type new name): ").strip()
        if response:
            output_name = response
    else:
        user_input = ask(f"Output filename (e.g.: {base_name}.jpg): ").strip()
        output_name = user_input if user_input else base_name

    output_path = Path(first_file).parent / output_name

    if any(p.resolve() == output_path.resolve() for p in sequence_files):
        print("Error: Output filename matches one of the fragment files.")
        return False

    if output_path.exists():
        if not ask_overwrite(str(output_path)):
            print("Operation cancelled.")
            return False

    print()
    print(f"Reconstructing '{output_name}'...")

    error = None
    try:
        with open(output_path, 'wb') as outfile:
            for i, part_path in enumerate(data_files):
                progress = (i + 1) / len(data_files) * 100
                print(f"  [{progress:5.1f}%] Processing {part_path.name}...", end="", flush=True)

                if is_compressed:
                    data, needs_pw = _zip_extract(part_path, password)
                    if needs_pw:
                        error = "Wrong password."
                        break
                    if data is None:
                        error = (f"Could not extract data from {part_path.name}."
                                 " Archive may be corrupted.")
                        break
                    outfile.write(data)
                else:
                    with open(part_path, 'rb') as pf:
                        shutil.copyfileobj(pf, outfile, COPY_CHUNK_SIZE)

                print(" OK")

        if error:
            # Remove the partial output only now that the file is closed:
            # unlinking an open file fails on Windows.
            print(" Error!")
            print(f"Error: {error}")
            try:
                output_path.unlink()
            except OSError:
                pass
            return False

        print()
        print(f"File reconstructed: {output_path}")

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

        response = ask("Delete fragment files? (y/n): ").strip().lower()
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

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--split", action="store_true",
                           help="Split file (interactive mode)")
    mode_group.add_argument("--join", action="store_true",
                           help="Join fragmented files")

    parser.add_argument("file", help="File to process")

    args = parser.parse_args()

    try:
        check_dependencies()

        if args.split:
            success = split_file(args.file)
        else:
            success = join_files(args.file)
    except KeyboardInterrupt:
        print()
        print("Operation cancelled by user.")
        sys.exit(130)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
