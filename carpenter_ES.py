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


def check_7z_installed():
    """Check if 7z is installed and provide installation instructions if not."""
    if shutil.which("7z") is not None:
        return True

    os_type = get_os_info()

    print("Error: 7z no está instalado.")
    print()

    if os_type == "macos":
        print("Para instalar en macOS, ejecuta:")
        print("  brew install p7zip")
    elif os_type == "linux":
        print("Para instalar en Linux (Debian/Ubuntu), ejecuta:")
        print("  sudo apt install p7zip-full")
        print()
        print("Para instalar en Linux (Fedora/RHEL), ejecuta:")
        print("  sudo dnf install p7zip p7zip-plugins")
        print()
        print("Para instalar en Linux (Arch), ejecuta:")
        print("  sudo pacman -S p7zip")
    else:
        print("Por favor, instala p7zip para tu sistema operativo.")

    return False


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
        response = input(f"El archivo '{filepath}' ya existe. ¿Sobrescribir? (s/n): ").strip().lower()
        return response in ['s', 'si', 'sí', 'y', 'yes']
    return True


def check_existing_files(filepaths):
    """Check if any output files exist and ask for confirmation."""
    existing = [f for f in filepaths if os.path.exists(f)]
    if existing:
        print("Los siguientes archivos ya existen:")
        for f in existing:
            print(f"  - {f}")
        response = input("¿Sobrescribir todos? (s/n): ").strip().lower()
        return response in ['s', 'si', 'sí', 'y', 'yes']
    return True


def get_password(confirm=True):
    """Get password interactively without showing it."""
    while True:
        password = getpass.getpass("Introduce la contraseña: ")
        if not password:
            print("La contraseña no puede estar vacía.")
            continue

        if confirm:
            password2 = getpass.getpass("Confirma la contraseña: ")
            if password != password2:
                print("Las contraseñas no coinciden. Inténtalo de nuevo.")
                continue

        return password


def split_file(filepath):
    """Split a file into multiple parts (interactive mode)."""
    filepath = Path(filepath)

    if not filepath.exists():
        print(f"Error: El archivo '{filepath}' no existe.")
        return False

    if not filepath.is_file():
        print(f"Error: '{filepath}' no es un archivo válido.")
        return False

    file_size = filepath.stat().st_size
    if file_size == 0:
        print("Error: El archivo está vacío.")
        return False

    # Ask for number of parts
    while True:
        try:
            num_parts_str = input("¿En cuántos fragmentos dividir? ").strip()
            num_parts = int(num_parts_str)
            if num_parts < 2:
                print("Error: El número de partes debe ser al menos 2.")
                continue
            break
        except ValueError:
            print("Error: Introduce un número válido.")
            continue

    # Calculate part size
    part_size = file_size // num_parts
    if part_size == 0:
        print(f"Error: El archivo es demasiado pequeño para dividir en {num_parts} partes.")
        return False

    # Ask if user wants password protection
    use_password_response = input("¿Proteger con contraseña? (s/n): ").strip().lower()
    use_password = use_password_response in ['s', 'si', 'sí', 'y', 'yes']

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
    output_dir = filepath.parent
    part_names = generate_part_names(base_name, num_parts, extension)
    part_paths = [output_dir / name for name in part_names]

    # Check for existing files
    if not check_existing_files([str(p) for p in part_paths]):
        print("Operación cancelada.")
        return False

    # Calculate MD5 before splitting
    print(f"Calculando MD5 de '{filepath.name}'...")
    file_md5 = calculate_md5(filepath)
    print(f"  MD5: {file_md5}")
    print()

    # Read and split the file
    print(f"Dividiendo '{filepath.name}' en {num_parts} partes...")

    try:
        # Create part 0 with MD5 and original filename
        md5_part_path = part_paths[0]
        md5_content = f"{file_md5}  {original_name}\n".encode('utf-8')

        print(f"  [  0.0%] Creando {md5_part_path.name} (checksum)...", end="")

        if use_password:
            temp_part = output_dir / ".temp_part_md5"
            with open(temp_part, 'wb') as pf:
                pf.write(md5_content)

            cmd = ["7z", "a", "-tzip", "-bso0", "-bsp0"]
            if password:
                cmd.extend([f"-p{password}", "-mem=AES256"])
            cmd.extend([str(md5_part_path), str(temp_part)])

            result = subprocess.run(cmd, capture_output=True)
            temp_part.unlink()

            if result.returncode != 0:
                print(" Error!")
                print(f"Error al comprimir: {result.stderr.decode()}")
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
                print(f"  [{progress:5.1f}%] Creando {part_path.name}...", end="")

                if use_password:
                    # Create temporary file for the part
                    temp_part = output_dir / f".temp_part_{i}"
                    with open(temp_part, 'wb') as pf:
                        pf.write(data)

                    # Compress with 7z
                    cmd = ["7z", "a", "-tzip", "-bso0", "-bsp0"]
                    if password:
                        cmd.extend([f"-p{password}", "-mem=AES256"])
                    cmd.extend([str(part_path), str(temp_part)])

                    result = subprocess.run(cmd, capture_output=True)

                    # Remove temp file
                    temp_part.unlink()

                    if result.returncode != 0:
                        print(" Error!")
                        print(f"Error al comprimir: {result.stderr.decode()}")
                        return False
                else:
                    # Write raw part
                    with open(part_path, 'wb') as pf:
                        pf.write(data)

                print(" OK")

        print()
        print(f"¡Completado! Se crearon {num_parts + 1} archivos:")
        for p in part_paths:
            print(f"  - {p.name}")

        return True

    except IOError as e:
        print(f"Error de lectura/escritura: {e}")
        return False


def find_sequence_files(any_file):
    """Find all files in a sequence based on any file from the sequence.
    The user can provide any part (e.g., part 3) and we'll find all parts.
    """
    filepath = Path(any_file)

    if not filepath.exists():
        print(f"Error: El archivo '{filepath}' no existe.")
        return None, None, None

    filename = filepath.stem
    extension = filepath.suffix
    parent = filepath.parent

    # Try to extract base name and number pattern
    # Expected format: basename_01.ext or basename_001.ext etc.
    parts = filename.rsplit('_', 1)
    if len(parts) != 2:
        print(f"Error: El archivo no sigue el patrón esperado (nombre_numero{extension}).")
        return None, None, None

    base_name, num_str = parts

    if not num_str.isdigit():
        print(f"Error: El archivo no sigue el patrón esperado (nombre_numero{extension}).")
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
        print("Error: No se encontraron archivos en la secuencia.")
        return None, None, None

    # Warn if part 0 (MD5) is missing
    if not has_part_0:
        print("Advertencia: No se encontró el archivo de checksum (parte 0).")
        print("            No se podrá verificar la integridad del archivo.")
        print()

    return sequence_files, base_name, extension


def detect_original_extension(first_zip_path, password=None):
    """Try to detect the original file extension from the first zip."""
    cmd = ["7z", "l", "-slt", str(first_zip_path)]
    if password:
        cmd.insert(2, f"-p{password}")

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        return None

    # Parse output to find the filename inside
    for line in result.stdout.split('\n'):
        if line.startswith('Path = ') and not line.endswith('.zip'):
            inner_path = line[7:].strip()
            # This is typically .temp_part_X, so we can't detect extension
            # We'll need to ask or use a stored metadata approach
            return None

    return None


def check_zip_needs_password(zip_path):
    """Check if a ZIP file requires a password to extract."""
    # Try to test the archive without password
    cmd = ["7z", "t", "-p", str(zip_path)]
    result = subprocess.run(cmd, capture_output=True, text=True)

    # Check if it failed due to password
    output = result.stdout + result.stderr
    if "Wrong password" in output or "Enter password" in output or result.returncode != 0:
        # Try with empty password to distinguish encrypted from corrupted
        cmd_empty = ["7z", "t", "-p", str(zip_path)]
        result_empty = subprocess.run(cmd_empty, capture_output=True, text=True)
        output_empty = result_empty.stdout + result_empty.stderr

        if "Wrong password" in output_empty or "Cannot open encrypted" in output_empty:
            return True

    return False


def extract_md5_info(md5_part_path, is_compressed, password=None):
    """Extract MD5 and original filename from part 0.
    Returns: (md5_hash, filename, needs_password)
    """
    try:
        if is_compressed:
            temp_dir = md5_part_path.parent / ".temp_extract_md5"
            temp_dir.mkdir(exist_ok=True)

            # Always use -p flag to prevent 7z from waiting for interactive input
            # Empty password (-p) will fail on encrypted files, which we detect
            pwd_flag = f"-p{password}" if password else "-p"
            cmd = ["7z", "e", pwd_flag, "-bso0", "-bsp0", f"-o{temp_dir}", "-y", str(md5_part_path)]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                shutil.rmtree(temp_dir, ignore_errors=True)
                # Check if it's a password error
                error_output = result.stdout + result.stderr
                if "Wrong password" in error_output or "Cannot open encrypted" in error_output:
                    return None, None, True  # Needs password
                return None, None, False

            extracted_files = list(temp_dir.iterdir())
            if extracted_files:
                content = extracted_files[0].read_text('utf-8').strip()
            else:
                content = None

            shutil.rmtree(temp_dir, ignore_errors=True)
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


def join_files(first_file):
    """Join split files back into the original."""
    sequence_files, base_name, extension = find_sequence_files(first_file)

    if sequence_files is None:
        return False

    is_compressed = extension.lower() == ".zip"

    # Check if 7z is needed
    if is_compressed and not check_7z_installed():
        return False

    print(f"Encontrados {len(sequence_files)} archivos en la secuencia:")
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
        print("El archivo está protegido con contraseña.")
        password = get_password(confirm=False)
        md5_hash, stored_name, needs_password = extract_md5_info(sequence_files[0], is_compressed, password)

        if needs_password:
            print("Error: Contraseña incorrecta.")
            return False

    if md5_hash and stored_name:
        original_md5 = md5_hash
        original_name = stored_name
        data_files = sequence_files[1:]  # Skip part 0 for data reconstruction
        print(f"Detectado checksum MD5: {original_md5}")
        print(f"Nombre original: {original_name}")
        print()

    # Determine output filename
    if original_name:
        output_name = original_name
        print(f"Se usará el nombre original: {output_name}")
        response = input("¿Cambiar nombre? (Enter para mantener, o escribe nuevo nombre): ").strip()
        if response:
            output_name = response
    else:
        user_input = input(f"Nombre del archivo de salida (ej: {base_name}.jpg): ").strip()
        output_name = user_input if user_input else base_name

    output_path = Path(first_file).parent / output_name

    # Check if output exists
    if output_path.exists():
        if not ask_overwrite(str(output_path)):
            print("Operación cancelada.")
            return False

    print()
    print(f"Reconstruyendo '{output_name}'...")

    try:
        with open(output_path, 'wb') as outfile:
            for i, part_path in enumerate(data_files):
                progress = (i + 1) / len(data_files) * 100
                print(f"  [{progress:5.1f}%] Procesando {part_path.name}...", end="")

                if is_compressed:
                    # Extract from zip to temp file
                    temp_dir = part_path.parent / ".temp_extract"
                    temp_dir.mkdir(exist_ok=True)

                    # Always use -p flag to prevent 7z from waiting for interactive input
                    pwd_flag = f"-p{password}" if password else "-p"
                    cmd = ["7z", "e", pwd_flag, "-bso0", "-bsp0", f"-o{temp_dir}", "-y", str(part_path)]

                    result = subprocess.run(cmd, capture_output=True)

                    if result.returncode != 0:
                        print(" Error!")
                        error_msg = result.stderr.decode()
                        if "Wrong password" in error_msg or "password" in error_msg.lower():
                            print("Error: Contraseña incorrecta.")
                        else:
                            print(f"Error al descomprimir: {error_msg}")
                        # Cleanup
                        shutil.rmtree(temp_dir, ignore_errors=True)
                        output_path.unlink(missing_ok=True)
                        return False

                    # Find extracted file and read it
                    extracted_files = list(temp_dir.iterdir())
                    if extracted_files:
                        with open(extracted_files[0], 'rb') as pf:
                            outfile.write(pf.read())

                    # Cleanup temp dir
                    shutil.rmtree(temp_dir, ignore_errors=True)
                else:
                    # Read raw part
                    with open(part_path, 'rb') as pf:
                        outfile.write(pf.read())

                print(" OK")

        print()
        print(f"Archivo reconstruido: {output_path}")

        # Verify MD5 if available
        if original_md5:
            print()
            print("Verificando integridad...")
            reconstructed_md5 = calculate_md5(output_path)
            print(f"  MD5 original:      {original_md5}")
            print(f"  MD5 reconstruido:  {reconstructed_md5}")

            if original_md5 == reconstructed_md5:
                print()
                print("  [OK] Integridad verificada correctamente")
            else:
                print()
                print("  [ERROR] Los checksums NO coinciden. El archivo puede estar corrupto.")
                return False

        print()

        # Ask if user wants to delete the fragment files
        response = input("¿Eliminar los archivos fragmentados? (s/n): ").strip().lower()
        if response in ['s', 'si', 'sí', 'y', 'yes']:
            print()
            print("Eliminando fragmentos...")
            for fragment in sequence_files:
                try:
                    fragment.unlink()
                    print(f"  - {fragment.name} eliminado")
                except OSError as e:
                    print(f"  - Error al eliminar {fragment.name}: {e}")
            print()
            print("Fragmentos eliminados.")

        return True

    except IOError as e:
        print(f"Error de lectura/escritura: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Carpenter - Herramienta para dividir y unir archivos",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  %(prog)s -cut archivo.jpg           Divide archivo (modo interactivo)
  %(prog)s -glue archivo_01.part      Une archivos fragmentados
        """
    )

    # Mode arguments (mutually exclusive)
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("-cut", action="store_true",
                           help="Dividir archivo (modo interactivo)")
    mode_group.add_argument("-glue", action="store_true",
                           help="Unir archivos fragmentados")

    # File argument (positional, at the end)
    parser.add_argument("file", help="Archivo a procesar")

    args = parser.parse_args()

    if args.cut:
        success = split_file(args.file)
    else:
        success = join_files(args.file)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
