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

    print("Error: pyzipper no está instalado.")
    print()
    print("Para habilitar partes ZIP protegidas con contraseña, ejecuta:")
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
        if not check_pyzipper_installed():
            return False
        password = get_password(confirm=True)

    # Generate output filenames (includes part 0 for MD5)
    base_name = filepath.stem
    original_name = filepath.name
    output_dir = filepath.parent / base_name  # Crear subdirectorio con el nombre del archivo
    part_names = generate_part_names(base_name, num_parts, extension)
    part_paths = [output_dir / name for name in part_names]

    # Verificar que el directorio de salida no sea un archivo existente
    if output_dir.exists() and not output_dir.is_dir():
        print(f"Error: '{output_dir}' existe pero no es un directorio.")
        return False

    # Check for existing files
    if not check_existing_files([str(p) for p in part_paths]):
        print("Operación cancelada.")
        return False

    # Calculate MD5 before splitting
    print(f"Calculando MD5 de '{filepath.name}'...")
    file_md5 = calculate_md5(filepath)
    print(f"  MD5: {file_md5}")
    print()

    # Crear directorio de salida
    output_dir.mkdir(exist_ok=True)
    print(f"Directorio de salida: {output_dir}")
    print()

    # Read and split the file
    print(f"Dividiendo '{filepath.name}' en {num_parts} partes...")

    try:
        # Create part 0 with MD5 and original filename
        md5_part_path = part_paths[0]
        md5_content = f"{file_md5}  {original_name}\n".encode('utf-8')

        print(f"  [  0.0%] Creando {md5_part_path.name} (checksum)...", end="")

        if use_password:
            try:
                write_zip_part(md5_part_path, ".part_md5", md5_content, password)
            except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as e:
                print(" Error!")
                print(f"Error al comprimir: {e}")
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
                    try:
                        write_zip_part(part_path, f".part_{i}", data, password)
                    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as e:
                        print(" Error!")
                        print(f"Error al comprimir: {e}")
                        return False
                else:
                    # Write raw part
                    with open(part_path, 'wb') as pf:
                        pf.write(data)

                print(" OK")

        print()
        print(f"¡Completado! Se crearon {num_parts + 1} archivos en '{output_dir}':")
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
    """Construye una ruta de salida segura dentro de base_dir desde un nombre no confiable."""
    candidate = (filename or "").strip()
    if not candidate:
        raise ValueError("El nombre del archivo de salida no puede estar vacío.")

    user_path = Path(candidate)
    if user_path.is_absolute():
        raise ValueError("No se permiten rutas de salida absolutas.")

    if len(user_path.parts) != 1:
        raise ValueError("El nombre de salida no puede incluir directorios.")

    safe_name = user_path.name
    if safe_name in {"", ".", ".."}:
        raise ValueError("Nombre de archivo de salida no válido.")

    base_resolved = Path(base_dir).resolve()
    output_path = (base_resolved / safe_name).resolve()

    try:
        output_path.relative_to(base_resolved)
    except ValueError as exc:
        raise ValueError("La ruta de salida sale del directorio de trabajo.") from exc

    if output_path.exists() and output_path.is_symlink():
        raise ValueError("Se rechaza escribir sobre un enlace simbólico.")

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

    base_dir = Path(first_file).parent
    while True:
        try:
            output_path = safe_output_path(base_dir, output_name)
            break
        except ValueError as e:
            print(f"Error: {e}")
            output_name = input(f"Nombre del archivo de salida (ej: {base_name}.jpg): ").strip()
            if not output_name:
                print("Operación cancelada.")
                return False

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
                    try:
                        part_bytes, _ = read_first_zip_member(part_path, password=password)
                    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as e:
                        print(" Error!")
                        if zip_requires_password(part_path) and (password is None or is_password_error(e)):
                            print("Error: Contraseña incorrecta.")
                        else:
                            print(f"Error al descomprimir: {e}")
                        output_path.unlink(missing_ok=True)
                        return False

                    if part_bytes is None:
                        print(" Error!")
                        print("Error al descomprimir: la parte ZIP no contiene archivos.")
                        output_path.unlink(missing_ok=True)
                        return False

                    outfile.write(part_bytes)
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
  %(prog)s -split archivo.jpg       Divide archivo (modo interactivo)
  %(prog)s -join archivo_01.part    Une archivos fragmentados
        """
    )

    # Mode arguments (mutually exclusive)
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("-split", action="store_true",
                           help="Dividir archivo (modo interactivo)")
    mode_group.add_argument("-join", action="store_true",
                           help="Unir archivos fragmentados")

    # File argument (positional, at the end)
    parser.add_argument("file", help="Archivo a procesar")

    args = parser.parse_args()

    if args.split:
        success = split_file(args.file)
    else:
        success = join_files(args.file)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
