# Carpenter

Herramienta de línea de comandos para dividir archivos en múltiples partes y reconstruirlos posteriormente. Soporta compresión ZIP con cifrado AES-256.

## Características

- Divide cualquier archivo en N partes iguales
- Compresión ZIP opcional con cifrado AES-256
- Verificación de integridad mediante MD5 (automática)
- Detecta automáticamente todas las partes de una secuencia
- Detecta automáticamente si los archivos ZIP requieren contraseña
- Modo completamente interactivo
- Opción de eliminar fragmentos después de reconstruir

## Requisitos

- Python 3.6+
- `p7zip` (solo si se usa protección con contraseña)

### Instalar p7zip

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

## Instalación

```bash
# Clonar el repositorio
git clone https://github.com/function0xmarki/carpenter.git
cd carpenter

# Dar permisos de ejecución
chmod +x carpenter.py
```

## Uso

### Dividir archivos (-split)

```bash
python3 carpenter.py -split archivo.jpg
```

El script preguntará interactivamente:
1. ¿En cuántos fragmentos dividir?
2. ¿Proteger con contraseña? (s/n)
   - Si es **sí**: pide contraseña y confirmación, genera archivos `.zip` con AES-256
   - Si es **no**: genera archivos `.part` sin comprimir

### Unir archivos (-join)

```bash
python3 carpenter.py -join archivo_01.part
```

> **Nota:** Puedes especificar cualquier parte de la secuencia (no necesariamente la parte 0). El script encontrará automáticamente todas las partes y detectará si necesita contraseña.

Al finalizar, preguntará si deseas eliminar los fragmentos.

### Ver ayuda

```bash
python3 carpenter.py --help
```

## Estructura de archivos generados

Al dividir `foto.jpg` en 3 partes:

| Archivo | Contenido |
|---------|-----------|
| `foto_0.part` | Checksum MD5 + nombre original |
| `foto_1.part` | Datos (parte 1) |
| `foto_2.part` | Datos (parte 2) |
| `foto_3.part` | Datos (parte 3) |

La parte `_0` contiene metadatos para verificar la integridad y restaurar el nombre original del archivo.

## Opciones

| Argumento | Descripción |
|-----------|-------------|
| `-split` | Divide el archivo (modo interactivo) |
| `-join` | Une las partes en el archivo original |
| `-h, --help` | Muestra la ayuda |

## Seguridad

- Las contraseñas se solicitan de forma interactiva y no se muestran en pantalla
- Al dividir con contraseña, se pide confirmación
- Al unir, se detecta automáticamente si el archivo requiere contraseña
- El cifrado utiliza AES-256 mediante 7-Zip
- El checksum MD5 permite verificar que el archivo no ha sido modificado

## Licencia

MIT License
