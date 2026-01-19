# Carpenter

Herramienta de línea de comandos para dividir archivos en múltiples partes y reconstruirlos posteriormente.

Soporta compresión ZIP con cifrado AES-256.

## Características

- Divide cualquier archivo en N partes iguales
- Compresión ZIP opcional con cifrado AES-256
- Verificación de integridad mediante MD5 (automática)
- Detecta automáticamente todas las partes de una secuencia
- Detecta automáticamente si los archivos ZIP requieren contraseña
- Contraseña solicitada de forma interactiva (no visible en terminal)

## Requisitos

- Python 3.6+
- `p7zip` (solo si se usa compresión ZIP)

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

### Dividir archivos (-cut)

```bash
# Dividir en 3 partes sin comprimir (.part)
python3 carpenter.py archivo.jpg -cut 3

# Dividir en 5 partes con compresión ZIP
python3 carpenter.py archivo.jpg -cut 5 -zip

# Dividir en 3 partes y contraseña (AES-256) "Generará obligatoriamente ZIP) 
python3 carpenter.py archivo.jpg -cut 3 -passwd
```

### Unir archivos (-glue)

```bash
# Unir partes .part
python3 carpenter.py archivo_0.part -glue

# Unir partes .zip (detecta automáticamente si requiere contraseña)
python3 carpenter.py archivo_0.zip -glue
```

> **Nota:** Puedes especificar cualquier parte de la secuencia (no necesariamente la parte 0). El script encontrará automáticamente todas las partes.


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
| `-cut N` | Divide el archivo en N partes |
| `-glue` | Une las partes en el archivo original |
| `-zip` | Comprime cada parte en formato ZIP (solo con `-cut`) |
| `-passwd` | Solicita contraseña para cifrar (solo con `-cut`, implica `-zip`) |

> **Nota:** Con `-glue` no es necesario especificar `-zip` ni `-passwd`. El script detecta automáticamente el formato y si requiere contraseña.

## Seguridad

- Las contraseñas se solicitan de forma interactiva y no se muestran en pantalla
- Al dividir con `-passwd`, se pide confirmación de contraseña
- Al unir, se detecta automáticamente si el archivo requiere contraseña
- El cifrado utiliza AES-256 mediante 7-Zip
- El checksum MD5 permite verificar que el archivo no ha sido modificado

## Licencia

MIT License
