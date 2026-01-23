# Instalación

## Requisitos

- Python 3.8+
- p7zip (opcional, solo para protección con contraseña)

## Dependencias de Python

No se requieren paquetes externos. Solo usa la biblioteca estándar de Python.

## Dependencias del Sistema

### p7zip (opcional)

Solo se requiere si deseas usar protección con contraseña.

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

## Verificar Instalación

```bash
# Verificar versión de Python
python3 --version

# Verificar instalación de 7z (opcional)
7z --help
```

## Uso

```bash
# Dividir un archivo
python3 carpenter.py -cut archivo.jpg

# Unir archivos
python3 carpenter.py -glue archivo_01.part
```
