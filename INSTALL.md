# Instalación — ia-model-scan

Scanner de seguridad para modelos IA (Fickling + ModelScan + GGUF nativo).  
Probado en **RHEL 8 / RHEL 9 / Rocky Linux 8-9 / AlmaLinux 8-9**.

---

## Requisitos

| Requisito | Versión mínima |
|-----------|---------------|
| Python | 3.10 o superior |
| pip | cualquier versión reciente |
| git | para clonar el repo |
| Acceso a internet | para descargar dependencias y modelos |

---

## 1. Verificar Python 3.10+

```bash
python3 --version   # debe mostrar 3.10.x o superior
```

**Si la versión es inferior a 3.10** (ej: RHEL 9 trae 3.9 por defecto):

```bash
sudo dnf install -y python3.11
```

Si `python3.11` no aparece en los repos, habilitar el módulo AppStream primero:

```bash
sudo dnf module enable -y python311
sudo dnf install -y python3.11
```

> **Importante:** no cambiar el `python3` del sistema con `alternatives`. Usar `python3.11`
> de forma explícita solo para crear el venv (paso 3). El scanner no depende del PATH del sistema.

---

## 2. Clonar el repositorio

```bash
git clone <url-del-repo> ia-model-scan
cd ia-model-scan
```

Si hay un `ia_model_scan.egg-info` de una instalación anterior fallida, eliminarlo antes de continuar:

```bash
rm -rf ia_model_scan.egg-info
```

---

## 3. Crear entorno virtual

> **Nunca usar `sudo` para crear el venv.** Si se crea con sudo, los archivos quedan
> en propiedad de root y los `pip install` posteriores fallan con errores de permisos.
> Verificar el dueño con `ls -la venv/bin/python3` — debe ser tu usuario, no root.

Si `python3` ya es 3.10+:

```bash
python3 -m venv venv
```

Si el sistema tiene Python < 3.10 y se instaló `python3.11`:

```bash
python3.11 -m venv venv
```

Activar el entorno:

```bash
source venv/bin/activate
```

Verificar que el entorno usa la versión correcta:

```bash
python3 --version   # debe mostrar 3.10.x o superior
```

---

## 4. Instalar pip si no está disponible

Dentro del venv activado, verificar que pip funciona:

```bash
python3 -m pip --version
```

Si retorna `No module named pip`:

```bash
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python3 get-pip.py
rm get-pip.py
```

---

## 5. Instalar dependencias

Siempre usar `python3 -m pip` en lugar de `pip` directamente, para garantizar que se instala en el venv y no en el usuario del sistema:

```bash
python3 -m pip install --upgrade pip
python3 -m pip install -e .
```

Esto instala:
- `fickling` — análisis de archivos Pickle
- `modelscan` — escáner de formatos ML
- `huggingface-hub` — descarga de modelos desde HuggingFace
- `python-dotenv` — carga de variables de entorno

Verificar que las librerías están instaladas en el venv:

```bash
python3 -m pip list | grep -E "fickling|modelscan"
```

> **Nota:** el scanner invoca fickling y modelscan como módulos Python (`python3 -m fickling`),
> no como comandos del sistema. No es necesario que los binarios estén en el PATH.

---

## 6. Configurar variables de entorno

```bash
cp .env.example .env
```

Editar `.env`:

```bash
# Token de HuggingFace — obligatorio para modelos gated (llama, gemma, etc.)
# Obtenerlo en: https://huggingface.co/settings/tokens
HF_TOKEN=hf_tu_token_aqui

# Timeouts de descarga (segundos)
HF_HUB_DOWNLOAD_TIMEOUT=300
HF_HUB_ETAG_TIMEOUT=1800

# Carpeta local donde se guardan los modelos
MODELS_BASE_DIR=./models
```

> Si solo se va a usar el scanner (sin descargar modelos), `HF_TOKEN` no es necesario.

---

## 7. Verificar instalación

```bash
python3 scanner.py
```

La salida debe mostrar el Python del venv y confirmar que los módulos están disponibles:

```
🔧 Verificando herramientas...
   Python: /ruta/ia-model-scan/venv/bin/python3
   ✅ fickling      → /ruta/ia-model-scan/venv/bin/fickling
   ✅ modelscan     → /ruta/ia-model-scan/venv/bin/modelscan
```

---

## 8. Uso básico

```bash
# Escanear una ruta (archivo o directorio)
python3 scanner.py /ruta/al/modelo

# Escanear directorio actual
python3 scanner.py .

# Escanear una lista de rutas desde archivo de texto
python3 scanner.py -file modelos.txt

# Descargar modelos definidos en models_catalog.py
python3 downloader.py

# Consultar tamaño de modelos en HuggingFace sin descargarlos
python3 size_checker.py
```

Los resultados se guardan automáticamente en:
- `logs/scan_YYYYMMDD_HHMMSS.log` — log completo en texto
- `reports/scan_YYYYMMDD_HHMMSS.json` — reporte en JSON

---

## Solución de problemas frecuentes en RHEL

### `Package requires a different Python: 3.9.x not in '>=3.10'`
El venv fue creado con Python 3.9. Eliminarlo y recrearlo con 3.11:
```bash
deactivate
rm -rf venv
sudo dnf install -y python3.11
python3.11 -m venv venv
source venv/bin/activate
python3 -m pip install -e .
```

### `Defaulting to user installation because normal site-packages is not writeable`
pip está instalando en `~/.local` en vez del venv — el venv no está activo. Ejecutar:
```bash
source venv/bin/activate
python3 -m pip install -e .   # usar python3 -m pip, no pip directamente
```

### `No module named pip` dentro del venv
```bash
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python3 get-pip.py
rm get-pip.py
```

### `fickling → NO encontrado` / `modelscan → NO encontrado`
Las librerías no están instaladas en el venv activo:
```bash
source venv/bin/activate
python3 -m pip list | grep -E "fickling|modelscan"   # verificar
python3 -m pip install fickling modelscan              # reinstalar si no aparecen
```

### Venv creado con sudo — archivos en propiedad de root
Síntoma: errores de permisos al instalar, o `ls -la venv/bin/python3` muestra `root` como dueño.
```bash
sudo rm -rf venv
python3 -m venv venv          # sin sudo
source venv/bin/activate
python3 -m pip install -e .
```

### `pip install` falla con `gcc` o compilación de extensiones C
```bash
sudo dnf install -y gcc python3-devel
# o si se instaló python3.11 explícitamente:
sudo dnf install -y gcc python3.11-devel
```

### Error de certificados SSL al instalar con pip
```bash
sudo dnf install -y ca-certificates
python3 -m pip install --upgrade certifi
```

### Descarga incompleta de modelos (solo descarga unos MB)
Problema de red o timeout. Eliminar la carpeta parcial y reintentar:
```bash
rm -rf models/Helsinki-NLP/opus-mt-es-en   # ajustar al modelo que falló
python3 downloader.py
```
Si persiste, aumentar los timeouts en `.env`:
```bash
HF_HUB_DOWNLOAD_TIMEOUT=600
HF_HUB_ETAG_TIMEOUT=3600
```

---

## Activar el entorno en cada sesión

El virtualenv **no persiste entre sesiones de terminal**. Cada vez que se abre una nueva sesión:

```bash
cd /ruta/a/ia-model-scan
source venv/bin/activate
```

Para evitar olvidarlo, se puede agregar un alias al `~/.bashrc`:

```bash
echo "alias ia-scan='cd /ruta/a/ia-model-scan && source venv/bin/activate'" >> ~/.bashrc
```
