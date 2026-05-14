# ia-model-scan

Scanner de seguridad para modelos de IA/ML. Detecta payloads maliciosos en archivos Pickle, SafeTensors, GGUF y HDF5 antes de desplegarlos en producción.

## Qué hace

Analiza archivos de modelo buscando vectores de ataque conocidos:

| Formato | Motor de análisis |
|---------|------------------|
| `.bin`, `.pkl` | Fickling (análisis Pickle) + ModelScan como fallback |
| `.safetensors` | ModelScan |
| `.h5` | ModelScan (Keras/HDF5) |
| `.gguf` | Validación nativa — magic, versión, metadata |

Para cada archivo genera: resultado (LIMPIO / PELIGROSO), hash SHA256, tamaño, y explicación de cada amenaza detectada con el riesgo concreto en entornos de producción.

Los resultados se guardan en `logs/` (texto) y `reports/` (JSON).

## Amenazas detectadas

- `__reduce__` / `GLOBAL` / `newobj` — ejecución de código arbitrario al deserializar (RCE clásico via Pickle)
- `exec` / `eval` — ejecución dinámica de código Python
- `os.system` / `subprocess` — comandos del sistema operativo
- `socket` / `pty` — exfiltración de datos o shell reversa
- `importlib` / `builtins.open` — importación dinámica o acceso al filesystem
- En GGUF: IPs embebidas, llamadas a shell, scripts ejecutables en metadata

## Instalación

Ver [INSTALL.md](INSTALL.md) para instrucciones detalladas, incluyendo Red Hat / RHEL.

Resumen rápido:

```bash
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -e .
cp .env.example .env
```

## Uso

```bash
# Escanear un directorio de modelos
python3 scanner.py ./models

# Escanear un archivo concreto
python3 scanner.py ./models/Helsinki-NLP/opus-mt-es-en/model.bin

# Escanear una lista de rutas (una por línea, # para comentarios)
python3 scanner.py -file modelos.txt
```

### Descargar modelos desde HuggingFace

Editar `models_catalog.py` para definir qué modelos descargar, luego:

```bash
python3 downloader.py
```

### Consultar tamaño sin descargar

```bash
python3 size_checker.py
```

## Configuración (.env)

```bash
# Token de HuggingFace — obligatorio para modelos gated (llama, gemma, etc.)
HF_TOKEN=hf_tu_token_aqui

# Timeouts de descarga (segundos)
HF_HUB_DOWNLOAD_TIMEOUT=300
HF_HUB_ETAG_TIMEOUT=1800

# Carpeta donde se guardan los modelos descargados
MODELS_BASE_DIR=./models
```

## Formato modelos.txt

```
./models/jinaai/jina-embeddings-v3
./models/Helsinki-NLP/opus-mt-en-es
# este es un comentario — se ignora
```

## Salida de ejemplo

```
════════════════════════════════════════════════════════════════
  🔐 SCANNER DE SEGURIDAD PARA MODELOS IA — v5.0
════════════════════════════════════════════════════════════════

  [1/2] ./models/Helsinki-NLP/opus-mt-es-en/model.bin
  Extensión : .bin
  Tamaño    : 301.2 MB
  SHA256    : a3f1e2...
  Método    : FICKLING → MODELSCAN (fallback)

  ╔═══════════════════════════════════════════╗
  ║   🟢  RESULTADO: LIMPIO                   ║
  ╚═══════════════════════════════════════════╝

────────────────────────────────────────────────────────────────
  Total escaneados  : 2
  🟢 Limpios        : 2
  🔴 Peligrosos     : 0
```

## Requisitos

- Python 3.10 o superior
- `fickling >= 0.1.3`
- `modelscan >= 0.8.0`
- `huggingface-hub >= 0.22.0`
- `python-dotenv >= 1.0.0`
