#!/usr/bin/env python3
"""
====================================================
  SCANNER DE SEGURIDAD PARA MODELOS IA
  Fickling + ModelScan + Hash SHA256 + GGUF nativo
  v5.0

  USO:
    python3 scanner.py /ruta/al/modelo
    python3 scanner.py -file modelos.txt
    python3 scanner.py .

  FORMATO modelos.txt (una ruta por línea):
    ./models/jinaai/jina-embeddings-v3
    ./models/Helsinki-NLP/opus-mt-en-es
    # este es un comentario
====================================================
"""

import zipfile
import os
import sys
import glob
import subprocess
import shutil
import hashlib
import json
import struct
import re
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# ── Extensiones a escanear ────────────────────────────────────────────────────
EXTENSIONES_RIESGO  = [".bin", ".h5", ".pkl"]
EXTENSIONES_SEGURAS = [".safetensors", ".gguf"]
EXTENSIONES_TODAS   = EXTENSIONES_RIESGO + EXTENSIONES_SEGURAS

# ── Directorios a ignorar ─────────────────────────────────────────────────────
DIRS_IGNORAR = [
    "venv", ".venv", "env", ".env",
    "tmp_scan", ".git", "__pycache__",
    "node_modules", ".tox", "dist", "build",
    "site-packages",
]

# ── Keywords peligrosas y sus explicaciones ───────────────────────────────────
PELIGROS_EXPLICADOS = {
    "__reduce__"   : "Ejecuta código arbitrario al deserializar el modelo",
    "exec"         : "Ejecuta código Python dinámico — vector de ejecución remota",
    "eval"         : "Evalúa y ejecuta strings como código Python",
    "os.system"    : "Ejecuta comandos del sistema operativo directamente",
    "subprocess"   : "Puede lanzar procesos del sistema operativo",
    "GLOBAL"       : "Importa módulos arbitrarios de Python durante la carga",
    "builtins.open": "Acceso arbitrario al sistema de archivos",
    "importlib"    : "Importación dinámica — puede cargar código externo",
    "pty"          : "Acceso a terminales — riesgo de shell inversa",
    "socket"       : "Conexiones de red — riesgo de exfiltración de datos",
    "shutil.rmtree": "Puede eliminar directorios del sistema de archivos",
    "newobj"       : "Opcode NEWOBJ: instancia clases arbitrarias",
}

RIESGO_BANCO = {
    "__reduce__"   : "RCE clásico via Pickle — puede comprometer el servidor completo.",
    "exec"         : "Ejecución directa de código — riesgo crítico en producción.",
    "eval"         : "Evaluación de código dinámico — puede ejecutar instrucciones inyectadas.",
    "os.system"    : "Ejecuta comandos del SO en el servidor bancario.",
    "subprocess"   : "Lanza procesos del sistema — riesgo de escalada de privilegios.",
    "GLOBAL"       : "Importa módulos no controlados — puede cargar librerías maliciosas.",
    "builtins.open": "Acceso libre al FS — puede leer/escribir datos sensibles.",
    "importlib"    : "Carga código externo dinámicamente — riesgo post-despliegue.",
    "pty"          : "Shell reversa hacia el atacante.",
    "socket"       : "Exfiltración de datos bancarios via red.",
    "shutil.rmtree": "Destrucción masiva de archivos en producción.",
    "newobj"       : "Instancia objetos arbitrarios en memoria.",
}

# ── Patrones legítimos de PyTorch (falsos positivos) ─────────────────────────
FALSOS_POSITIVOS = [
    "_rebuild_tensor", "_rebuild_parameter",
    "persistent_load", "bfloat16storage",
    "floatstorage", "halfstorage", "bytestorage",
    "longstorage", "unsafeopsc", "__setstate__",
    "ordereddict", "_var",
]

LINEAS_BENIGNAS = [
    "no settings file", "using defaults", "no issues found",
    "total skipped", "run with --show-skipped",
    "scanning /", "--- summary ---", "--- skipped ---",
]

# ── Validación nativa GGUF ────────────────────────────────────────────────────
GGUF_MAGIC   = b"GGUF"
GGUF_MAX_STR = 1_000_000

GGUF_CLAVES_URL_PERMITIDAS = {
    "general.license.link",
    "general.source.url",
    "general.source.huggingface",
    "general.url",
    "general.doi",
    "general.arxiv",
}
GGUF_PREFIJOS_URL_PERMITIDOS = (
    "general.base_model.",
    "general.dataset.",
    "general.license.",
)

GGUF_PATRONES = [
    (r"https?://",                             "URL HTTP externa en metadata",          True),
    (r"ftp://",                                "URL FTP externa en metadata",           True),
    (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  "Dirección IP embebida",                False),
    (r"(bash|sh|cmd|powershell)\s+-c\s+",     "Llamada a intérprete de shell",         False),
    (r"import\s+os|import\s+subprocess",       "Import Python embebido",               False),
    (r"#!/",                                   "Shebang — script ejecutable embebido", False),
    (r"\$\(|`[^`]{1,200}`",                   "Sustitución de comando shell",          False),
    (r"curl\s+|wget\s+",                       "Descarga remota embebida",             False),
    (r"\bnc\s+-|\bnetcat\b",                  "Netcat — posible shell reversa",        False),
    (r"\beval\s*\(",                           "eval() en metadata",                   False),
    (r"\bexec\s*\(",                           "exec() en metadata",                   False),
]

RIESGO_GGUF = {
    "URL HTTP externa en metadata":         "Conexión a servidor externo al cargar el modelo — exfiltración potencial.",
    "URL FTP externa en metadata":          "Transferencia de datos via FTP embebida en el modelo.",
    "Dirección IP embebida":                "Endpoint hardcodeado — posible servidor C2.",
    "Llamada a intérprete de shell":        "Ejecución de comandos del SO desde metadata — RCE.",
    "Import Python embebido":               "Código Python en metadata — requiere revisión manual.",
    "Shebang — script ejecutable embebido": "Script ejecutable embebido en el modelo.",
    "Sustitución de comando shell":         "Ejecución dinámica de comandos — vector RCE.",
    "Descarga remota embebida":             "Intento de descarga desde servidor externo.",
    "Netcat — posible shell reversa":       "Shell reversa hacia el atacante — crítico.",
    "eval() en metadata":                   "Ejecución de código dinámico — vector de inyección.",
    "exec() en metadata":                   "Ejecución de código arbitrario — riesgo crítico.",
}


def _gu32(f): return struct.unpack("<I", f.read(4))[0]
def _gu64(f): return struct.unpack("<Q", f.read(8))[0]

def _gstr(f, ver):
    n = _gu32(f) if ver == 1 else _gu64(f)
    if n > GGUF_MAX_STR:
        raise ValueError(f"String demasiado largo: {n} bytes")
    return f.read(n).decode("utf-8", errors="replace")

_GSIZES = {0:1, 1:1, 2:2, 3:2, 4:4, 5:4, 6:4, 7:1, 10:8, 11:8, 12:8}

def _gval(f, vtype, ver):
    if vtype == 8:
        return _gstr(f, ver)
    if vtype == 9:
        etype = _gu32(f)
        count = _gu32(f) if ver == 1 else _gu64(f)
        if etype in _GSIZES:
            f.read(count * _GSIZES[etype])
            return None
        texts = []
        for i in range(count):
            v = _gval(f, etype, ver)
            if v is not None and i < 32:
                texts.append(str(v))
        return " | ".join(texts) if texts else None
    if vtype in _GSIZES:
        f.read(_GSIZES[vtype])
        return None
    raise ValueError(f"Tipo GGUF desconocido: {vtype}")


def validar_gguf(filepath):
    checks, alertas, meta = {}, [], {}
    try:
        with open(filepath, "rb") as f:
            magic = f.read(4)
            if magic != GGUF_MAGIC:
                return "CORRUPTO", {"error": f"Magic inválido: {magic!r}", "checks": checks}
            checks["magic"] = "OK  (GGUF)"

            ver = _gu32(f)
            if ver not in {1, 2, 3}:
                alertas.append(f"Versión GGUF desconocida: {ver}")
                checks["version"] = f"ALERTA  (v{ver} — desconocida)"
            else:
                checks["version"] = f"OK  (v{ver})"

            tc = _gu32(f) if ver == 1 else _gu64(f)
            checks["tensor_count"] = f"OK  ({tc:,} tensores)"

            mc = _gu32(f) if ver == 1 else _gu64(f)
            checks["meta_count"] = f"OK  ({mc:,} entradas)"

            if ver == 1:
                checks["metadata"] = "INFO  (v1: análisis de metadata omitido)"
            else:
                for _ in range(min(mc, 2000)):
                    key   = _gstr(f, ver)
                    vtype = _gu32(f)
                    val   = _gval(f, vtype, ver)
                    if val is not None:
                        meta[key] = str(val)
                checks["metadata"] = f"OK  ({len(meta)} claves con texto)"

                for clave in ("general.name", "general.architecture",
                              "general.author", "general.license"):
                    if clave in meta:
                        checks[clave.replace("general.", "")] = meta[clave]

                for key, val in meta.items():
                    clave_url_segura = (
                        key in GGUF_CLAVES_URL_PERMITIDAS or
                        key.startswith(GGUF_PREFIJOS_URL_PERMITIDOS)
                    )
                    for patron, desc, respetar_whitelist in GGUF_PATRONES:
                        if respetar_whitelist and clave_url_segura:
                            continue
                        if re.search(patron, f"{key}={val}", re.IGNORECASE):
                            msg = f"{desc}  →  clave '{key}': {val[:100]}"
                            if msg not in alertas:
                                alertas.append(msg)

    except (struct.error, EOFError) as e:
        return "CORRUPTO", {"error": f"Archivo truncado/malformado: {e}", "checks": checks}
    except Exception as e:
        return "CORRUPTO", {"error": str(e), "checks": checks}

    return ("PELIGROSO" if alertas else "LIMPIO"), {
        "checks": checks, "alertas": alertas, "meta": meta
    }


# ── Formato de tamaño ────────────────────────────────────────────────────────
def format_size(bytes_size):
    if not bytes_size:
        return "desconocido"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_size < 1024:
            return f"{bytes_size:.1f} {unit}"
        bytes_size /= 1024
    return f"{bytes_size:.1f} PB"


# ── Colores ───────────────────────────────────────────────────────────────────
C = {
    "R" : "\033[91m", "G" : "\033[92m", "Y" : "\033[93m",
    "B" : "\033[94m", "C" : "\033[96m", "W" : "\033[97m",
    "RST": "\033[0m", "BD" : "\033[1m", "DIM": "\033[2m",
}

def c(color, texto):
    return f"{C[color]}{texto}{C['RST']}"

LOG_LINES = []

def log(texto=""):
    limpio = texto
    for v in C.values():
        limpio = limpio.replace(v, "")
    LOG_LINES.append(limpio)
    print(texto)

def sep(char="─", n=64):
    log(c("DIM", char * n))

def titulo(texto, char="═"):
    log(c("BD", char * 64))
    log(c("BD", f"  {texto}"))
    log(c("BD", char * 64))


# ── Parsear argumentos ────────────────────────────────────────────────────────
def parsear_args():
    args = sys.argv[1:]

    if not args:
        print(f"""
{c('BD', 'USO:')}
  {c('G', 'python3 scanner.py /ruta/modelo')}           ← escanea una ruta
  {c('G', 'python3 scanner.py -file modelos.txt')}      ← escanea lista de rutas
  {c('G', 'python3 scanner.py .')}                       ← escanea directorio actual

{c('BD', 'FORMATO modelos.txt')} (una ruta por línea, # para comentarios):
  ./models/jinaai/jina-embeddings-v3
  ./models/Helsinki-NLP/opus-mt-en-es
  # este es un comentario
""")
        sys.exit(0)

    if args[0] == "-file":
        if len(args) < 2:
            print(c("R", "❌ Falta el nombre del archivo después de -file"))
            sys.exit(1)
        archivo = args[1]
        if not os.path.exists(archivo):
            print(c("R", f"❌ Archivo no encontrado: {archivo}"))
            sys.exit(1)
        with open(archivo, "r") as f:
            rutas = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        if not rutas:
            print(c("Y", f"⚠️  El archivo '{archivo}' está vacío o solo tiene comentarios."))
            sys.exit(0)
        return rutas

    return [args[0]]


# ── Descubrir archivos de modelo en una ruta ──────────────────────────────────
def descubrir_archivos(ruta):
    archivos = []

    if os.path.isfile(ruta):
        if os.path.splitext(ruta)[1].lower() in EXTENSIONES_TODAS:
            archivos.append(ruta)
        return archivos

    if not os.path.isdir(ruta):
        log(c("Y", f"  ⚠️  Ruta no válida: {ruta}"))
        return archivos

    for ext in EXTENSIONES_TODAS:
        for f in glob.glob(os.path.join(ruta, "**", f"*{ext}"), recursive=True):
            partes = f.replace("\\", "/").split("/")
            if any(d in partes for d in DIRS_IGNORAR):
                continue
            archivos.append(f)

    return sorted(set(archivos))


# ── SHA256 ────────────────────────────────────────────────────────────────────
def sha256(filepath):
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return f"ERROR: {e}"


# ── Filtros de falsos positivos ───────────────────────────────────────────────
def es_falso_positivo(linea):
    ll = linea.lower()
    return any(p.lower() in ll for p in FALSOS_POSITIVOS)

def es_linea_benigna(linea):
    ll = linea.lower()
    return any(p.lower() in ll for p in LINEAS_BENIGNAS)


# ── Analizar con Fickling (ZIP PyTorch → .pkl) ────────────────────────────────
def analizar_fickling(filepath):
    tmp = "./tmp_scan_pkl"
    try:
        if os.path.exists(tmp):
            shutil.rmtree(tmp)
        os.makedirs(tmp, exist_ok=True)

        with zipfile.ZipFile(filepath, "r") as z:
            z.extractall(tmp)

        pkl_path = None
        for root, _, files in os.walk(tmp):
            for f in files:
                if f.endswith(".pkl"):
                    pkl_path = os.path.join(root, f)
                    break

        if not pkl_path:
            return None, "sin_pkl"

        r = subprocess.run([_bin("fickling"), pkl_path], capture_output=True, text=True, timeout=120)
        return r.stdout + r.stderr, "fickling"

    except zipfile.BadZipFile:
        r = subprocess.run([_bin("modelscan"), "-p", filepath], capture_output=True, text=True, timeout=180)
        return r.stdout + r.stderr, "modelscan_fallback"
    except Exception as e:
        return f"ERROR: {e}", "error"
    finally:
        if os.path.exists(tmp):
            shutil.rmtree(tmp)


# ── Analizar con ModelScan ────────────────────────────────────────────────────
def analizar_modelscan(filepath):
    try:
        r = subprocess.run([_bin("modelscan"), "-p", filepath], capture_output=True, text=True, timeout=180)
        return r.stdout + r.stderr, "modelscan"
    except Exception as e:
        return f"ERROR: {e}", "error"


# ── Evaluar riesgo ────────────────────────────────────────────────────────────
def evaluar(salida):
    if not salida:
        return "INDETERMINADO", {}

    salida_lower = salida.lower()
    lineas = salida.strip().split("\n")

    if "no issues found" in salida_lower:
        return "LIMPIO", {}

    peligros = {}
    for keyword, explicacion in PELIGROS_EXPLICADOS.items():
        sospechosas = [
            l.strip() for l in lineas
            if l.strip()
            and not es_falso_positivo(l)
            and not es_linea_benigna(l)
            and keyword.lower() in l.lower()
        ]
        if sospechosas:
            peligros[keyword] = {"explicacion": explicacion, "lineas": sospechosas}

    if peligros:
        return "PELIGROSO", peligros
    elif "error" in salida_lower and "no issues" not in salida_lower:
        return "ERROR", {}
    return "LIMPIO", {}


# ── Escanear un archivo ───────────────────────────────────────────────────────
def escanear_archivo(filepath, idx, total):
    ext = os.path.splitext(filepath)[1].lower()
    resultado = {
        "archivo"    : filepath,
        "extension"  : ext,
        "size_bytes" : 0,
        "sha256"     : "",
        "estado"     : "INDETERMINADO",
        "metodo"     : "",
        "peligros"   : {},
    }

    log()
    sep()
    log(c("BD", f"  [{idx}/{total}] {filepath}"))
    sep()
    log(c("DIM", f"  Extensión : {ext}"))

    try:
        size_bytes = os.path.getsize(filepath)
        resultado["size_bytes"] = size_bytes
        log(c("DIM", f"  Tamaño    : {format_size(size_bytes)}"))
    except OSError:
        log(c("Y", "  Tamaño    : no disponible"))

    print(c("DIM", "  SHA256    : calculando..."), end="\r", flush=True)
    hash_val = sha256(filepath)
    resultado["sha256"] = hash_val
    log(c("DIM", f"  SHA256    : {hash_val}"))

    if ext == ".safetensors":
        log(c("DIM", "  Método    : MODELSCAN (formato seguro safetensors)"))
        salida, metodo = analizar_modelscan(filepath)
        estado, peligros = evaluar(salida)
        resultado["metodo"] = metodo

    elif ext in [".bin", ".pkl"]:
        log(c("DIM", "  Método    : FICKLING → MODELSCAN (fallback)"))
        salida, metodo = analizar_fickling(filepath)
        if metodo == "modelscan_fallback":
            log(c("Y", "  ℹ️  Fallback: no era ZIP PyTorch, se usó modelscan"))
        estado, peligros = evaluar(salida)
        resultado["metodo"] = metodo

    elif ext == ".h5":
        log(c("DIM", "  Método    : MODELSCAN (formato HDF5/Keras)"))
        salida, metodo = analizar_modelscan(filepath)
        estado, peligros = evaluar(salida)
        resultado["metodo"] = metodo

    elif ext == ".gguf":
        log(c("DIM", "  Método    : VALIDACIÓN NATIVA GGUF"))
        estado, detalles = validar_gguf(filepath)
        resultado["metodo"] = "gguf_nativo"

        for k, v in detalles.get("checks", {}).items():
            col = "R" if ("ALERTA" in v or "FALLO" in v) else "G"
            log(c(col, f"    {k:<22}: {v}"))
        if "error" in detalles:
            log(c("R", f"  Error     : {detalles['error']}"))

        peligros = {}
        for alerta in detalles.get("alertas", []):
            desc = alerta.split("  →  ")[0] if "  →  " in alerta else alerta[:60]
            if desc not in peligros:
                peligros[desc] = {
                    "explicacion": alerta,
                    "lineas": [],
                    "_riesgo": RIESGO_GGUF.get(desc, "Contenido sospechoso en metadata GGUF."),
                }
            peligros[desc]["lineas"].append(alerta)

    else:
        log(c("Y", f"  ⚠️  Extensión no soportada: {ext}"))
        return resultado

    resultado["estado"]   = estado
    resultado["peligros"] = peligros

    log()
    if estado == "PELIGROSO":
        log(c("R", "  ╔═══════════════════════════════════════════╗"))
        log(c("R", "  ║   🔴  RESULTADO: PELIGROSO                ║"))
        log(c("R", "  ╚═══════════════════════════════════════════╝"))
    elif estado == "LIMPIO":
        log(c("G", "  ╔═══════════════════════════════════════════╗"))
        log(c("G", "  ║   🟢  RESULTADO: LIMPIO                   ║"))
        log(c("G", "  ╚═══════════════════════════════════════════╝"))
    else:
        log(c("Y", "  ╔═══════════════════════════════════════════╗"))
        log(c("Y", f"  ║   🟡  RESULTADO: {estado:<26}║"))
        log(c("Y", "  ╚═══════════════════════════════════════════╝"))

    if estado == "PELIGROSO" and peligros:
        log()
        log(c("R", "  " + "▓" * 52))
        log(c("R", c("BD", "  ⚠️  EXPLICACIÓN DE PELIGROS DETECTADOS")))
        log(c("R", "  " + "▓" * 52))

        for i, (kw, info) in enumerate(peligros.items(), 1):
            log()
            log(c("BD",  f"  [{i}] Keyword     : {c('R', kw)}"))
            log(c("Y",   f"      Significado : {info['explicacion']}"))
            log(c("Y",    "      Aparece en  :"))
            for linea in info["lineas"][:5]:
                log(c("C", f"        › {linea}"))
            riesgo = info.get("_riesgo") or RIESGO_BANCO.get(kw, "Compromete el entorno de producción bancario.")
            log(c("Y",    "      Riesgo banco:"))
            log(c("R",   f"        ⚡ {riesgo}"))

        log()
        log(c("R", "  " + "▓" * 52))

    return resultado


# ── Helpers de rutas de binarios del venv ────────────────────────────────────
def _bin(name):
    return os.path.join(os.path.dirname(sys.executable), name)


# ── Verificar herramientas ────────────────────────────────────────────────────
def verificar_herramientas():
    log(c("BD", "\n🔧 Verificando herramientas..."))
    log(c("DIM", f"   Python: {sys.executable}"))
    ok = True
    for h in ["fickling", "modelscan"]:
        path = _bin(h)
        if os.path.isfile(path):
            log(c("G", f"   ✅ {h:<12} → {path}"))
        else:
            log(c("R", f"   ❌ {h:<12} → NO encontrado  (pip install {h})"))
            ok = False
    if not ok:
        log(c("R", "\n❌ Instala las herramientas faltantes antes de continuar."))
        sys.exit(1)


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    fecha       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ts          = datetime.now().strftime("%Y%m%d_%H%M%S")

    os.makedirs("logs",    exist_ok=True)
    os.makedirs("reports", exist_ok=True)

    archivo_log    = f"logs/scan_{ts}.log"
    archivo_json   = f"reports/scan_{ts}.json"

    rutas_input = parsear_args()

    titulo("🔐 SCANNER DE SEGURIDAD PARA MODELOS IA — v5.0")
    log(c("DIM", f"  Fecha        : {fecha}"))
    log(c("DIM", f"  Rutas input  : {len(rutas_input)}"))
    for r in rutas_input:
        log(c("DIM", f"    • {r}"))

    verificar_herramientas()

    log(c("BD", "\n🔍 Descubriendo archivos de modelo..."))
    todos_archivos = []
    for ruta in rutas_input:
        encontrados = descubrir_archivos(ruta)
        log(c("DIM", f"  {ruta} → {len(encontrados)} archivo(s)"))
        todos_archivos.extend(encontrados)

    todos_archivos = sorted(set(todos_archivos))

    if not todos_archivos:
        log(c("Y", "\n⚠️  No se encontraron archivos de modelo para escanear."))
        log(c("Y",  "   Extensiones buscadas: .bin .h5 .pkl .safetensors .gguf"))
        sys.exit(0)

    log(c("BD", f"\n  Total archivos a escanear: {c('W', str(len(todos_archivos)))}"))

    resultados = []
    for idx, filepath in enumerate(todos_archivos, 1):
        r = escanear_archivo(filepath, idx, len(todos_archivos))
        resultados.append(r)

    log()
    titulo("📋 RESUMEN EJECUTIVO DE SEGURIDAD")
    log()

    peligrosos    = [r for r in resultados if r["estado"] == "PELIGROSO"]
    limpios       = [r for r in resultados if r["estado"] == "LIMPIO"]
    indeterminados = [r for r in resultados if r["estado"] not in ("PELIGROSO", "LIMPIO")]

    total_bytes = sum(r["size_bytes"] for r in resultados)

    log(c("BD", f"  Total escaneados  : {len(resultados)}"))
    log(c("G",  f"  🟢 Limpios         : {len(limpios)}"))
    log(c("R",  f"  🔴 Peligrosos      : {len(peligrosos)}"))
    log(c("Y",  f"  🟡 Indeterminados  : {len(indeterminados)}"))
    log(c("BD", f"  Tamaño total      : {format_size(total_bytes)}"))
    log()
    sep()

    for r in resultados:
        hash_corto = r["sha256"][:16] + "..." if len(r["sha256"]) > 16 else r["sha256"]
        size_str   = format_size(r["size_bytes"])
        if r["estado"] == "PELIGROSO":
            log(c("R",   f"  🔴 PELIGROSO  │ {r['archivo']}"))
            log(c("DIM", f"               │ {size_str}  │  SHA256: {hash_corto}"))
            for kw, info in r["peligros"].items():
                desc = PELIGROS_EXPLICADOS.get(kw) or info.get("explicacion", kw)
                log(c("Y", f"               │  ↳ {desc[:65]}"))
        elif r["estado"] == "LIMPIO":
            log(c("G",   f"  🟢 LIMPIO     │ {r['archivo']}"))
            log(c("DIM", f"               │ {size_str}  │  SHA256: {hash_corto}"))
        else:
            log(c("Y",   f"  🟡 {r['estado']:<10}│ {r['archivo']}"))
            log(c("DIM", f"               │ {size_str}  │  SHA256: {hash_corto}"))

    sep()
    log(c("BD", f"  Tamaño total escaneado : {format_size(total_bytes)}"))
    log()

    if peligrosos:
        log(c("R", c("BD", "  🚨 ACCIÓN RECOMENDADA:")))
        log(c("Y",  "  Los modelos PELIGROSOS NO deben desplegarse en producción."))
        log(c("Y",  "  Notificar al equipo de seguridad y reemplazar por"))
        log(c("Y",  "  versiones .safetensors si están disponibles en HuggingFace."))
    else:
        log(c("G", c("BD", "  ✅ Ningún modelo presenta peligros reales.")))
        log(c("DIM", "  Nota: los modelos .bin/pkl son formato Pickle (menos seguro que"))
        log(c("DIM", "  .safetensors). Migrar si existen equivalentes disponibles."))

    log()
    sep()

    with open(archivo_log, "w", encoding="utf-8") as f:
        f.write("\n".join(LOG_LINES))

    reporte_data = {
        "fecha"   : fecha,
        "resumen" : {
            "total"         : len(resultados),
            "limpios"       : len(limpios),
            "peligrosos"    : len(peligrosos),
            "indeterminados": len(indeterminados),
            "total_bytes"   : total_bytes,
            "total_legible" : format_size(total_bytes),
        },
        "resultados": [
            {
                "archivo"     : r["archivo"],
                "estado"      : r["estado"],
                "size_bytes"  : r["size_bytes"],
                "size_legible": format_size(r["size_bytes"]),
                "sha256"      : r["sha256"],
                "metodo"      : r["metodo"],
                "peligros"    : list(r["peligros"].keys()),
            }
            for r in resultados
        ],
    }
    with open(archivo_json, "w", encoding="utf-8") as f:
        json.dump(reporte_data, f, indent=2, ensure_ascii=False)

    log(c("G",  f"\n  ✅ Log completo  : {archivo_log}"))
    log(c("G",  f"  ✅ Reporte JSON  : {archivo_json}"))
    log(c("BD", "═" * 64 + "\n"))


if __name__ == "__main__":
    main()
