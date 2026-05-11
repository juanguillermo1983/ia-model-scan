"""
Descarga los modelos definidos en DOWNLOAD_QUEUE (models_catalog.py),
ordenados de menor a mayor peso. Omite los ya descargados.
Los modelos gated requieren HF_TOKEN en .env.
"""

import os
import shutil
from pathlib import Path
from dotenv import load_dotenv
from models_catalog import queue_entries

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────
HF_TOKEN   = os.getenv("HF_TOKEN", "")
LOCAL_BASE = os.getenv("MODELS_BASE_DIR", "./models")

# Deben setearse ANTES de importar huggingface_hub
os.environ["HF_HUB_DOWNLOAD_TIMEOUT"] = os.getenv("HF_HUB_DOWNLOAD_TIMEOUT", "300")
os.environ["HF_HUB_ETAG_TIMEOUT"]     = os.getenv("HF_HUB_ETAG_TIMEOUT", "1800")

from huggingface_hub import snapshot_download


def model_local_path(model_id: str) -> Path:
    return Path(LOCAL_BASE) / model_id


def is_downloaded(model_id: str) -> bool:
    path = model_local_path(model_id)
    if not path.exists():
        return False
    weight_exts = (".safetensors", ".bin", ".pt", ".gguf", ".h5")
    return any(path.rglob(f"*{ext}") for ext in weight_exts)


def fmt(gb: float) -> str:
    return f"{gb * 1024:.0f} MB" if gb < 1 else f"{gb:.1f} GB"


def main():
    models = queue_entries()
    total  = len(models)
    results = []

    print("=" * 62)
    print(f"  Descargando {total} modelo(s)  →  {LOCAL_BASE}/")
    print("=" * 62)

    if not HF_TOKEN:
        print("  AVISO: HF_TOKEN no configurado — los modelos gated fallarán.")
        print("         Agrega HF_TOKEN en el archivo .env\n")

    for i, (size_gb, model_id, gated) in enumerate(models, 1):
        tag   = " [gated]" if gated else ""
        label = f"[{i}/{total}] {model_id}{tag}  ({fmt(size_gb)})"
        dest  = model_local_path(model_id)

        print(f"{'─' * 62}")
        print(f"  {label}")

        if is_downloaded(model_id):
            print("  → Ya descargado, omitiendo.\n")
            results.append((model_id, "omitido", size_gb))
            continue

        if gated and not HF_TOKEN:
            print("  → Omitido: modelo gated requiere HF_TOKEN.\n")
            results.append((model_id, "omitido (sin token)", size_gb))
            continue

        print("  → Descargando...")
        dest.mkdir(parents=True, exist_ok=True)
        try:
            snapshot_download(
                repo_id   = model_id,
                local_dir = str(dest),
                token     = HF_TOKEN or None,
            )
            print(f"  → Listo: {dest}\n")
            results.append((model_id, "ok", size_gb))

        except KeyboardInterrupt:
            print("\n  Interrumpido por el usuario. Limpiando descarga parcial...")
            shutil.rmtree(dest, ignore_errors=True)
            break

        except Exception as e:
            short_err = str(e).splitlines()[0][:120]
            print(f"  → ERROR: {short_err}")
            print(f"     Archivos parciales en: {dest}")
            print(f"     Borra esa carpeta para reintentar.\n")
            results.append((model_id, f"error: {short_err}", size_gb))

    print("\n" + "=" * 62)
    print("  RESUMEN")
    print("=" * 62)

    ok      = [r for r in results if r[1] == "ok"]
    omitidos = [r for r in results if r[1].startswith("omitido")]
    errors  = [r for r in results if r[1].startswith("error")]

    for model_id, status, size_gb in results:
        icon = {"ok": "OK     ", "omitido": "SKIP   "}.get(
            status if status in ("ok", "omitido") else "error", "ERROR  "
        )
        print(f"  {icon} {model_id:<45} {fmt(size_gb):>8}")

    print("─" * 62)
    downloaded_gb = sum(s for _, st, s in ok)
    print(f"  Descargados : {len(ok)} modelos  ({fmt(downloaded_gb)})")
    print(f"  Omitidos    : {len(omitidos)} modelos")
    print(f"  Errores     : {len(errors)} modelos")
    print("=" * 62)


if __name__ == "__main__":
    main()
