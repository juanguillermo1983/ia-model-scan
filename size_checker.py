"""
Consulta el tamaño de los modelos del catálogo en la API de HuggingFace
sin descargarlos. Muestra un resumen por modelo y el detalle de cada archivo.
"""

import os
import urllib.request
import json
from dotenv import load_dotenv
from models_catalog import MODEL_IDS

load_dotenv()

HF_TOKEN = os.getenv("HF_TOKEN", "")


def format_size(bytes_size):
    if bytes_size is None or bytes_size == 0:
        return "desconocido"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_size < 1024:
            return f"{bytes_size:.1f} {unit}"
        bytes_size /= 1024
    return f"{bytes_size:.1f} PB"


def extract_size(file_entry):
    """Obtiene el tamaño desde los distintos campos que usa la API de HF."""
    size = file_entry.get("size")
    if size and size > 0:
        return size

    lfs = file_entry.get("lfs")
    if lfs and isinstance(lfs, dict):
        size = lfs.get("size")
        if size and size > 0:
            return size

    xet = file_entry.get("xet")
    if xet and isinstance(xet, dict):
        size = xet.get("size")
        if size and size > 0:
            return size

    return None


def get_model_info(model_id):
    url = f"https://huggingface.co/api/models/{model_id}?blobs=true"
    headers = {"Accept": "application/json"}
    if HF_TOKEN:
        headers["Authorization"] = f"Bearer {HF_TOKEN}"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return None, "modelo gated — necesita token HF"
        return None, f"HTTP {e.code}"
    except Exception as e:
        return None, str(e)

    siblings = data.get("siblings", [])
    files, total, unknown_count = [], 0, 0

    for f in siblings:
        size = extract_size(f)
        files.append({"name": f.get("rfilename", ""), "size": size})
        if size:
            total += size
        else:
            unknown_count += 1

    if total == 0 and siblings:
        print(f"  [debug] campos del primer archivo en {model_id}:")
        print(f"  {list(siblings[0].keys())}")

    return {
        "total": total,
        "files": files,
        "unknown_count": unknown_count,
        "gated": data.get("gated", False),
        "private": data.get("private", False),
    }, None


def main():
    print("=" * 62)
    print(f"{'MODELO':<45} {'TAMAÑO TOTAL':>14}")
    print("=" * 62)

    grand_total = 0
    details = []

    for model_id in MODEL_IDS:
        info, error = get_model_info(model_id)

        if error:
            print(f"{model_id:<45} ⚠  {error}")
            details.append((model_id, None, error, []))
            continue

        flags = ""
        if info["gated"]:
            flags += " [gated]"
        if info["private"]:
            flags += " [privado]"

        size_str = format_size(info["total"])
        if info["unknown_count"] > 0 and info["total"] == 0:
            size_str = "ver debug arriba"
        elif info["unknown_count"] > 0:
            size_str += f" +{info['unknown_count']} sin dato"

        print(f"{model_id:<45} {size_str:>14}{flags}")
        grand_total += info["total"] or 0
        details.append((model_id, info["total"], None, info["files"]))

    print("=" * 62)
    print(f"{'TOTAL ACUMULADO':<45} {format_size(grand_total):>14}")
    print("=" * 62)

    WEIGHT_EXTS = (".safetensors", ".bin", ".pt", ".gguf", ".h5", ".ot")

    print("\n\nDETALLE POR ARCHIVO")
    print("=" * 62)

    for model_id, total, error, files in details:
        print(f"\n{model_id}  ({format_size(total)})")
        if error:
            print(f"  Error: {error}")
            continue

        weight_files = [f for f in files if f["name"].endswith(WEIGHT_EXTS)]
        other_files  = [f for f in files if not f["name"].endswith(WEIGHT_EXTS)]

        if weight_files:
            print(f"  Pesos ({len(weight_files)} archivos):")
            for f in sorted(weight_files, key=lambda x: x["size"] or 0, reverse=True):
                print(f"    {f['name']:<50} {format_size(f['size'])}")

        if other_files:
            other_total = sum(f["size"] or 0 for f in other_files)
            label = format_size(other_total) if other_total > 0 else "sin dato"
            print(f"  Config/tokenizer/otros ({len(other_files)} archivos): {label}")


if __name__ == "__main__":
    main()
