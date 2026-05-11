"""
Central registry of all HuggingFace models used in this project.

Each entry: (size_gb, model_id, gated)
  - size_gb : approximate download size in GB (validated via HF API)
  - model_id: HuggingFace repo id  (org/name)
  - gated   : True if the model requires an accepted license + HF_TOKEN

To select which models to download, edit DOWNLOAD_QUEUE below.
"""

# fmt: off
CATALOG = [
    # ── Lightweight (< 1 GB) ─────────────────────────────────────────────────
    ( 0.599, "Helsinki-NLP/opus-mt-es-en",                                    False),
    # ( 0.894, "Helsinki-NLP/opus-mt-en-es",                                    False),
    # ( 0.932, "sentence-transformers/all-MiniLM-L6-v2",                        False),
    # # ── Small (1 – 5 GB) ─────────────────────────────────────────────────────
    # ( 1.1,   "Qwen/Qwen3-Embedding-0.6B",                                     False),
    # ( 1.2,   "sentence-transformers/all-MiniLM-L12-v2",                       False),
    # ( 2.9,   "Qwen/Qwen2.5-Coder-1.5B-Instruct",                             False),
    # ( 2.9,   "bartowski/Qwen2.5-Coder-1.5B-Instruct-GGUF",                   False),
    # ( 2.9,   "Qwen/Qwen2.5-1.5B-Instruct-GGUF",                              False),
    # ( 4.1,   "llamaindex/vdr-2b-multi-v1",                                    False),
    # ( 4.3,   "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2",   False),
    # ( 4.6,   "meta-llama/Llama-3.2-1B-Instruct",                              True),
    # ( 4.6,   "bartowski/Llama-3.2-1B-Instruct-GGUF",                          False),
    # # ── Medium (5 – 15 GB) ───────────────────────────────────────────────────
    # ( 5.0,   "intfloat/multilingual-e5-base",                                 False),
    # ( 5.4,   "jinaai/jina-embeddings-v3",                                     False),
    # ( 7.3,   "jinaai/jina-embeddings-v4",                                     False),
    # ( 9.6,   "google/gemma-4-E2B",                                             True),
    # (12.0,   "meta-llama/Llama-3.2-3B-Instruct",                              True),
    # (12.0,   "Qwen/Qwen2.5-3B-Instruct-GGUF",                                False),
    # # ── Large (> 15 GB) ──────────────────────────────────────────────────────
    # (29.9,   "meta-llama/Llama-3.1-8B-Instruct",                              True),
    # (56.9,   "Qwen/Qwen3-30B-A3B",                                            False),
    # (148.4,  "Qwen/Qwen3-Coder-Next",                                         False),
]
# fmt: on

# ── Download queue ────────────────────────────────────────────────────────────
# Edit this list to control which models get downloaded by downloader.py.
# Use the model_id string exactly as it appears in CATALOG above.
DOWNLOAD_QUEUE = [
    "Helsinki-NLP/opus-mt-es-en",
]

# ── Derived helpers ───────────────────────────────────────────────────────────
MODEL_IDS = [model_id for _, model_id, _ in CATALOG]
GATED_IDS = {model_id for _, model_id, gated in CATALOG if gated}

def catalog_entry(model_id: str) -> tuple | None:
    """Return the (size_gb, model_id, gated) tuple for a given model_id."""
    return next((e for e in CATALOG if e[1] == model_id), None)

def queue_entries() -> list[tuple]:
    """Return CATALOG entries for models in DOWNLOAD_QUEUE, preserving order."""
    return [e for e in CATALOG if e[1] in DOWNLOAD_QUEUE]
