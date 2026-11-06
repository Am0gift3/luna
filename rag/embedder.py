"""Lazy SentenceTransformer singleton.

Why lazy:
  - importing `rag` must NOT load a 120 MB model (slows startup, breaks tests)
  - if the model fails to load (OOM, missing weights), we degrade gracefully
    instead of crashing Flask at import time
"""
import logging
import threading
from . import config

logger = logging.getLogger(__name__)

_lock = None          # will become a threading.Lock
_model = None
_load_failed = False


def _get_lock():
    global _lock
    if _lock is None:
        _lock = threading.Lock()
    return _lock


def get():
    """Return the SentenceTransformer, loading it on first use. None on failure."""
    global _model, _load_failed
    if _model is not None:
        return _model
    if _load_failed:
        return None
    with _get_lock():
        if _model is not None:
            return _model
        if _load_failed:
            return None
        try:
            from sentence_transformers import SentenceTransformer
            logger.info(f"Loading embedder: {config.EMBED_MODEL}")
            _model = SentenceTransformer(config.EMBED_MODEL)
            logger.info(f"Embedder loaded ({config.EMBED_MODEL})")
            return _model
        except Exception as e:
            logger.warning(f"Embedder load failed: {e}")
            _load_failed = True
            return None


def is_available() -> bool:
    return get() is not None


def encode(texts, *, normalize=True, is_query=False):
    """Encode a list of strings → list[list[float]].

    bge/e5 models want a prefix that differs for queries vs passages.
    We set this at config time and honor it here so callers stay ignorant.
    """
    m = get()
    if m is None:
        raise RuntimeError("Embedder unavailable")
    if config.EMBED_REQUIRES_PREFIX:
        prefix = "query: " if is_query else "passage: "
        texts = [prefix + t for t in texts]
    return m.encode(texts, normalize_embeddings=normalize).tolist()
