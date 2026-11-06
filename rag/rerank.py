"""Cross-encoder reranker (Phase 5).

Why a second model: embedding models score (query, doc) independently; a
cross-encoder reads them together and is far more precise. Cost is ~10 ms/
pair on CPU. We only rerank the top RERANK_TOP_N candidates, so this is cheap.
"""
import logging
import threading
from . import config

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_model = None
_failed = False


def _get():
    global _model, _failed
    if _model is not None or _failed:
        return _model
    with _lock:
        if _model is not None or _failed:
            return _model
        try:
            from sentence_transformers import CrossEncoder
            logger.info(f"Loading reranker: {config.RERANK_MODEL}")
            _model = CrossEncoder(config.RERANK_MODEL)
            logger.info("Reranker loaded")
        except Exception as e:
            logger.warning(f"Reranker load failed: {e}")
            _failed = True
            _model = None
    return _model


def is_available() -> bool:
    return _get() is not None


def rerank(query, hits, top_k=None):
    """Re-score hits with a cross-encoder. Returns the reordered list."""
    if not hits:
        return hits
    model = _get()
    if model is None:
        return hits[:top_k] if top_k else hits

    pairs = [(query, h["text"]) for h in hits]
    try:
        scores = model.predict(pairs)
    except Exception as e:
        logger.warning(f"Rerank failed, passing through: {e}")
        return hits[:top_k] if top_k else hits

    ranked = sorted(zip(hits, scores), key=lambda x: float(x[1]), reverse=True)
    out = [{**h, "rerank_score": float(s)} for h, s in ranked]
    return out[:top_k] if top_k else out
