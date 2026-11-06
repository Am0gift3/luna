"""Ingestion — the only place documents enter the vector store.

Phase 1 guarantees baked in:
  - every chunk is tagged with user_id → cross-user isolation
  - chunk IDs are namespaced per upload → no collisions on re-upload
  - stale chunks for the same (user, source) are deleted first

Phase 7 additions:
  - per-user lock so concurrent ingest of the same source is safe
  - async submission via a small thread pool
  - cache invalidation for the BM25 index
"""
import logging
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import config, embedder, chunking, extract, store

logger = logging.getLogger(__name__)

# ─── Concurrency controls (Phase 7) ──────────────────────────────────
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="rag-ingest")
_user_locks = {}
_user_locks_guard = threading.Lock()


def _lock_for(user_id):
    uid = int(user_id)
    with _user_locks_guard:
        if uid not in _user_locks:
            _user_locks[uid] = threading.Lock()
        return _user_locks[uid]


# ─── BM25 cache invalidation ─────────────────────────────────────────
# retrieve.py caches a BM25 index per user. Any ingest invalidates it.
def _invalidate_bm25(user_id):
    try:
        from . import retrieve
        retrieve.invalidate_bm25_cache(int(user_id))
    except Exception:
        pass


# ─── Core API ────────────────────────────────────────────────────────
def text(user_id, workspace_id, content, source):
    """Ingest a string. Returns {'chunks': N, 'upload_id': '...'}.

    Callers must pass a stable `source` — usually the filename or URL — so
    re-ingesting the same document replaces the old one cleanly.
    """
    if not embedder.is_available():
        raise RuntimeError("Embedder unavailable")
    if not (content or "").strip():
        raise ValueError("No extractable text")

    chunks = chunking.split(content)
    if not chunks:
        raise ValueError("Chunker produced no chunks")

    embeddings = embedder.encode(chunks)   # already normalized

    uid = int(user_id)
    upload_id = uuid.uuid4().hex

    with _lock_for(uid):
        coll = store.knowledge()
        # Phase 1: delete stale chunks for the same (user, source).
        # Wrapped in try/except because Chroma raises on empty filter matches.
        try:
            coll.delete(where={"$and": [{"user_id": uid}, {"source": source}]})
        except Exception:
            pass

        ids = [f"{uid}_{upload_id}_{i}" for i in range(len(chunks))]
        metas = [
            {
                "source": source,
                "user_id": uid,
                "workspace_id": workspace_id,
                "chunk_index": i,
                "upload_id": upload_id,
                "embed_model": config.EMBED_MODEL,   # for future re-embed migration
            }
            for i in range(len(chunks))
        ]
        coll.add(ids=ids, embeddings=embeddings, metadatas=metas, documents=chunks)

    _invalidate_bm25(uid)
    logger.info(f"Ingested {len(chunks)} chunks for user={uid} source={source}")
    return {"chunks": len(chunks), "upload_id": upload_id}


def file(user_id, workspace_id, path: Path, source=None):
    """Ingest a file. `source` defaults to the filename."""
    content = extract.read(Path(path))
    return text(user_id, workspace_id, content, source or Path(path).name)


def file_async(user_id, workspace_id, path, source=None):
    """Submit file ingestion to the pool. Returns a Future.

    Callers can poll or `.result()` — but the route should return immediately
    so the browser doesn't block on a 200-page PDF.
    """
    return _executor.submit(file, user_id, workspace_id, Path(path), source)


def scraped(user_id, workspace_id, run_id, url, data):
    """Ingest scraped JSON. Source is namespaced so re-scraping replaces cleanly."""
    import json
    return text(
        user_id, workspace_id,
        json.dumps(data, indent=2, ensure_ascii=False),
        source=f"scraped:{url or run_id}",
    )


# ─── Deletion ────────────────────────────────────────────────────────
def delete_source(user_id, source):
    store.knowledge().delete(
        where={"$and": [{"user_id": int(user_id)}, {"source": source}]}
    )
    _invalidate_bm25(user_id)


def delete_all(user_id):
    try:
        store.knowledge().delete(where={"user_id": int(user_id)})
    except Exception:
        pass
    _invalidate_bm25(user_id)
