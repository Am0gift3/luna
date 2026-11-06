"""ChromaDB client and collection wrappers. Sets cosine metric at creation."""
import logging
import threading
import chromadb
from . import config

logger = logging.getLogger(__name__)

_client = None
_client_lock = threading.Lock()


def _get_client():
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                config.VECTOR_STORE_DIR.mkdir(exist_ok=True)
                _client = chromadb.PersistentClient(path=str(config.VECTOR_STORE_DIR))
    return _client


def knowledge():
    """The shared 'knowledge' collection. All access is user-scoped via `where`."""
    return _get_client().get_or_create_collection(
        config.KNOWLEDGE_COLLECTION,
        metadata={"hnsw:space": "cosine"},   # Phase 2a — cosine, not L2
    )


def memory():
    """Workspace-memory collection (past tool executions, semantically searchable)."""
    return _get_client().get_or_create_collection(
        config.MEMORY_COLLECTION,
        metadata={"hnsw:space": "cosine"},
    )


# ─── Filter helper ───────────────────────────────────────────────────
# Chroma's `where=` requires `$and` when combining 2+ conditions. Using a
# helper ensures every query is consistent — impossible to forget a user
# scope because callers always pass user_id.
def scope(user_id, workspace_id=None):
    conds = [{"user_id": int(user_id)}]
    if workspace_id is not None:
        conds.append({"workspace_id": workspace_id})
    if len(conds) == 1:
        return conds[0]
    return {"$and": conds}
