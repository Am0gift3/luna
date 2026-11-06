"""Workspace memory — semantically-searchable log of past tool executions.

Why it exists:
  The agent shouldn't repeat the same nmap scan across turns. Instead of
  dumping the whole chat into context, we vectorize each tool call+result
  and retrieve only the most relevant past executions per turn.

Design notes:
  - Write-only from the agent (via append()); read-only from retrieval.
  - This module does NOT touch SQLAlchemy. The DB row (MemoryEntry) stays
    in app.py — keeping this package importable/testable without Flask.
  - All entries carry user_id AND workspace_id; retrieval is scoped by both.
  - Pruning: we keep the most recent N per (user, workspace) so the
    collection doesn't grow unbounded. The DB is the source of truth.
"""
import json
import logging
import threading
import uuid
from datetime import datetime, timezone

from . import config, embedder, store

logger = logging.getLogger(__name__)

# Serialize writes per (user, workspace) so concurrent tool calls don't
# corrupt the memory collection with half-inserted entries.
_write_locks = {}
_write_guard = threading.Lock()


def _lock_for(key):
    with _write_guard:
        if key not in _write_locks:
            _write_locks[key] = threading.Lock()
        return _write_locks[key]


# ─── Write path ──────────────────────────────────────────────────────
def append(user_id, workspace_id, tool, args, result, user_query=None):
    """Vectorize one tool execution into the memory collection.

    `args` and `result` may be long — we truncate result to 2000 chars
    because embeddings saturate quickly and long tool output is stored in
    the DB verbatim anyway.
    """
    if not embedder.is_available():
        logger.debug("memory.append: embedder unavailable, skipping")
        return None
    if user_id is None or not workspace_id:
        return None

    uid = int(user_id)
    text = (
        f"Tool: {tool}\n"
        f"Args: {json.dumps(args, default=str)}\n"
        f"Result: {(result or '')[:2000]}"
    )
    try:
        emb = embedder.encode([text], is_query=False)[0]
    except Exception as e:
        logger.warning(f"memory.append embed failed: {e}")
        return None

    entry_id = f"mem_{uid}_{uuid.uuid4().hex}"
    meta = {
        "user_id": uid,
        "workspace_id": workspace_id,
        "tool": tool,
        "user_query": (user_query or "")[:500],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    with _lock_for((uid, workspace_id)):
        try:
            store.memory().add(
                ids=[entry_id],
                embeddings=[emb],
                documents=[text],
                metadatas=[meta],
            )
        except Exception as e:
            logger.warning(f"memory.append store failed: {e}")
            return None
    return entry_id


# ─── Read path ───────────────────────────────────────────────────────
def search(user_id, workspace_id, query, k=3, min_score=None):
    """Return past executions semantically similar to `query`.

    Callers should use the user's *last message* as the query, not the whole
    conversation. Similarity floor defaults to config.MIN_SCORE.
    """
    if user_id is None or not query or not embedder.is_available():
        return []
    min_score = config.MIN_SCORE if min_score is None else min_score

    try:
        q = embedder.encode([query], is_query=True)
        res = store.memory().query(
            query_embeddings=q,
            n_results=k,
            where=store.scope(user_id, workspace_id),
            include=["documents", "metadatas", "distances"],
        )
    except Exception as e:
        logger.warning(f"memory.search failed: {e}")
        return []

    docs  = (res.get("documents") or [[]])[0]
    metas = (res.get("metadatas") or [[]])[0]
    dists = (res.get("distances") or [[]])[0]

    out = []
    for doc, meta, dist in zip(docs, metas, dists):
        score = 1.0 - float(dist)
        if score < min_score:
            continue
        out.append({"text": doc, "meta": meta, "score": score})
    return out


# ─── Maintenance ─────────────────────────────────────────────────────
def prune(user_id, workspace_id, keep_last=500):
    """Keep only the most recent `keep_last` entries per (user, workspace).

    Cheap heuristic: sort by timestamp metadata, delete the tail. Run from a
    background task — this is O(n) in the collection size for that scope.
    """
    uid = int(user_id)
    try:
        res = store.memory().get(
            where=store.scope(uid, workspace_id),
            include=["metadatas"],
        )
    except Exception as e:
        logger.warning(f"memory.prune load failed: {e}")
        return {"deleted": 0}

    ids = res.get("ids") or []
    metas = res.get("metadatas") or []
    if len(ids) <= keep_last:
        return {"deleted": 0}

    rows = list(zip(ids, metas))
    rows.sort(key=lambda r: (r[1] or {}).get("timestamp", ""), reverse=True)
    to_delete = [r[0] for r in rows[keep_last:]]

    try:
        store.memory().delete(ids=to_delete)
    except Exception as e:
        logger.warning(f"memory.prune delete failed: {e}")
        return {"deleted": 0}
    logger.info(f"Pruned {len(to_delete)} memory entries for user={uid}")
    return {"deleted": len(to_delete)}


def clear(user_id, workspace_id=None):
    """Delete all memory entries for a user (optionally scoped to one workspace)."""
    try:
        store.memory().delete(where=store.scope(user_id, workspace_id))
        return True
    except Exception as e:
        logger.warning(f"memory.clear failed: {e}")
        return False


def stats(user_id, workspace_id=None):
    """Return {'count': N} for the given scope. Useful for a debug panel."""
    try:
        res = store.memory().get(
            where=store.scope(user_id, workspace_id),
            include=[],
        )
        return {"count": len(res.get("ids") or [])}
    except Exception:
        return {"count": 0}
