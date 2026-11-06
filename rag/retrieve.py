"""Retrieval pipeline.

Order matters and each stage is independently togglable:
  1. (optional) rewrite the query                 (Phase 6)
  2. vector search, cosine, top-N                 (Phase 2)
  3. BM25 search, top-N                           (Phase 4)
  4. RRF merge                                    (Phase 4)
  5. cross-encoder rerank to top-K                (Phase 5)
  6. threshold filter                             (Phase 2)
  7. MMR diversity dedup                          (Phase 7)

Every caller in app.py goes through `search()`. Nobody else touches Chroma.
"""
import logging
import threading
from collections import defaultdict
from . import config, embedder, store, bm25, rerank, rewrite

logger = logging.getLogger(__name__)

# ─── BM25 per-user cache ─────────────────────────────────────────────
# Rebuild from Chroma on demand; invalidated by ingest.py.
_bm25_cache = {}
_bm25_guard = threading.Lock()


def invalidate_bm25_cache(user_id):
    with _bm25_guard:
        _bm25_cache.pop(int(user_id), None)


def _get_bm25(user_id):
    """Return (bm25_index, doc_ids, doc_texts, doc_metas) for the user, or None."""
    uid = int(user_id)
    with _bm25_guard:
        if uid in _bm25_cache:
            return _bm25_cache[uid]

    # Rebuild outside the guard so a slow load doesn't block other users
    try:
        res = store.knowledge().get(
            where={"user_id": uid},
            include=["documents", "metadatas"],
        )
    except Exception as e:
        logger.warning(f"BM25 load failed for user {uid}: {e}")
        return None

    ids   = res.get("ids") or []
    docs  = res.get("documents") or []
    metas = res.get("metadatas") or []
    if not ids:
        return None

    idx = bm25.BM25()
    idx.fit(docs)
    entry = (idx, ids, docs, metas)
    with _bm25_guard:
        _bm25_cache[uid] = entry
    return entry


# ─── Vector search ───────────────────────────────────────────────────
def _vector_search(user_id, workspace_id, query, n):
    if not embedder.is_available():
        return []
    try:
        q = embedder.encode([query], is_query=True)
        res = store.knowledge().query(
            query_embeddings=q,
            n_results=n,
            where=store.scope(user_id, workspace_id),
            include=["documents", "metadatas", "distances"],
        )
    except Exception as e:
        logger.warning(f"Vector search failed: {e}")
        return []

    ids   = (res.get("ids") or [[]])[0]
    docs  = (res.get("documents") or [[]])[0]
    metas = (res.get("metadatas") or [[]])[0]
    dists = (res.get("distances") or [[]])[0]

    out = []
    for i, d, m, dist in zip(ids, docs, metas, dists):
        # Chroma cosine "distance" is 1 - cosine_similarity; convert back
        out.append({
            "id": i,
            "text": d,
            "source": (m or {}).get("source"),
            "meta": m or {},
            "score": 1.0 - float(dist),
        })
    return out


# ─── BM25 search ─────────────────────────────────────────────────────
def _bm25_search(user_id, query, n):
    entry = _get_bm25(user_id)
    if not entry:
        return []
    idx, ids, docs, metas = entry
    scores = idx.scores(query)
    # Take top N by score
    ranked = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:n]
    out = []
    for i in ranked:
        if scores[i] <= 0:
            continue
        out.append({
            "id": ids[i],
            "text": docs[i],
            "source": (metas[i] or {}).get("source"),
            "meta": metas[i] or {},
            "bm25_score": scores[i],
        })
    return out


# ─── RRF merge ───────────────────────────────────────────────────────
def _rrf(ranked_lists, k=config.RRF_K):
    """Merge multiple ranked lists by Reciprocal Rank Fusion."""
    scores = defaultdict(float)
    id_to_hit = {}
    for ranked in ranked_lists:
        for rank, hit in enumerate(ranked):
            scores[hit["id"]] += 1.0 / (k + rank + 1)
            # Merge metadata: keep whichever hit we saw first, then
            # carry over the score fields from the other ranker too.
            if hit["id"] in id_to_hit:
                existing = id_to_hit[hit["id"]]
                for key in ("score", "bm25_score"):
                    if key in hit and key not in existing:
                        existing[key] = hit[key]
            else:
                id_to_hit[hit["id"]] = dict(hit)
    merged_ids = sorted(scores.keys(), key=lambda x: scores[x], reverse=True)
    out = []
    for doc_id in merged_ids:
        hit = id_to_hit[doc_id]
        hit["rrf_score"] = scores[doc_id]
        out.append(hit)
    return out


# ─── MMR dedup (Phase 7) ─────────────────────────────────────────────
def _mmr_select(hits, query_embedding, k, lambda_param=config.MMR_LAMBDA):
    """Maximal Marginal Relevance — pick diverse top-K from a candidate pool.

    This prevents near-duplicate chunks (common with overlapping chunking or
    the same doc scraped from two URLs) from eating the top-K budget.
    """
    if len(hits) <= k:
        return hits

    # We need candidate embeddings. Cheapest source: re-encode on the fly.
    # Only do this when there are more candidates than we need.
    try:
        cand_embs = embedder.encode([h["text"] for h in hits])
    except Exception:
        return hits[:k]

    try:
        import numpy as np
        q = np.asarray(query_embedding, dtype="float32").reshape(-1)
        cand = np.asarray(cand_embs, dtype="float32")
        selected = []
        remaining = list(range(len(hits)))
        while remaining and len(selected) < k:
            best_idx, best_score = None, -1e9
            for i in remaining:
                rel = float(np.dot(cand[i], q))
                if selected:
                    div = max(float(np.dot(cand[i], cand[j])) for j in selected)
                else:
                    div = 0.0
                score = lambda_param * rel - (1 - lambda_param) * div
                if score > best_score:
                    best_score, best_idx = score, i
            selected.append(best_idx)
            remaining.remove(best_idx)
        return [hits[i] for i in selected]
    except Exception as e:
        logger.debug(f"MMR failed, falling back to top-K: {e}")
        return hits[:k]


# ─── Public API ──────────────────────────────────────────────────────
def search(user_id, workspace_id, query, k=config.DEFAULT_K, *,
           use_hybrid=None, use_rerank=None, use_mmr=None, min_score=None,
           llm_fn=None, rewrite_query=False):
    """Retrieve the top-K most relevant chunks for this (user, workspace).

    Args:
        user_id, workspace_id : tenant scope; both required for isolation.
        query                 : the user's natural-language question.
        k                     : final number of hits to return.
        use_hybrid            : vector + BM25 (default from config).
        use_rerank            : cross-encoder rerank (default from config).
        use_mmr               : diversity dedup (default from config).
        min_score             : cosine-similarity floor (default from config).
        llm_fn                : callable(messages)->str, needed only for rewrite.
        rewrite_query         : if True and llm_fn is given, rewrite query first.

    Returns:
        list[{'text', 'source', 'score', 'rerank_score'?, 'rrf_score'?}]
    """
    if user_id is None or not query:
        return []
    if not embedder.is_available():
        return []

    use_hybrid   = config.USE_HYBRID   if use_hybrid   is None else use_hybrid
    use_rerank   = config.USE_RERANK   if use_rerank   is None else use_rerank
    use_mmr      = config.USE_MMR      if use_mmr      is None else use_mmr
    min_score    = config.MIN_SCORE    if min_score    is None else min_score

    # 1. Optional rewrite
    if rewrite_query and llm_fn is not None:
        query = rewrite.rewrite(query, llm_fn)

    # 2. Vector search (over-fetch for reranking)
    vec_hits = _vector_search(user_id, workspace_id, query, config.VECTOR_CANDIDATES)

    # 3. BM25 hybrid
    if use_hybrid:
        bm_hits = _bm25_search(user_id, query, config.BM25_CANDIDATES)
        merged = _rrf([vec_hits, bm_hits])
    else:
        merged = vec_hits

    if not merged:
        return []

    # 4. Threshold (with cosine, ~0.30 is a good floor for bge-small)
    if min_score > 0:
        merged = [h for h in merged if h.get("score", 1.0) >= min_score]
        if not merged:
            return []

    # 5. Rerank
    if use_rerank and rerank.is_available():
        merged = rerank.rerank(query, merged[:config.RERANK_TOP_N], top_k=None)

    # 6. MMR (only if we have more candidates than we need)
    if use_mmr and len(merged) > k:
        try:
            q_emb = embedder.encode([query], is_query=True)[0]
            merged = _mmr_select(merged, q_emb, k)
        except Exception:
            pass

    # 7. Final trim
    out = []
    for h in merged[:k]:
        out.append({
            "text": h["text"],
            "source": h.get("source"),
            "score": h.get("score", 0.0),
            **({"rerank_score": h["rerank_score"]} if "rerank_score" in h else {}),
            **({"rrf_score":    h["rrf_score"]}    if "rrf_score"    in h else {}),
        })
    return out


def search_memory(user_id, workspace_id, query, k=3):
    """Similar-past-actions retrieval. Uses the same cosine setup."""
    if user_id is None or not query or not embedder.is_available():
        return []
    try:
        q = embedder.encode([query], is_query=True)
        res = store.memory().query(
            query_embeddings=q, n_results=k,
            where=store.scope(user_id, workspace_id),
            include=["documents", "metadatas", "distances"],
        )
    except Exception as e:
        logger.warning(f"Memory search failed: {e}")
        return []
    docs  = (res.get("documents") or [[]])[0]
    metas = (res.get("metadatas") or [[]])[0]
    return [{"text": d, "meta": m} for d, m in zip(docs, metas)]
