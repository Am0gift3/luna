"""rag — self-contained RAG module for MOONSHOT.

Public API — app.py imports only this:

    from rag import ingest, retrieve, memory, list_sources, delete_source

CLI for testing (no Flask import needed):
    python -m rag query "log4shell payload" --user 1 --workspace default
    python -m rag ingest knowledge/foo.md --user 1
    python -m rag sources --user 1
    python -m rag stats
"""
from . import config, embedder, store, extract, chunking
from . import ingest, retrieve, memory, scraped_context

__all__ = [
    "config", "embedder", "store", "extract", "chunking",
    "ingest", "retrieve", "memory", "scraped_context",
    "list_sources", "delete_source", "stats",
]


# ─── Convenience wrappers ────────────────────────────────────────────
def list_sources(user_id):
    """List distinct `source` values ingested by this user."""
    try:
        res = store.knowledge().get(
            where={"user_id": int(user_id)},
            include=["metadatas"],
        )
    except Exception:
        return []
    seen = set()
    for m in res.get("metadatas") or []:
        s = (m or {}).get("source")
        if s:
            seen.add(s)
    return sorted(seen)


def delete_source(user_id, source):
    """Delete all chunks from a given (user, source)."""
    ingest.delete_source(user_id, source)
    return True


def stats(user_id=None):
    """Return {'chunks': N, 'sources': M, 'memory': K} for a scope."""
    try:
        where = {"user_id": int(user_id)} if user_id is not None else None
        res = store.knowledge().get(where=where, include=["metadatas"])
        metas = res.get("metadatas") or []
        return {
            "chunks": len(res.get("ids") or []),
            "sources": len({(m or {}).get("source") for m in metas if m}),
        }
    except Exception:
        return {"chunks": 0, "sources": 0}


# ─── CLI ─────────────────────────────────────────────────────────────
def _cli():  # pragma: no cover
    import argparse, json, sys
    p = argparse.ArgumentParser(prog="rag")
    sub = p.add_subparsers(dest="cmd", required=True)

    q = sub.add_parser("query", help="Run a retrieval")
    q.add_argument("query")
    q.add_argument("--user", type=int, required=True)
    q.add_argument("--workspace", default="default")
    q.add_argument("--k", type=int, default=5)

    ing = sub.add_parser("ingest", help="Ingest a file")
    ing.add_argument("path")
    ing.add_argument("--user", type=int, required=True)
    ing.add_argument("--workspace", default="default")

    src = sub.add_parser("sources", help="List ingested sources")
    src.add_argument("--user", type=int, required=True)

    st = sub.add_parser("stats", help="Show counts")
    st.add_argument("--user", type=int, default=None)

    args = p.parse_args()
    if args.cmd == "query":
        hits = retrieve.search(args.user, args.workspace, args.query, k=args.k)
        for i, h in enumerate(hits):
            print(f"[{i}] score={h['score']:.3f} source={h['source']}")
            print(f"    {h['text'][:200]}")
    elif args.cmd == "ingest":
        print(ingest.file(args.user, args.workspace, args.path))
    elif args.cmd == "sources":
        print(json.dumps(list_sources(args.user), indent=2))
    elif args.cmd == "stats":
        print(json.dumps(stats(args.user), indent=2))


if __name__ == "__main__":  # pragma: no cover
    _cli()
