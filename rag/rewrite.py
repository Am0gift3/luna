"""LLM-based query rewriter (Phase 6).

Vague queries ("scan it", "what about the other one?") retrieve nothing.
A one-line LLM call that rewrites the query into a retrieval-friendly form
fixes most of these. The rewrite is *opt-in*: callers pass an `llm_fn`
so this module doesn't depend on app.py.
"""
import logging

logger = logging.getLogger(__name__)

_REWRITE_PROMPT = """Rewrite the following user message as a single, self-contained
search query for a knowledge base about penetration testing, CVEs, and tool
documentation. Keep any CVE IDs, tool names, flags, port numbers, and IPs verbatim.
Return ONLY the rewritten query, no preamble, no quotes.

User message: {query}
"""


def rewrite(query, llm_fn=None):
    """Return a rewritten query. On any failure, returns the original."""
    if not query or not llm_fn:
        return query
    try:
        prompt = _REWRITE_PROMPT.format(query=query)
        # `llm_fn` must accept (messages) and return a string
        out = llm_fn([{"role": "user", "content": prompt}])
        if not out:
            return query
        out = out.strip().splitlines()[0].strip().strip('"').strip("'")
        # Sanity: reject rewrites that got absurdly long or empty
        if not out or len(out) > 400:
            return query
        logger.debug(f"rewrite: {query!r} → {out!r}")
        return out
    except Exception as e:
        logger.debug(f"rewrite failed, using original: {e}")
        return query
