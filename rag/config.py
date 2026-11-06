"""Central configuration. Every tunable lives here so nothing else needs env access."""
import os
from pathlib import Path

# ─── Paths ───────────────────────────────────────────────────────────
VECTOR_STORE_DIR = Path(os.environ.get("RAG_DB_PATH", "vector_store"))

# ─── Collections ─────────────────────────────────────────────────────
KNOWLEDGE_COLLECTION = "knowledge"
MEMORY_COLLECTION    = "workspace_memory"

# ─── Embedder (Phase 3) ──────────────────────────────────────────────
# all-MiniLM-L6-v2 = baseline (fast, weak on technical text).
# bge-small-en-v1.5 = drop-in upgrade, ~30 MB more, noticeably better on
#   CVE/flag/jargon queries. Swap by changing this string + re-ingesting.
# e5-small-v2 requires "query: " / "passage: " prefixes — handled in embedder.py.
EMBED_MODEL    = os.environ.get("RAG_EMBED_MODEL", "BAAI/bge-small-en-v1.5")
EMBED_DIM      = 384
EMBED_REQUIRES_PREFIX = EMBED_MODEL.startswith("intfloat/e5")

# ─── Chunking (Phase 2) ──────────────────────────────────────────────
# 1200 chars ≈ 300 tokens for bge-small's 512-token window.
# Overlap 180 chars (~15%) preserves cross-boundary context.
CHUNK_SIZE    = 1200
CHUNK_OVERLAP = 180

# ─── Retrieval ───────────────────────────────────────────────────────
DEFAULT_K       = 3     # what most callers get
VECTOR_CANDIDATES = 20  # fetch this many from Chroma before hybrid/rerank
BM25_CANDIDATES   = 20  # same for BM25
RRF_K           = 60    # standard RRF constant; higher = flatter weighting
RERANK_TOP_N    = 30    # how many to feed the cross-encoder
MIN_SCORE       = 0.30  # cosine-similarity floor. Tune with eval harness.
MMR_LAMBDA      = 0.7   # 1.0 = pure relevance, 0.0 = pure diversity

# ─── Reranker (Phase 5) ──────────────────────────────────────────────
RERANK_MODEL = "cross-encoder/ms-marco-MiniLM-L-6-v2"

# ─── Feature flags ───────────────────────────────────────────────────
# Toggle these per-call; defaults are the "full pipeline" behavior.
USE_HYBRID       = True   # vector + BM25 RRF (Phase 4)
USE_RERANK       = True   # cross-encoder over top-N   (Phase 5)
USE_MMR          = True   # diversity dedup            (Phase 7)
USE_THRESHOLD    = True   # MIN_SCORE filter
