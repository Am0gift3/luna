"""Hit@K + MRR harness — run after every phase change."""
import json, sys
from pathlib import Path
import rag

EVAL = Path("eval/queries.jsonl")
K    = 5


def main():
    user = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    workspace = sys.argv[2] if len(sys.argv) > 2 else "default"
    queries = [json.loads(l) for l in EVAL.read_text().splitlines() if l.strip()]

    hits, mrrs = [], []
    for q in queries:
        results = rag.retrieve.search(user, workspace, q["query"], k=K)
        sources = [r.get("source") or "" for r in results]
        expected = q["expected_sources"]
        ranks = [i for i, s in enumerate(sources)
                 if any(exp in s for exp in expected)]
        hit = bool(ranks)
        mrr = 1.0 / (min(ranks) + 1) if ranks else 0.0
        hits.append(hit); mrrs.append(mrr)
        print(f"{'✓' if hit else '✗'}  {q['query']}  →  {sources[:3]}")

    n = len(queries)
    print(f"\nHit@{K}: {sum(hits)}/{n} = {sum(hits)/n:.1%}")
    print(f"MRR:    {sum(mrrs)/n:.3f}")


if __name__ == "__main__":
    main()
