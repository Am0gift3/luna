"""In-house BM25 — no extra dependency.

BM25 catches what dense vectors miss: exact CVE IDs, tool flags (`-sV`),
error strings, port numbers. Combined with vector search via RRF in
retrieve.py, this is the single biggest quality win for technical data.
"""
import math
import re
from collections import Counter

_TOKEN = re.compile(r"[A-Za-z0-9_\-\.]+")  # keep CVE-2021-44228 and -sV as one token


def tokenize(text: str):
    return [t.lower() for t in _TOKEN.findall(text or "")]


class BM25:
    """Okapi BM25. k1=1.5, b=0.75 are the standard defaults."""

    def __init__(self, k1=1.5, b=0.75):
        self.k1 = k1
        self.b = b
        self.doc_freqs = []       # list of Counter per doc
        self.doc_len = []
        self.avgdl = 0.0
        self.idf = {}
        self.n = 0

    def fit(self, corpus):
        """corpus: list of strings (already the raw document text)."""
        tokenized = [tokenize(d) for d in corpus]
        self.n = len(tokenized)
        self.doc_len = [len(t) for t in tokenized]
        self.avgdl = (sum(self.doc_len) / self.n) if self.n else 0.0
        self.doc_freqs = [Counter(t) for t in tokenized]

        df = Counter()
        for freq in self.doc_freqs:
            for term in freq:
                df[term] += 1
        self.idf = {
            term: math.log(1 + (self.n - cnt + 0.5) / (cnt + 0.5))
            for term, cnt in df.items()
        }

    def scores(self, query):
        """Return a list of BM25 scores, one per indexed doc."""
        q_tokens = tokenize(query)
        out = [0.0] * self.n
        for term in q_tokens:
            idf = self.idf.get(term)
            if idf is None:
                continue
            for i, freq in enumerate(self.doc_freqs):
                tf = freq.get(term, 0)
                if tf == 0:
                    continue
                denom = tf + self.k1 * (1 - self.b + self.b * (self.doc_len[i] / self.avgdl))
                out[i] += idf * (tf * (self.k1 + 1)) / denom
        return out
