"""File-to-text extraction. Preserves boundary information for chunking."""
import json
from pathlib import Path

# pypdf is a maintained fork of PyPDF2; fall back if only PyPDF2 is installed.
try:
    from pypdf import PdfReader
except ImportError:  # pragma: no cover
    from PyPDF2 import PdfReader

ALLOWED_EXTENSIONS = {"txt", "md", "pdf", "json", "csv"}


def allowed(name: str) -> bool:
    return "." in name and name.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def read(path: Path) -> str:
    """Return the text content of a supported file. Raises ValueError on unsupported."""
    ext = path.suffix.lower()
    if ext in (".txt", ".md"):
        return path.read_text(encoding="utf-8", errors="replace")
    if ext == ".pdf":
        with open(path, "rb") as f:
            reader = PdfReader(f)
            pages = [(p.extract_text() or "") for p in reader.pages]
        return "\n\n".join(pages)   # preserve page breaks as paragraph breaks
    if ext == ".json":
        # No pointless round-trip — just pretty-print so the chunker can
        # split on structural boundaries.
        try:
            return json.dumps(json.loads(path.read_text(encoding="utf-8")),
                              indent=2, ensure_ascii=False)
        except json.JSONDecodeError:
            return path.read_text(encoding="utf-8", errors="replace")
    if ext == ".csv":
        # Chunk-by-row rather than DataFrame.to_string() — that one-liner
        # blows the token budget on wide tables and loses column structure.
        import pandas as pd
        df = pd.read_csv(path)
        rows_per_chunk = 20
        chunks = []
        for i in range(0, len(df), rows_per_chunk):
            slice_ = df.iloc[i:i + rows_per_chunk]
            chunks.append(f"# CSV rows {i}-{i+len(slice_)}\n"
                          + slice_.to_csv(index=False))
        return "\n\n".join(chunks)
    raise ValueError(f"Unsupported extension: {ext}")
