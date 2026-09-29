"""
ORACLE Deterministic Markdown Parser & Chunker (Brick 2A)
Converts raw files into immutable Evidence objects with byte-level provenance.
Zero external heavy dependencies. Pure Python standard library.
"""

import hashlib
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from backend.evidence.models import Evidence


class MarkdownEvidenceParser:
    """
    Deterministic parser for Markdown documents.
    Splits documents along header and paragraph boundaries while maintaining
    cryptographic content hashes and exact UTF-8 byte offsets.
    """

    def __init__(self, min_chunk_chars: int = 40):
        self.min_chunk_chars = min_chunk_chars

    def parse_file(
        self,
        file_path: str | Path,
        source_id: Optional[str] = None,
        base_dir: Optional[str | Path] = None,
        created_at: Optional[str] = None,
    ) -> List[Evidence]:
        """
        Parse a document file from disk into Evidence objects.
        If source_id is not specified, defaults to file.stem (e.g. DOC-POLICY-01).
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Source file not found: {file_path}")

        raw_bytes = path.read_bytes()
        text = raw_bytes.decode("utf-8")

        resolved_source_id = source_id or path.stem
        rel_path = str(path.relative_to(base_dir)) if base_dir else str(path)

        # Ingestion timestamp: defaults to file mtime if not passed
        if created_at is None:
            mtime = path.stat().st_mtime
            created_at = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()

        return self.parse_text(
            text=text,
            source_id=resolved_source_id,
            source_path=rel_path,
            created_at=created_at,
            raw_bytes=raw_bytes,
        )

    def parse_text(
        self,
        text: str,
        source_id: str,
        source_path: str,
        created_at: Optional[str] = None,
        raw_bytes: Optional[bytes] = None,
    ) -> List[Evidence]:
        """
        Parse raw text into Evidence objects with exact UTF-8 byte boundary tracking.
        """
        if raw_bytes is None:
            raw_bytes = text.encode("utf-8")

        if created_at is None:
            created_at = "2026-01-01T00:00:00Z"

        evidence_list: List[Evidence] = []
        current_section = "Root"

        # Pattern splits on double newlines while tracking match spans
        paragraph_pattern = re.compile(r"(?:\r?\n){2,}")
        
        # Split text into raw blocks with character start/end tracking
        blocks: List[tuple[int, int, str]] = []
        last_idx = 0
        
        for match in paragraph_pattern.finditer(text):
            start = last_idx
            end = match.start()
            if end > start:
                blocks.append((start, end, text[start:end]))
            last_idx = match.end()
            
        if last_idx < len(text):
            blocks.append((last_idx, len(text), text[last_idx:]))

        chunk_idx = 0

        for block_start_char, block_end_char, raw_block in blocks:
            header_match = re.match(r"^(#{1,6})\s+(.+)$", raw_block.strip())
            if header_match:
                current_section = header_match.group(2).strip()

            stripped = raw_block.strip()
            if len(stripped) < self.min_chunk_chars and not header_match:
                continue

            l_trim = len(raw_block) - len(raw_block.lstrip())
            r_trim = len(raw_block) - len(raw_block.rstrip())
            
            exact_start_char = block_start_char + l_trim
            exact_end_char = block_end_char - r_trim
            content = text[exact_start_char:exact_end_char]

            if not content:
                continue

            # Compute exact UTF-8 byte offsets
            start_offset = len(text[:exact_start_char].encode("utf-8"))
            end_offset = len(text[:exact_end_char].encode("utf-8"))

            # Cryptographic SHA-256 content hash
            content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
            evidence_id = f"{source_id}#c{chunk_idx:03d}"

            metadata: Dict[str, Any] = {
                "section": current_section,
                "is_header": bool(header_match),
                "char_length": len(content),
            }

            evidence = Evidence(
                evidence_id=evidence_id,
                source_id=source_id,
                content=content,
                content_hash=content_hash,
                source_path=source_path,
                chunk_index=chunk_idx,
                start_offset=start_offset,
                end_offset=end_offset,
                metadata=metadata,
                created_at=created_at,
            )
            evidence_list.append(evidence)
            chunk_idx += 1

        return evidence_list
