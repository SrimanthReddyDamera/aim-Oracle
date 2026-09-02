"""
Unit Tests & Integrity Audit for ORACLE Evidence Foundation (Brick 2A)
Verifies:
  1. Determinism audit (identity invariance regardless of created_at timestamp)
  2. Byte-level provenance mapping (raw_bytes[start:end] == content)
  3. Corpus & manifest ID integrity (zero orphaned IDs)
  4. Deliberate contradictions & temporal rollback in NOVA corpus
  5. Ground-truth evaluation dataset integrity & epistemic classification
"""

import json
from pathlib import Path
import pytest

from backend.evidence.models import Evidence
from backend.evidence.parser import MarkdownEvidenceParser

CORPUS_DIR = Path(__file__).resolve().parent.parent / "test_data" / "nova_corpus"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"
EVAL_SET_PATH = Path(__file__).resolve().parent.parent / "test_data" / "nova_eval_set.json"


@pytest.fixture
def parser():
    return MarkdownEvidenceParser()


@pytest.fixture
def corpus_manifest():
    assert MANIFEST_PATH.exists(), f"Manifest file missing: {MANIFEST_PATH}"
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def test_evidence_model_validation():
    """Verify Evidence model enforces start_offset <= end_offset."""
    ev = Evidence(
        evidence_id="DOC-1#c000",
        source_id="DOC-1",
        content="Sample content",
        content_hash="abc123hash",
        source_path="path/to/doc.md",
        chunk_index=0,
        start_offset=0,
        end_offset=14,
        metadata={},
        created_at="2026-01-01T00:00:00Z"
    )
    assert ev.start_offset == 0
    assert ev.end_offset == 14

    with pytest.raises(ValueError):
        Evidence(
            evidence_id="DOC-1#c000",
            source_id="DOC-1",
            content="Sample content",
            content_hash="abc123hash",
            source_path="path/to/doc.md",
            chunk_index=0,
            start_offset=20,
            end_offset=10,
            metadata={},
            created_at="2026-01-01T00:00:00Z"
        )


def test_determinism_audit(parser, corpus_manifest):
    """
    AUDIT 1: Determinism.
    Demonstrates that:
      - evidence_id is deterministic
      - content_hash is deterministic
      - chunk content is deterministic
      - start_offset / end_offset are deterministic
      - source_id is deterministic
      - canonical_identity() is 100% invariant, even when created_at differs.
    """
    doc_meta = corpus_manifest["documents"][0]
    file_path = CORPUS_DIR / doc_meta["filename"]

    # Run 1 with simulated timestamp A
    run_1 = parser.parse_file(file_path, created_at="2026-01-01T00:00:00Z")
    # Run 2 with simulated timestamp B
    run_2 = parser.parse_file(file_path, created_at="2026-12-31T23:59:59Z")

    assert len(run_1) == len(run_2)
    assert len(run_1) > 0

    for c1, c2 in zip(run_1, run_2):
        # 1. Content-derived fields MUST be 100% identical
        assert c1.evidence_id == c2.evidence_id
        assert c1.source_id == c2.source_id
        assert c1.content == c2.content
        assert c1.content_hash == c2.content_hash
        assert c1.start_offset == c2.start_offset
        assert c1.end_offset == c2.end_offset
        assert c1.canonical_identity() == c2.canonical_identity()

        # 2. Timestamps are classified strictly as ingestion metadata
        assert c1.created_at != c2.created_at
        assert c1.created_at == "2026-01-01T00:00:00Z"
        assert c2.created_at == "2026-12-31T23:59:59Z"


def test_byte_level_provenance_mapping(parser, corpus_manifest):
    """
    AUDIT 2: Byte-level provenance.
    Verifies that slicing raw bytes by [start_offset:end_offset] reconstructs content exactly.
    """
    for doc in corpus_manifest["documents"]:
        file_path = CORPUS_DIR / doc["filename"]
        assert file_path.exists(), f"Corpus file missing: {file_path}"
        raw_bytes = file_path.read_bytes()

        chunks = parser.parse_file(file_path)
        assert len(chunks) > 0, f"No chunks parsed for {doc['source_id']}"

        for chunk in chunks:
            # Slicing the raw source bytes by [start_offset:end_offset] MUST match chunk.content
            sliced_bytes = raw_bytes[chunk.start_offset:chunk.end_offset]
            reconstructed_text = sliced_bytes.decode("utf-8")

            assert reconstructed_text == chunk.content, (
                f"Byte provenance mismatch in {chunk.evidence_id}!\n"
                f"Expected: {chunk.content!r}\n"
                f"Got:      {reconstructed_text!r}"
            )


def test_manifest_and_source_id_integrity(parser, corpus_manifest):
    """
    AUDIT 3: Source ID & Filename mapping consistency.
    Verifies that file.stem exactly equals doc['source_id'], eliminating any ambiguous naming.
    """
    assert len(corpus_manifest["documents"]) == 6

    for doc in corpus_manifest["documents"]:
        file_path = CORPUS_DIR / doc["filename"]
        assert file_path.exists()
        # Stem must match source_id directly
        assert file_path.stem == doc["source_id"]

        # Parser automatically resolves source_id to file.stem
        chunks = parser.parse_file(file_path)
        for chunk in chunks:
            assert chunk.source_id == doc["source_id"]
            assert chunk.evidence_id.startswith(f"{doc['source_id']}#")


def test_ground_truth_eval_set_integrity(parser, corpus_manifest):
    """
    AUDIT 4: Zero orphaned IDs in preliminary eval set.
    Verifies that every primary_supporting, contradictory, and distractor ID
    in nova_eval_set.json exists in the parsed corpus.
    """
    assert EVAL_SET_PATH.exists(), f"Evaluation benchmark missing: {EVAL_SET_PATH}"
    eval_data = json.loads(EVAL_SET_PATH.read_text(encoding="utf-8"))

    # Parse all corpus documents and index generated Evidence objects
    evidence_index = {}
    for doc in corpus_manifest["documents"]:
        file_path = CORPUS_DIR / doc["filename"]
        for chunk in parser.parse_file(file_path):
            evidence_index[chunk.evidence_id] = chunk

    assert len(evidence_index) == 28, f"Expected 28 corpus chunks, found {len(evidence_index)}"

    test_cases = eval_data.get("test_cases", [])
    assert len(test_cases) == 5

    for tc in test_cases:
        qid = tc["question_id"]
        classes = tc["evidence_classification"]

        supporting_ids = classes["primary_supporting_evidence"]
        contradictory_ids = classes["relevant_contradictory_or_stale_evidence"]
        distractor_ids = classes["irrelevant_distractor_evidence"]

        assert len(supporting_ids) > 0, f"{qid} missing primary supporting evidence"

        # Check for orphaned IDs
        for eid in supporting_ids:
            assert eid in evidence_index, f"{qid} has orphaned primary evidence ID: {eid}"
        for eid in contradictory_ids:
            assert eid in evidence_index, f"{qid} has orphaned contradictory evidence ID: {eid}"
        for eid in distractor_ids:
            assert eid in evidence_index, f"{qid} has orphaned distractor evidence ID: {eid}"


def test_deliberate_contradictions_presence(parser, corpus_manifest):
    """
    AUDIT 5: Verify that the corpus contains opposing claims.
    """
    arch_file = CORPUS_DIR / "DOC-NOVA-ARCH-OLD.md"
    incident_file = CORPUS_DIR / "DOC-NOVA-INC-402.md"

    arch_chunks = parser.parse_file(arch_file)
    incident_chunks = parser.parse_file(incident_file)

    # Outdated claim: Redis v7.2 and mTLS 1.3 active
    assert any("v7.2" in c.content and "mTLS 1.3" in c.content for c in arch_chunks)
    # Reality claim: Rolled back to v5.4.12, no mTLS 1.3
    assert any("v5.4" in c.content and "NOT support mutual TLS" in c.content for c in incident_chunks)
