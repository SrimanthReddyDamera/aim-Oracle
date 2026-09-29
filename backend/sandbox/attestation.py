"""
ORACLE 5.1 — Cryptographic Attestation & Digital Proof Seal

Implements genuine Ed25519 digital signing and verification for verification manifests.
Computes SHA-256 digests for all execution artifacts and guarantees tamper detection.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from backend.sandbox.models import AttestationSeal, VerificationManifest


class AttestationAuthority:
    """
    Manages Ed25519 cryptographic signing keys and attestation seals for ORACLE verifications.
    """

    DEFAULT_KEY_PATH = Path("oracle_dev_ed25519.pem")

    def __init__(self, private_key_pem: Optional[bytes] = None, signer_id: str = "oracle-sandbox-engine/v5.1"):
        self.signer_id = signer_id
        if private_key_pem:
            self._private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        else:
            # Check environment or local file, or generate a dev key
            env_key = os.environ.get("ORACLE_SIGNING_KEY_PEM")
            if env_key:
                self._private_key = serialization.load_pem_private_key(env_key.encode("utf-8"), password=None)
            elif self.DEFAULT_KEY_PATH.exists():
                key_bytes = self.DEFAULT_KEY_PATH.read_bytes()
                self._private_key = serialization.load_pem_private_key(key_bytes, password=None)
            else:
                # Generate new key for dev/test
                self._private_key = ed25519.Ed25519PrivateKey.generate()
                # Persist dev key for consistency if in current directory
                try:
                    pem = self._private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                    self.DEFAULT_KEY_PATH.write_bytes(pem)
                except Exception:
                    pass

        self._public_key = self._private_key.public_key()

    @property
    def public_key_hex(self) -> str:
        raw_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw_bytes.hex()

    @staticmethod
    def compute_sha256(content: str | bytes) -> str:
        """Calculates SHA-256 hex digest of string or bytes."""
        if isinstance(content, str):
            content = content.encode("utf-8")
        return hashlib.sha256(content).hexdigest()

    @staticmethod
    def canonicalize_manifest(manifest: VerificationManifest | Dict[str, Any]) -> bytes:
        """
        Produces deterministic canonical JSON representation of a manifest.
        Keys are sorted and compact whitespace is enforced.
        """
        if isinstance(manifest, VerificationManifest):
            data = manifest.model_dump()
        else:
            data = dict(manifest)
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign_manifest(
        self,
        manifest: VerificationManifest,
        gate_status: str = "DEPLOYMENT_CLEARED",
    ) -> AttestationSeal:
        """
        Digitally signs the canonical verification manifest with Ed25519.
        Returns a strongly-typed AttestationSeal.
        """
        canonical_bytes = self.canonicalize_manifest(manifest)
        manifest_digest = hashlib.sha256(canonical_bytes).hexdigest()

        # Sign the manifest digest
        signature_bytes = self._private_key.sign(manifest_digest.encode("utf-8"))
        signature_hex = signature_bytes.hex()

        token = f"attest_v51_{manifest.verification_id}_{signature_hex[:16]}"

        return AttestationSeal(
            token=token,
            digest=manifest_digest,
            signature_hex=signature_hex,
            public_key_hex=self.public_key_hex,
            signer=self.signer_id,
            gate_status=gate_status,
            timestamp=manifest.completed_at,
            is_valid=True,
        )

    @classmethod
    def verify_manifest(
        cls,
        manifest: VerificationManifest | Dict[str, Any],
        signature_hex: str,
        public_key_hex: str,
    ) -> bool:
        """
        Independently verifies that the Ed25519 signature matches the canonical manifest.
        Detects any tampering in any field of the manifest.
        """
        try:
            canonical_bytes = cls.canonicalize_manifest(manifest)
            manifest_digest = hashlib.sha256(canonical_bytes).hexdigest()

            pub_key_bytes = bytes.fromhex(public_key_hex)
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_key_bytes)

            sig_bytes = bytes.fromhex(signature_hex)
            public_key.verify(sig_bytes, manifest_digest.encode("utf-8"))
            return True
        except Exception:
            return False
