#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""passport_issuance_bench.py

Simulates, at a cryptographic/electronic level, the *issuance* process of an ePassport
in order to estimate per-step timings and total execution time.

Purpose
-------
- Compare timings for classical cryptography (pre-PQC) vs PQC signatures:
  - CRYSTALS-Dilithium (ML-DSA-44 / 65 / 87)
  - SPHINCS+ (SLH-DSA)

Inputs
------
- MRZ: either a .txt file with 2 MRZ lines, or the 2 lines passed via CLI.
- 1x JPG (portrait)
- 2x WSQ (fingerprints)
- 1x JPG (signature)

What it simulates
-----------------
It does NOT generate real DGs/EF.COM/EF.SOD files or full ASN.1 structures.
It DOES simulate the typical cryptographic steps of issuance and measure timings:
- Reading inputs
- Building “DG blobs” (DG1, DG2, DG3, DG7) as bytes
- Hashing each DG
- Issuance PKI (self-signed CSCA + DS certificate signed by CSCA)
- Signing the “SOD payload” (equivalent to PA)
- Active Authentication (AA): key generation + challenge signing/verification
- Chip Authentication (CA): ECDH key generation + shared secret derivation
- (Optional) PACE (highly simplified): MRZ/CAN KDF + ECDH + MAC

Backends
--------
- Classical: uses `cryptography` (RSA/ECDSA/ECDH/HKDF).
- PQC: attempts to use `oqs` (oqs-python/liboqs). If it is not available,
  the script falls back to "simulate" mode (uses repeated hashing to approximate load).

Usage
-----
Classical:
  python passport_issuance_bench.py --mrz-file mrz.txt --portrait face.jpg --finger1 f1.wsq --finger2 f2.wsq --signature sig.jpg --suite classic --runs 5 --out report_classic.json

Dilithium:
  python passport_issuance_bench.py --mrz-file mrz.txt --portrait face.jpg --finger1 f1.wsq --finger2 f2.wsq --signature sig.jpg --suite pqc-dilithium --runs 5 --out report_dilithium.json

SPHINCS+:
  python passport_issuance_bench.py --mrz-file mrz.txt --portrait face.jpg --finger1 f1.wsq --finger2 f2.wsq --signature sig.jpg --suite pqc-sphincs --runs 5 --out report_sphincs.json

Important notes
---------------
- Timings depend HEAVILY on CPU, libraries (C vs pure Python), and input sizes.
- In real ePassports, CA/PA/AA and PACE have exact structures and requirements
  (ICAO 9303 / BSI TR-03110). This script models the typical cryptographic workload.

"""

from __future__ import annotations

import argparse
import base64
import json
import os
import platform
import secrets
import statistics
import sys
import time
from datetime import timezone
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import hashlib

# -----------------------------
# Timing utilities
# -----------------------------

@dataclass
class StepTiming:
    name: str
    seconds: float

@dataclass
class RunReport:
    suite: str
    steps: List[StepTiming]
    total_seconds: float

@dataclass
class SummaryReport:
    suite: str
    runs: int
    per_step_stats: Dict[str, Dict[str, float]]
    total_stats: Dict[str, float]
    environment: Dict[str, Any]
    notes: Dict[str, Any]


class Timer:
    def __init__(self):
        self.steps: List[StepTiming] = []

    def timeit(self, name: str, fn: Callable[[], Any]) -> Any:
        t0 = time.perf_counter()
        out = fn()
        t1 = time.perf_counter()
        self.steps.append(StepTiming(name=name, seconds=t1 - t0))
        return out


def read_bytes(path: Path) -> bytes:
    with path.open("rb") as f:
        return f.read()


# -----------------------------
# MRZ helpers
# -----------------------------

def load_mrz(mrz_file: Optional[Path], mrz_line1: Optional[str], mrz_line2: Optional[str]) -> Tuple[str, str]:
    if mrz_file:
        txt = mrz_file.read_text(encoding="utf-8", errors="replace").splitlines()
        lines = [l.strip() for l in txt if l.strip()]
        if len(lines) < 2:
            raise ValueError("The MRZ file must contain at least 2 lines.")
        return lines[0], lines[1]
    if mrz_line1 and mrz_line2:
        return mrz_line1.strip(), mrz_line2.strip()
    raise ValueError("You must provide --mrz-file or both --mrz-line1 and --mrz-line2")


# -----------------------------
# Hashing
# -----------------------------

def hash_bytes(data: bytes, algo: str = "sha256") -> bytes:
    h = hashlib.new(algo)
    h.update(data)
    return h.digest()


# -----------------------------
# Cripto clásica (cryptography)
# -----------------------------

class ClassicCrypto:
    def __init__(self, sig_alg: str = "rsa", rsa_bits: int = 3072, ec_curve: str = "P-256"):
        self.sig_alg = sig_alg
        self.rsa_bits = rsa_bits
        self.ec_curve = ec_curve

        # Lazy import to allow running the script without cryptography
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa, ec
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
            from cryptography.hazmat.primitives import serialization
            from cryptography.x509.oid import NameOID
            import cryptography.x509 as x509
            from datetime import datetime, timedelta
        except Exception as e:
            raise RuntimeError(
                "Missing 'cryptography' library. Install it with: pip install cryptography"
            ) from e

        self._rsa = rsa
        self._ec = ec
        self._hashes = hashes
        self._padding = padding
        self._HKDF = HKDF
        self._serialization = serialization
        self._x509 = x509
        self._NameOID = NameOID
        self._datetime = datetime
        self._timedelta = timedelta

    # ---- Certificates (CSCA / DS) ----
    def gen_sig_keypair(self):
        if self.sig_alg.lower() == "rsa":
            return self._rsa.generate_private_key(public_exponent=65537, key_size=self.rsa_bits)
        elif self.sig_alg.lower() == "ecdsa":
            curve = self._ec.SECP256R1() if self.ec_curve.upper() in ("P-256", "SECP256R1") else self._ec.SECP384R1()
            return self._ec.generate_private_key(curve)
        else:
            raise ValueError("sig_alg debe ser 'rsa' o 'ecdsa'")

    def self_signed_cert(self, private_key, common_name: str):
        x509 = self._x509
        NameOID = self._NameOID
        now = self._datetime.now(timezone.utc)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"ZZ"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Simulated CSCA"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + self._timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(private_key, self._hashes.SHA256())
        )
        return cert

    def cert_signed_by(self, subject_private_key, issuer_cert, issuer_private_key, common_name: str):
        x509 = self._x509
        NameOID = self._NameOID
        now = self._datetime.now(timezone.utc)

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"ZZ"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Simulated DS"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer_cert.subject)
            .public_key(subject_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + self._timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(issuer_private_key, self._hashes.SHA256())
        )
        return cert

    # ---- Signature / verification (PA/AA) ----
    def sign(self, private_key, message: bytes) -> bytes:
        if self.sig_alg.lower() == "rsa":
            return private_key.sign(
                message,
                self._padding.PSS(
                    mgf=self._padding.MGF1(self._hashes.SHA256()),
                    salt_length=self._padding.PSS.MAX_LENGTH,
                ),
                self._hashes.SHA256(),
            )
        else:
            return private_key.sign(message, self._ec.ECDSA(self._hashes.SHA256()))

    def verify(self, public_key, message: bytes, signature: bytes) -> bool:
        try:
            if self.sig_alg.lower() == "rsa":
                public_key.verify(
                    signature,
                    message,
                    self._padding.PSS(
                        mgf=self._padding.MGF1(self._hashes.SHA256()),
                        salt_length=self._padding.PSS.MAX_LENGTH,
                    ),
                    self._hashes.SHA256(),
                )
            else:
                public_key.verify(signature, message, self._ec.ECDSA(self._hashes.SHA256()))
            return True
        except Exception:
            return False

    # ---- Chip Authentication (CA) ECDH + HKDF ----
    def gen_ecdh_keypair(self):
        curve = self._ec.SECP256R1()
        return self._ec.generate_private_key(curve)

    def ecdh_shared(self, priv, peer_pub) -> bytes:
        return priv.exchange(self._ec.ECDH(), peer_pub)

    def hkdf(self, ikm: bytes, info: bytes = b"ICAO-CA", length: int = 32, salt: Optional[bytes] = None) -> bytes:
        hkdf = self._HKDF(
            algorithm=self._hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
        )
        return hkdf.derive(ikm)

    # ---- PACE (simplified) ----
    def pace_sim(self, mrz_or_can: str) -> None:
        # Simple model: K_pi = SHA256(MRZ/CAN), then ECDH + HMAC token
        import hmac

        k_pi = hashlib.sha256(mrz_or_can.encode("utf-8", errors="ignore")).digest()
        # Ephemeral terminal/chip ECDH
        chip = self.gen_ecdh_keypair()
        term = self.gen_ecdh_keypair()
        ss1 = self.ecdh_shared(chip, term.public_key())
        ss2 = self.ecdh_shared(term, chip.public_key())
        assert ss1 == ss2
        k_sess = self.hkdf(ss1, info=b"PACE")
        # Tokens (MACs over public keys)
        token_chip = hmac.new(k_pi, chip.public_key().public_bytes(
            encoding=self._serialization.Encoding.X962,
            format=self._serialization.PublicFormat.UncompressedPoint,
        ), hashlib.sha256).digest()
        token_term = hmac.new(k_pi, term.public_key().public_bytes(
            encoding=self._serialization.Encoding.X962,
            format=self._serialization.PublicFormat.UncompressedPoint,
        ), hashlib.sha256).digest()
        # Tokens help prevent trivial offline attacks; here we only compute them
        _ = (k_sess, token_chip, token_term)


def combine_hybrid_secrets(classic_ss: bytes, pqc_ss: bytes) -> bytes:
    """Combine two secrets (classical + PQC) and return IKM for a KDF.

    Note: real designs use a KDF over the concatenation plus context.
    Here we return SHA-256(classic||pqc) as a compact IKM.
    """
    return hashlib.sha256(classic_ss + pqc_ss).digest()

# -----------------------------
# PQC signature (oqs) or simulation
# -----------------------------

class PQCSignature:
    """Wrapper for PQC signatures using oqs; falls back to simulation."""

    def __init__(self, algorithm: str, mode: str = "auto"):
        self.algorithm = algorithm
        self.mode = mode
        self._oqs = None
        if mode in ("auto", "oqs"):
            try:
                import oqs  # type: ignore
                self._oqs = oqs
                self.mode = "oqs"
            except Exception:
                if mode == "oqs":
                    raise RuntimeError("Could not import 'oqs'. Install it with: pip install oqs")
                self.mode = "simulate"
        else:
            self.mode = "simulate"

    def keygen(self) -> Tuple[bytes, bytes]:
        if self.mode == "oqs":
            with self._oqs.Signature(self.algorithm) as s:
                pk = s.generate_keypair()
                sk = s.export_secret_key()
                return pk, sk
        # Simulation: pseudo-random keys
        pk = secrets.token_bytes(1312)
        sk = secrets.token_bytes(2528)
        return pk, sk

    def sign(self, message: bytes, sk: bytes) -> bytes:
        if self.mode == "oqs":
            with self._oqs.Signature(self.algorithm, sk) as s:
                return s.sign(message)
        # Simulation: repeated hashing (consumes CPU)
        x = message + sk
        for _ in range(2000):
            x = hashlib.sha256(x).digest()
        return x

    def verify(self, message: bytes, signature: bytes, pk: bytes) -> bool:
        if self.mode == "oqs":
            with self._oqs.Signature(self.algorithm) as s:
                return s.verify(message, signature, pk)
                
        # Simulation: recomputes and approximately compares (not real verification)
        x = message + pk
        for _ in range(2000):
            x = hashlib.sha256(x).digest()
        # It is not truly verifiable, but we return True if lengths match
        return isinstance(signature, (bytes, bytearray)) and len(signature) > 0


class PQCKEM:
    """Wrapper for PQC KEM using oqs; falls back to simulation."""

    def __init__(self, algorithm: str, mode: str = "auto"):
        self.algorithm = algorithm
        self.mode = mode
        self._oqs = None
        if mode in ("auto", "oqs"):
            try:
                import oqs  # type: ignore
                self._oqs = oqs
                self.mode = "oqs"
            except Exception:
                if mode == "oqs":
                    raise RuntimeError("Could not import 'oqs'. Install it with: pip install oqs")
                self.mode = "simulate"
        else:
            self.mode = "simulate"

    def keygen(self) -> Tuple[bytes, bytes]:
        """Return (pk, sk)."""
        if self.mode == "oqs":
            with self._oqs.Signature(self.algorithm) as s:
                pk = kem.generate_keypair()
                sk = kem.export_secret_key()
                return pk, sk
        # Simulation: approximate sizes
        pk = secrets.token_bytes(1184)
        sk = secrets.token_bytes(2400)
        return pk, sk

    def encaps(self, pk: bytes) -> Tuple[bytes, bytes]:
        """Return (ciphertext, shared_secret)."""
        if self.mode == "oqs":
            with self._oqs.KeyEncapsulation(self.algorithm) as kem:
                ct, ss = kem.encap_secret(pk)
                return ct, ss
        # Simulation: random ct + derived ss
        ct = secrets.token_bytes(1088)
        ss = hashlib.sha256(pk + ct).digest()
        return ct, ss

    def decaps(self, ct: bytes, sk: bytes) -> bytes:
        """Return shared_secret."""
        if self.mode == "oqs":
            with self._oqs.KeyEncapsulation(self.algorithm) as kem:
                return kem.decap_secret(ct)
        return hashlib.sha256(sk + ct).digest()

# -----------------------------
# Simulated issuance (run)
# -----------------------------

@dataclass
class Inputs:
    mrz1: str
    mrz2: str
    portrait: bytes
    finger1: bytes
    finger2: bytes
    signature: bytes


def load_inputs(timer: Timer, args) -> Inputs:
    mrz1, mrz2 = timer.timeit("load_mrz", lambda: load_mrz(args.mrz_file, args.mrz_line1, args.mrz_line2))
    portrait = timer.timeit("read_portrait_jpg", lambda: read_bytes(args.portrait))
    fingerprint1_bytes = timer.timeit("read_fingerprint1_wsq", lambda: read_bytes(args.finger1))
    fingerprint2_bytes = timer.timeit("read_fingerprint2_wsq", lambda: read_bytes(args.finger2))
    signature_bytes = timer.timeit("read_signature_jpg", lambda: read_bytes(args.signature))
    return Inputs(mrz1=mrz1, mrz2=mrz2, portrait=portrait, finger1=fingerprint1_bytes, finger2=fingerprint2_bytes, signature=signature_bytes)


def build_dgs(timer: Timer, inputs: Inputs) -> Dict[str, bytes]:
    def _build():
        dg1 = (inputs.mrz1 + "\n" + inputs.mrz2).encode("utf-8", errors="ignore")
        dg2 = inputs.portrait
        # DG3 usually contains templates/images; here we concatenate the 2 WSQ files
        dg3 = inputs.finger1 + b"\x00\x00" + inputs.finger2
        dg7 = inputs.signature
        return {"DG1": dg1, "DG2": dg2, "DG3": dg3, "DG7": dg7}
    return timer.timeit("build_dg_blobs", _build)


def hash_dgs(timer: Timer, dgs: Dict[str, bytes], algo: str = "sha256") -> Dict[str, bytes]:
    def _hash_all():
        return {k: hash_bytes(v, algo=algo) for k, v in dgs.items()}
    return timer.timeit(f"hash_dgs_{algo}", _hash_all)


def sod_payload_from_hashes(dg_hashes: Dict[str, bytes]) -> bytes:
    # In a real EF.SOD this would be CMS SignedData with ASN.1 structure.
    # Here we create a deterministic "payload": JSON with base64 hashes.
    payload = {k: base64.b64encode(v).decode("ascii") for k, v in sorted(dg_hashes.items())}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def issue_classic(timer: Timer, dgs: Dict[str, bytes], dg_hashes: Dict[str, bytes], pace: bool, ca_mode: str, kem_alg: str, pqc_mode: str) -> None:
    cc = timer.timeit("init_classic_crypto", lambda: ClassicCrypto(sig_alg="rsa", rsa_bits=3072))

    # CSCA
    csca_priv = timer.timeit("CSCA_keygen", cc.gen_sig_keypair)
    csca_cert = timer.timeit("CSCA_self_signed_cert", lambda: cc.self_signed_cert(csca_priv, "CSCA-ZZ"))

    # DS
    ds_priv = timer.timeit("DS_keygen", cc.gen_sig_keypair)
    ds_cert = timer.timeit("DS_cert_signed_by_CSCA", lambda: cc.cert_signed_by(ds_priv, csca_cert, csca_priv, "DS-ZZ"))

    # PA: sign the SOD payload
    sod_payload = timer.timeit("build_SOD_payload", lambda: sod_payload_from_hashes(dg_hashes))
    sod_sig = timer.timeit("PA_sign_SOD", lambda: cc.sign(ds_priv, sod_payload))
    _ok = timer.timeit("PA_verify_SOD", lambda: cc.verify(ds_priv.public_key(), sod_payload, sod_sig))

    # AA: keypair + challenge signature
    aa_priv = timer.timeit("AA_keygen", cc.gen_sig_keypair)
    challenge = secrets.token_bytes(32)
    aa_sig = timer.timeit("AA_sign_challenge", lambda: cc.sign(aa_priv, challenge))
    _aa_ok = timer.timeit("AA_verify_challenge", lambda: cc.verify(aa_priv.public_key(), challenge, aa_sig))    # CA: classical (ECDH) or hybrid (ECDH + PQC KEM)
    if ca_mode == "classic":
        ca_chip_priv = timer.timeit("CA_chip_keygen_ECDH", cc.gen_ecdh_keypair)
        ca_term_priv = timer.timeit("CA_terminal_ephemeral_keygen", cc.gen_ecdh_keypair)
        ss_chip = timer.timeit("CA_ecdh_shared_chip", lambda: cc.ecdh_shared(ca_chip_priv, ca_term_priv.public_key()))
        ss_term = timer.timeit("CA_ecdh_shared_terminal", lambda: cc.ecdh_shared(ca_term_priv, ca_chip_priv.public_key()))
        _ = timer.timeit("CA_derive_session_keys", lambda: (cc.hkdf(ss_chip, info=b"CA"), cc.hkdf(ss_term, info=b"CA")))
    else:
        # Hybrid: classical ECDH secret + PQC secret (KEM), combined with a KDF
        kem = timer.timeit(f"CA_init_KEM_{kem_alg}", lambda: PQCKEM(kem_alg, mode=pqc_mode))
        # Static keys on the chip side (as in CA): pk/sk
        kem_pk, kem_sk = timer.timeit(f"CA_KEM_keygen_chip_{kem_alg}", kem.keygen)

        ca_chip_priv = timer.timeit("CA_chip_keygen_ECDH", cc.gen_ecdh_keypair)
        ca_term_priv = timer.timeit("CA_terminal_ephemeral_keygen", cc.gen_ecdh_keypair)
        ss_classic_chip = timer.timeit("CA_ecdh_shared_chip", lambda: cc.ecdh_shared(ca_chip_priv, ca_term_priv.public_key()))
        ss_classic_term = timer.timeit("CA_ecdh_shared_terminal", lambda: cc.ecdh_shared(ca_term_priv, ca_chip_priv.public_key()))

        ct, ss_pqc_term = timer.timeit(f"CA_KEM_encaps_terminal_{kem_alg}", lambda: kem.encaps(kem_pk))
        ss_pqc_chip = timer.timeit(f"CA_KEM_decaps_chip_{kem_alg}", lambda: kem.decaps(ct, kem_sk))

        ikm_chip = timer.timeit("CA_hybrid_combine_IKM_chip", lambda: combine_hybrid_secrets(ss_classic_chip, ss_pqc_chip))
        ikm_term = timer.timeit("CA_hybrid_combine_IKM_terminal", lambda: combine_hybrid_secrets(ss_classic_term, ss_pqc_term))

        _ = timer.timeit("CA_hybrid_derive_session_keys", lambda: (cc.hkdf(ikm_chip, info=b"CA-HYB"), cc.hkdf(ikm_term, info=b"CA-HYB")))

    # Optional PACE
    if pace:
        mrz_concat = (dgs["DG1"].decode("utf-8", errors="ignore"))
        timer.timeit("PACE_simulated", lambda: cc.pace_sim(mrz_concat))

    # Avoid warnings about unused variables
    _ = (csca_cert, ds_cert, _ok, _aa_ok)


def issue_pqc(timer: Timer, dgs: Dict[str, bytes], dg_hashes: Dict[str, bytes], pq_alg: str, pace: bool, pq_mode: str, ca_mode: str, kem_alg: str) -> None:
    """PQC: replace PA (SOD signature) and AA (challenge signature) with PQC.
    CA remains classical (ECDH) by default.
    """
    # Classical cryptography for CA and certificates (simplified: "dummy" certificates),
    # because PQC X.509 is not yet universally standardized.
    cc = timer.timeit("init_classic_crypto_for_CA", lambda: ClassicCrypto(sig_alg="rsa", rsa_bits=3072))

    # Simulated "certificates" (key generation only) to reflect provisioning cost.
    csca_priv = timer.timeit("CSCA_keygen_classic", cc.gen_sig_keypair)
    _ = timer.timeit("CSCA_self_signed_cert", lambda: cc.self_signed_cert(csca_priv, "CSCA-ZZ"))
    ds_priv = timer.timeit("DS_keygen_classic", cc.gen_sig_keypair)
    _ = timer.timeit("DS_cert_signed_by_CSCA", lambda: cc.cert_signed_by(ds_priv, cc.self_signed_cert(csca_priv, "CSCA-ZZ"), csca_priv, "DS-ZZ"))

    # PQC signer
    pq = timer.timeit(f"init_PQC_{pq_alg}", lambda: PQCSignature(pq_alg, mode=pq_mode))
    pk, sk = timer.timeit(f"PQC_keygen_{pq_alg}", pq.keygen)

    sod_payload = timer.timeit("build_SOD_payload", lambda: sod_payload_from_hashes(dg_hashes))
    sod_sig = timer.timeit(f"PA_sign_SOD_{pq_alg}", lambda: pq.sign(sod_payload, sk))
    _ok = timer.timeit(f"PA_verify_SOD_{pq_alg}", lambda: pq.verify(sod_payload, sod_sig, pk))

    # AA also uses PQC
    aa_pk, aa_sk = timer.timeit(f"AA_PQC_keygen_{pq_alg}", pq.keygen)
    challenge = secrets.token_bytes(32)
    aa_sig = timer.timeit(f"AA_sign_challenge_{pq_alg}", lambda: pq.sign(challenge, aa_sk))
    _aa_ok = timer.timeit(f"AA_verify_challenge_{pq_alg}", lambda: pq.verify(challenge, aa_sig, aa_pk))    # CA: classical (ECDH) or hybrid (ECDH + PQC KEM)
    if ca_mode == "classic":
        ca_chip_priv = timer.timeit("CA_chip_keygen_ECDH", cc.gen_ecdh_keypair)
        ca_term_priv = timer.timeit("CA_terminal_ephemeral_keygen", cc.gen_ecdh_keypair)
        ss_chip = timer.timeit("CA_ecdh_shared_chip", lambda: cc.ecdh_shared(ca_chip_priv, ca_term_priv.public_key()))
        ss_term = timer.timeit("CA_ecdh_shared_terminal", lambda: cc.ecdh_shared(ca_term_priv, ca_chip_priv.public_key()))
        _ = timer.timeit("CA_derive_session_keys", lambda: (cc.hkdf(ss_chip, info=b"CA"), cc.hkdf(ss_term, info=b"CA")))
    else:
        kem = timer.timeit(f"CA_init_KEM_{kem_alg}", lambda: PQCKEM(kem_alg, mode=pq_mode))
        kem_pk, kem_sk = timer.timeit(f"CA_KEM_keygen_chip_{kem_alg}", kem.keygen)

        ca_chip_priv = timer.timeit("CA_chip_keygen_ECDH", cc.gen_ecdh_keypair)
        ca_term_priv = timer.timeit("CA_terminal_ephemeral_keygen", cc.gen_ecdh_keypair)
        ss_classic_chip = timer.timeit("CA_ecdh_shared_chip", lambda: cc.ecdh_shared(ca_chip_priv, ca_term_priv.public_key()))
        ss_classic_term = timer.timeit("CA_ecdh_shared_terminal", lambda: cc.ecdh_shared(ca_term_priv, ca_chip_priv.public_key()))

        ct, ss_pqc_term = timer.timeit(f"CA_KEM_encaps_terminal_{kem_alg}", lambda: kem.encaps(kem_pk))
        ss_pqc_chip = timer.timeit(f"CA_KEM_decaps_chip_{kem_alg}", lambda: kem.decaps(ct, kem_sk))

        ikm_chip = timer.timeit("CA_hybrid_combine_IKM_chip", lambda: combine_hybrid_secrets(ss_classic_chip, ss_pqc_chip))
        ikm_term = timer.timeit("CA_hybrid_combine_IKM_terminal", lambda: combine_hybrid_secrets(ss_classic_term, ss_pqc_term))

        _ = timer.timeit("CA_hybrid_derive_session_keys", lambda: (cc.hkdf(ikm_chip, info=b"CA-HYB"), cc.hkdf(ikm_term, info=b"CA-HYB")))

    if pace:
        mrz_concat = (dgs["DG1"].decode("utf-8", errors="ignore"))
        timer.timeit("PACE_simulated", lambda: cc.pace_sim(mrz_concat))

    _ = (_ok, _aa_ok)


# -----------------------------
# Statistics
# -----------------------------

def summarize(reports: List[RunReport]) -> SummaryReport:
    suite = reports[0].suite if reports else "unknown"
    steps_by_name: Dict[str, List[float]] = {}
    totals = [r.total_seconds for r in reports]

    for r in reports:
        for s in r.steps:
            steps_by_name.setdefault(s.name, []).append(s.seconds)

    def stats(xs: List[float]) -> Dict[str, float]:
        return {
            "mean": statistics.mean(xs),
            "median": statistics.median(xs),
            "stdev": statistics.stdev(xs) if len(xs) > 1 else 0.0,
            "min": min(xs),
            "max": max(xs),
        }

    per_step_stats = {name: stats(vals) for name, vals in steps_by_name.items()}
    total_stats = stats(totals)

    env = {
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "openssl": os.environ.get("OPENSSL_VERSION", "(unknown)"),
    }

    notes = {
        "pqc_backend": "oqs" if "oqs" in sys.modules else "(not imported)",
        "warning": "Timings depend on the hardware. Run multiple repetitions (--runs).",
    }

    return SummaryReport(
        suite=suite,
        runs=len(reports),
        per_step_stats=per_step_stats,
        total_stats=total_stats,
        environment=env,
        notes=notes,
    )


# -----------------------------
# CLI
# -----------------------------

def parse_args():
    p = argparse.ArgumentParser(description="ePassport issuance benchmark (PA/AA/CA) with and without PQC")

    mrz_group = p.add_mutually_exclusive_group(required=True)
    mrz_group.add_argument("--mrz-file", type=Path, help="TXT file with 2 MRZ lines")
    mrz_group.add_argument("--mrz-lines", nargs=2, metavar=("MRZ1", "MRZ2"), help="2 MRZ lines via CLI")

    p.add_argument("--portrait", type=Path, required=True, help="Portrait JPG")
    p.add_argument("--finger1", type=Path, required=True, help="Fingerprint 1 WSQ")
    p.add_argument("--finger2", type=Path, required=True, help="Fingerprint 2 WSQ")
    p.add_argument("--signature", type=Path, required=True, help="Signature JPG")

    p.add_argument("--suite", choices=["classic", "pqc-dilithium", "pqc-sphincs"], default="classic")
    p.add_argument("--pqc-mode", choices=["auto", "oqs", "simulate"], default="auto",
                   help="PQC backend: auto (tries oqs), oqs (required), simulate (without oqs)")
    p.add_argument("--ca-mode", choices=["classic", "hybrid"], default="classic",
                   help="Chip Authentication: classic=ECDH, hybrid=ECDH+PQC KEM")
    p.add_argument("--kem-alg", default="Kyber768",
                   help="KEM algorithm for hybrid CA (e.g., Kyber512/Kyber768/Kyber1024 or ML-KEM-768 depending on backend)")

    p.add_argument("--pace", action="store_true", help="Include the PACE step (simulated) in the timing")
    p.add_argument("--runs", type=int, default=3, help="Number of repetitions (default 3)")
    p.add_argument("--out", type=Path, default=None, help="Save JSON report")
    p.add_argument("--print", dest="do_print", action="store_true", help="Print summary to the console")

    args = p.parse_args()
    if args.mrz_lines:
        args.mrz_line1, args.mrz_line2 = args.mrz_lines
    else:
        args.mrz_line1 = args.mrz_line2 = None

    return args


def run_once(args) -> RunReport:
    timer = Timer()

    inputs = load_inputs(timer, args)
    dgs = build_dgs(timer, inputs)
    dg_hashes = hash_dgs(timer, dgs, algo="sha256")

    if args.suite == "classic":
        timer.timeit("issue_classic_total", lambda: issue_classic(timer, dgs, dg_hashes, args.pace, args.ca_mode, args.kem_alg, args.pqc_mode))
    elif args.suite == "pqc-dilithium":
        # Typical names in liboqs: ML-DSA-44 (Dilithium2) / ML-DSA-65 (Dilithium 3) / ML-DSA-87 (Dilithium 5)
        timer.timeit("issue_pqc_total", lambda: issue_pqc(timer, dgs, dg_hashes, pq_alg="ML-DSA-44", pace=args.pace, pq_mode=args.pqc_mode, ca_mode=args.ca_mode, kem_alg=args.kem_alg))
    elif args.suite == "pqc-sphincs":
        # Typical name in liboqs: SPHINCS+-sha2-128f-simple, etc.
        timer.timeit("issue_pqc_total", lambda: issue_pqc(timer, dgs, dg_hashes, pq_alg="SLH_DSA_PURE_SHA2_128F", pace=args.pace, pq_mode=args.pqc_mode, ca_mode=args.ca_mode, kem_alg=args.kem_alg))
    else:
        raise ValueError("Unknown suite")

    total = sum(s.seconds for s in timer.steps)
    return RunReport(suite=args.suite, steps=timer.steps, total_seconds=total)


def main():
    args = parse_args()

    # Validate files
    for fp in [args.portrait, args.finger1, args.finger2, args.signature]:
        if not fp.exists():
            raise FileNotFoundError(f"Does not exist: {fp}")

    reports: List[RunReport] = []
    for _ in range(args.runs):
        reports.append(run_once(args))

    summary = summarize(reports)

    payload = {
        "summary": asdict(summary),
        "runs": [
            {
                "suite": r.suite,
                "total_seconds": r.total_seconds,
                "steps": [asdict(s) for s in r.steps],
            }
            for r in reports
        ],
    }

    if args.out:
        args.out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    if args.do_print or not args.out:
        print(json.dumps(payload["summary"], indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
