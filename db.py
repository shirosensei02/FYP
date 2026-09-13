"""
db.py
=====
Singleton MongoDB client for the FYP patch-study pipeline.

Connection is established lazily on first use.
The URI is read from the MONGO_URI environment variable (via .env).

Collections
-----------
  fyp_patches.successful_patches  – patches that passed all validation stages
  fyp_patches.all_attempts        – every terminal pipeline attempt
"""

from __future__ import annotations

import os
import logging
from datetime import datetime, timezone

import certifi
from dotenv import load_dotenv
from pymongo import MongoClient, ASCENDING, errors

load_dotenv()

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
_MONGO_URI  = os.getenv("MONGO_URI", "mongodb://localhost:27017")
_DB_NAME    = "fyp_patches"
_COL_PASS   = "successful_patches"
_COL_ATTEMPTS = "all_attempts"

# ── Internal singleton ────────────────────────────────────────────────────────
_client: MongoClient | None = None


def _is_truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _mongo_tls_options(uri: str) -> dict[str, str | bool]:
    """Enable TLS only when the URI or explicit environment opts into it.

    X.509 client credentials are intentionally opt-in: never infer a
    certificate by searching the project directory.
    """
    client_certificate = os.getenv("MONGO_TLS_CERT_FILE")
    tls_enabled = uri.startswith("mongodb+srv://") or _is_truthy(os.getenv("MONGO_TLS")) or bool(client_certificate)
    if not tls_enabled:
        return {}

    options: dict[str, str | bool] = {"tls": True, "tlsCAFile": certifi.where()}
    if client_certificate:
        options["tlsCertificateKeyFile"] = client_certificate
    return options


def _get_db():
    """Return the database, initialising the client on first call."""
    global _client
    if _client is None:
        logger.info("db - connecting to MongoDB: %s", _MONGO_URI.split("@")[-1])
        try:
            _client = MongoClient(
                _MONGO_URI,
                serverSelectionTimeoutMS=5_000,
                **_mongo_tls_options(_MONGO_URI),
            )
            # Verify connectivity early so failures are obvious.
            _client.admin.command("ping")
            _ensure_indexes(_client[_DB_NAME])
            logger.info("db - connected OK")
        except Exception:
            # Do not retain a half-initialised client after a failed connection.
            _client = None
            raise
    return _client[_DB_NAME]


def _ensure_indexes(db) -> None:
    """Create indexes if they don't already exist."""
    for collection_name in (_COL_PASS, _COL_ATTEMPTS):
        col = db[collection_name]
        col.create_index([("package_name", ASCENDING), ("model_used", ASCENDING)])
        col.create_index([("timestamp", ASCENDING)])


# ── Public helpers ────────────────────────────────────────────────────────────

def save_patch_attempt(state: dict, passed: bool) -> str | None:
    """
    Persist one terminal pipeline outcome to MongoDB.

    Both passing and failing attempts are stored in ``all_attempts``.

    Returns the inserted document's str(_id), or None on failure.
    """
    doc = _build_doc(state, passed)
    try:
        db = _get_db()
        result = db[_COL_ATTEMPTS].insert_one(doc)
        inserted_id = str(result.inserted_id)
        logger.info("db - saved attempt passed=%s _id=%s", passed, inserted_id)
        return inserted_id

    except errors.PyMongoError as exc:
        logger.error("db - failed to save to MongoDB: %s", exc)
        return None


def save_patch_result(state: dict, passed: bool) -> str | None:
    """Persist a validated successful patch to ``successful_patches`` only."""
    if not passed:
        return None

    doc = _build_doc(state, passed=True)
    try:
        db = _get_db()
        result = db[_COL_PASS].insert_one(doc)
        inserted_id = str(result.inserted_id)
        logger.info("db - saved validated patch _id=%s", inserted_id)
        return inserted_id
    except errors.PyMongoError as exc:
        logger.error("db - failed to save to MongoDB: %s", exc)
        return None


def _build_doc(state: dict, passed: bool) -> dict:
    patch = state.get("current_patch") or {}
    return {
        "timestamp":       datetime.now(timezone.utc),
        "passed":          passed,
        "package_name":    state.get("package_name"),
        "package_version": state.get("package_version"),
        "model_used":      patch.get("model_used") or state.get("generation_model_used"),
        "attempt_number":  patch.get("attempt_number"),
        "diff":            patch.get("diff"),
        "validation":      state.get("validation") or {},
        "vulnerabilities": state.get("vulnerabilities") or [],
        "errors":          state.get("errors") or [],
        "generation_status": state.get("generation_status"),
        "generation_error": state.get("generation_error"),
    }
