"""Durable GET/time allowances shared by all HTTP phases of one service.

A reservation is charged before network work starts. Only a completed phase with
validated counters can refund its unused allowance; an interrupted or unknown
phase remains fully charged, including after a process restart. Wall-clock time
between phases is never part of the HTTP traversal budget.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import threading
from typing import TYPE_CHECKING, Any
import uuid

from campaign_state import StateError

if TYPE_CHECKING:
    from campaign_state import EventLedger


SERVICE_SCHEMA_VERSION = "1"
IDENTITY_FIELDS = {"hostname", "ip", "port", "scheme"}
HALT_REASONS = {"HTTP_401", "HTTP_403", "HTTP_429", "AUTHENTICATION_REQUIRED",
                "HTTP_ACCESS_DENIED", "RATE_LIMITED"}


def _integer(value: Any, minimum: int = 0) -> bool:
    return type(value) is int and value >= minimum


def service_identity(hostname: str, ip: str, port: int, scheme: str) -> dict[str, Any]:
    """Canonicalize an already authorized, pinned service, without DNS access."""
    if (not isinstance(hostname, str) or not hostname or hostname != hostname.strip()
            or any(character in hostname for character in "/\\:@?#")
            or not isinstance(ip, str)
            or not isinstance(scheme, str) or scheme.lower() not in ("http", "https")
            or not _integer(port, 1) or port > 65535):
        raise StateError("Identité de service HTTP invalide.")
    name = hostname.rstrip(".").lower()
    if not name or any(character.isspace() or ord(character) < 32 for character in name):
        raise StateError("Nom de service HTTP invalide.")
    try:
        address = str(ipaddress.ip_address(ip))
    except (ValueError, TypeError) as exc:
        raise StateError("Adresse de service HTTP invalide.") from exc
    return {"hostname": name, "ip": address, "port": port, "scheme": scheme.lower()}


def normalize_identity(identity: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(identity, dict) or set(identity) != IDENTITY_FIELDS:
        raise StateError("Identité de service HTTP invalide.")
    return service_identity(**identity)


def identity_key(identity: dict[str, Any]) -> str:
    encoded = json.dumps(normalize_identity(identity), sort_keys=True,
                         separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def validate_collection_record(key: str, record: dict[str, Any]) -> None:
    """Collection records retain their own phase schema, but pin their identity."""
    if (not isinstance(record, dict) or not isinstance(key, str)
            or identity_key(record.get("identity")) != key
            or record["identity"] != normalize_identity(record["identity"])):
        raise StateError("État de collecte HTTP sans identité valide.")


def validate_service_record(key: str, record: dict[str, Any]) -> None:
    """Reject malformed or overdrawn quota snapshots before replay or mutation."""
    fields = {"schema_version", "identity", "max_requests", "budget_ms",
              "charged_requests", "charged_elapsed_ms", "reservations", "halted_reason"}
    if not isinstance(record, dict) or set(record) != fields:
        raise StateError("État de quota HTTP invalide.")
    validate_collection_record(key, record)
    if (record["schema_version"] != SERVICE_SCHEMA_VERSION
            or not _integer(record["max_requests"], 1)
            or not _integer(record["budget_ms"], 1)
            or not _integer(record["charged_requests"])
            or not _integer(record["charged_elapsed_ms"])
            or not isinstance(record["reservations"], dict)
            or (record["halted_reason"] is not None
                and (not isinstance(record["halted_reason"], str)
                     or record["halted_reason"] not in HALT_REASONS))):
        raise StateError("État de quota HTTP invalide.")
    requests = elapsed = 0
    for token, reservation in record["reservations"].items():
        if (not isinstance(token, str) or not token.startswith(key + ":")
                or len(token) != len(key) + 33
                or any(character not in "0123456789abcdef" for character in token[len(key) + 1:])
                or not isinstance(reservation, dict)
                or set(reservation) != {"requests", "budget_ms", "status", "actual_requests",
                                        "actual_elapsed_ms"}
                or not _integer(reservation["requests"], 1)
                or not _integer(reservation["budget_ms"], 1)
                or reservation["status"] not in ("RESERVED", "SETTLED")):
            raise StateError("Réservation HTTP invalide.")
        if reservation["status"] == "RESERVED":
            if (reservation["actual_requests"] is not None
                    or reservation["actual_elapsed_ms"] is not None):
                raise StateError("Réservation HTTP incomplète contradictoire.")
            requests += reservation["requests"]
            elapsed += reservation["budget_ms"]
        else:
            if (not _integer(reservation["actual_requests"])
                    or not _integer(reservation["actual_elapsed_ms"])
                    or reservation["actual_requests"] > reservation["requests"]
                    or reservation["actual_elapsed_ms"] > reservation["budget_ms"]):
                raise StateError("Compteurs HTTP terminés invalides.")
            requests += reservation["actual_requests"]
            elapsed += reservation["actual_elapsed_ms"]
    if (requests != record["charged_requests"] or elapsed != record["charged_elapsed_ms"]
            or requests > record["max_requests"] or elapsed > record["budget_ms"]):
        raise StateError("Quota HTTP incohérent ou dépassé.")


class ServiceBudgets:
    """Thread-safe quota accounting backed by the campaign event ledger."""

    def __init__(self, manifest: dict[str, Any], ledger: EventLedger):
        self.manifest = manifest
        self.ledger = ledger
        self._lock = threading.RLock()
        records = manifest.setdefault("http_services", {})
        if not isinstance(records, dict):
            raise StateError("Collection de quotas HTTP invalide.")
        for key, record in records.items():
            validate_service_record(key, record)

    def _save(self, key: str, record: dict[str, Any]) -> dict[str, Any]:
        validate_service_record(key, record)
        # Never publish an unreserved allowance if durable append fails.
        self.ledger.append("http_service", key, record)
        self.manifest["http_services"][key] = record
        return copy.deepcopy(record)

    def _record(self, key: str) -> dict[str, Any]:
        record = self.manifest["http_services"].get(key)
        if record is None:
            raise StateError("Service HTTP sans quota enregistré.")
        return record

    def ensure(self, identity: dict[str, Any], max_requests: int = 5,
               budget_ms: int = 20000) -> str:
        identity = normalize_identity(identity)
        key = identity_key(identity)
        if not _integer(max_requests, 1) or not _integer(budget_ms, 1):
            raise StateError("Limites de quota HTTP invalides.")
        with self._lock:
            existing = self.manifest["http_services"].get(key)
            if existing is not None:
                if existing["max_requests"] != max_requests or existing["budget_ms"] != budget_ms:
                    raise StateError("Les quotas HTTP ne changent pas pendant une campagne.")
                return key
            self._save(key, {"schema_version": SERVICE_SCHEMA_VERSION, "identity": identity,
                             "max_requests": max_requests, "budget_ms": budget_ms,
                             "charged_requests": 0, "charged_elapsed_ms": 0,
                             "reservations": {}, "halted_reason": None})
            return key

    def remaining(self, key: str) -> dict[str, Any]:
        with self._lock:
            record = self._record(key)
            return {"requests": record["max_requests"] - record["charged_requests"],
                    "budget_ms": record["budget_ms"] - record["charged_elapsed_ms"],
                    "charged_requests": record["charged_requests"],
                    "charged_elapsed_ms": record["charged_elapsed_ms"],
                    "halted_reason": record["halted_reason"],
                    "open_reservations": sum(item["status"] == "RESERVED"
                                             for item in record["reservations"].values())}

    def snapshot(self, key: str) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._record(key))

    def reserve(self, key: str, requests: int, budget_ms: int) -> str:
        if not _integer(requests, 1) or not _integer(budget_ms, 1):
            raise StateError("Réservation HTTP invalide.")
        with self._lock:
            record = copy.deepcopy(self._record(key))
            remaining = self.remaining(key)
            if (record["halted_reason"] or requests > remaining["requests"]
                    or budget_ms > remaining["budget_ms"]):
                raise StateError("Budget HTTP épuisé, réservé ou service arrêté.")
            token = key + ":" + uuid.uuid4().hex
            record["reservations"][token] = {"requests": requests, "budget_ms": budget_ms,
                                              "status": "RESERVED", "actual_requests": None,
                                              "actual_elapsed_ms": None}
            record["charged_requests"] += requests
            record["charged_elapsed_ms"] += budget_ms
            self._save(key, record)
            return token

    def settle(self, token: str, actual_requests: int,
               actual_elapsed_ms: int) -> dict[str, Any]:
        if (not isinstance(token, str) or ":" not in token
                or not _integer(actual_requests) or not _integer(actual_elapsed_ms)):
            raise StateError("Compteurs HTTP terminés invalides.")
        key = token.split(":", 1)[0]
        with self._lock:
            record = copy.deepcopy(self._record(key))
            reservation = record["reservations"].get(token)
            if reservation is None:
                raise StateError("Réservation HTTP inconnue.")
            if reservation["status"] == "SETTLED":
                if (reservation["actual_requests"] != actual_requests
                        or reservation["actual_elapsed_ms"] != actual_elapsed_ms):
                    raise StateError("Une réservation terminée ne peut être recomptée.")
                return record
            if (actual_requests > reservation["requests"]
                    or actual_elapsed_ms > reservation["budget_ms"]):
                raise StateError("Le parcours HTTP dépasse son allocation réservée.")
            record["charged_requests"] -= reservation["requests"] - actual_requests
            record["charged_elapsed_ms"] -= reservation["budget_ms"] - actual_elapsed_ms
            reservation.update(status="SETTLED", actual_requests=actual_requests,
                               actual_elapsed_ms=actual_elapsed_ms)
            return self._save(key, record)

    def halt(self, key: str, reason: str) -> dict[str, Any]:
        if not isinstance(reason, str) or reason not in HALT_REASONS:
            raise StateError("Cause d'arrêt HTTP invalide.")
        with self._lock:
            record = copy.deepcopy(self._record(key))
            if record["halted_reason"] is not None:
                return record
            record["halted_reason"] = reason
            return self._save(key, record)
