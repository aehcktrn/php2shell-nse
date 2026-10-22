"""Read-only, evidence-aware import of authenticated PHP runtime inventories.

This module validates the shape, binding, freshness and consistency of supplied
attestations. It does not authenticate their origin, execute commands, fetch
references, or infer vendor backports from a version string. A confirmed state
is conditional on the operator's trusted evidence and declared backend coverage.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import math
from pathlib import Path
from typing import Any

CVES = ("CVE-2026-109618", "CVE-2026-109619")
STATUSES = {"fixed", "affected", "unknown"}
MAX_INVENTORY_BYTES = 16 * 1024 * 1024
TRUST_NOTE = (
    "Conclusion conditionnelle aux preuves fournies: l'origine de l'inventaire, "
    "les references et l'exhaustivite declaree ne sont pas verifiees automatiquement."
)


class InventoryError(ValueError):
    """The input inventory cannot be read safely or has an invalid envelope."""


def parse_time(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("Horodatage ISO 8601 avec fuseau requis.")
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None or stamp.utcoffset() is None:
        raise ValueError("L'horodatage doit inclure un fuseau.")
    return stamp.astimezone(timezone.utc)


def normalize_hostname(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError("Nom d'hote invalide.")
    name = value.rstrip(".").lower()
    if any(char.isspace() or ord(char) < 32 for char in name) or any(c in name for c in "/\\@?#"):
        raise ValueError("Nom d'hote invalide.")
    try:
        return str(ipaddress.ip_address(name.strip("[]")))
    except ValueError:
        pass
    name = name.encode("idna").decode("ascii")
    labels = name.split(".")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
           or not all(char.isalnum() or char == "-" for char in label) for label in labels):
        raise ValueError("Nom d'hote invalide.")
    return name


def _port(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError("Port TCP invalide.")
    number = int(value)
    if str(number) != str(value) or not 1 <= number <= 65535:
        raise ValueError("Port TCP invalide.")
    return number


def _nonempty(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        raise ValueError(f"{label} requis et limite a 4096 caracteres.")
    if any(ord(char) < 32 for char in value):
        raise ValueError(f"{label} contient des caracteres de controle.")
    return value


def _record_binding(record: dict[str, Any]) -> tuple[str, int, str, str]:
    name, number = normalize_hostname(record.get("hostname")), _port(record.get("port"))
    scheme = record.get("scheme")
    if scheme not in ("http", "https"):
        raise ValueError("Scheme http ou https requis.")
    ip = record.get("ip", "")
    if ip:
        ip = str(ipaddress.ip_address(ip))
    return name, number, scheme, ip


def _row_binding(row: dict[str, Any]) -> tuple[str, int, str, str] | None:
    try:
        name, number = normalize_hostname(row.get("hostname")), _port(row.get("port"))
        scheme = row.get("scheme") or ("https" if row.get("service", "").startswith("ssl/")
                                        or row.get("service") == "https" else "http")
        if scheme not in ("http", "https"):
            return None
        ip = str(ipaddress.ip_address(row["ip"])) if row.get("ip") else ""
        return name, number, scheme, ip
    except (ValueError, TypeError, UnicodeError):
        return None


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InventoryError(f"Cle JSON dupliquee: {key}")
        result[key] = value
    return result


def load_inventory(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > MAX_INVENTORY_BYTES:
            raise InventoryError("Inventaire trop volumineux (16 Mio maximum).")
        raw = path.read_bytes()
        data = json.loads(raw, object_pairs_hook=_unique_object)
    except (OSError, ValueError, UnicodeError) as exc:
        raise InventoryError(f"Impossible de lire l'inventaire JSON: {exc}") from exc
    if not isinstance(data, dict) or str(data.get("schema_version")) != "1" \
            or not isinstance(data.get("records"), list):
        raise InventoryError("Inventaire attendu: schema_version='1' et records=[...].")
    if len(data["records"]) > 100000 or any(not isinstance(item, dict) for item in data["records"]):
        raise InventoryError("Liste records invalide ou trop volumineuse.")
    # Bad binding must not silently disappear from the matching process.
    for index, record in enumerate(data["records"]):
        try:
            _record_binding(record)
        except (ValueError, TypeError, UnicodeError) as exc:
            raise InventoryError(f"records[{index}]: correspondance service invalide: {exc}") from exc
    return {"records": data["records"], "sha256": hashlib.sha256(raw).hexdigest(),
            "filename": path.name, "trust_note": TRUST_NOTE}


def _validate_record(record: dict[str, Any], now: datetime, max_age: float) -> tuple[str, str, dict[str, Any]]:
    if record.get("authenticated") is not True:
        return "UNVERIFIED", "Collecte authentifiee non attestee.", {}
    try:
        _nonempty(record.get("source"), "Source")
        _nonempty(record.get("evidence_reference"), "Reference de preuve")
        observed = parse_time(record.get("observed_at"))
    except (ValueError, TypeError) as exc:
        return "UNVERIFIED", str(exc), {}
    if observed > now + timedelta(minutes=5):
        return "UNVERIFIED", "Preuve datee dans le futur.", {}
    if now - observed > timedelta(hours=max_age):
        return "STALE", "Preuve trop ancienne pour la campagne courante.", {}
    if not isinstance(record.get("covers_all_backends"), bool):
        return "UNVERIFIED", "Exhaustivite des backends non declaree.", {}
    instances = record.get("instances")
    if not isinstance(instances, list) or not instances:
        return "UNVERIFIED", "Aucun runtime actif decrit.", {}
    details = {}
    for instance in instances:
        if not isinstance(instance, dict):
            return "UNVERIFIED", "Description de runtime invalide.", {}
        try:
            identity = _nonempty(instance.get("id"), "Identifiant runtime")
            _nonempty(instance.get("runtime"), "Runtime ou SAPI")
            _nonempty(instance.get("version"), "Version runtime")
            _nonempty(instance.get("package") or instance.get("build_id"), "Paquet ou build")
        except ValueError as exc:
            return "UNVERIFIED", str(exc), {}
        if identity in details:
            return "CONFLICT", "Identifiant runtime duplique dans une preuve.", {}
        if instance.get("active_runtime_verified") is not True:
            return "UNVERIFIED", "Le build charge par un runtime actif n'est pas atteste.", {}
        cves = instance.get("cves")
        if not isinstance(cves, dict) or any(cves.get(cve) not in STATUSES for cve in CVES):
            return "UNVERIFIED", "Statut explicite des deux CVE requis pour chaque runtime.", {}
        details[identity] = tuple(cves[cve] for cve in CVES)
    values = [state for pair in details.values() for state in pair]
    if "affected" in values:
        return "PATCH_MISSING_CONFIRMED", "Au moins un runtime actif atteste reste affecte.", details
    if all(value == "fixed" for value in values) and record["covers_all_backends"]:
        return "PATCH_CONFIRMED", "Les deux correctifs sont attestes sur tous les runtimes actifs declares.", details
    return "PARTIAL", "Preuves incompletes: couverture partielle ou statut CVE encore inconnu.", details


def assess_runtime(row: dict[str, Any], inventory: dict[str, Any] | None,
                   *, now: datetime | None = None, max_age_hours: float = 24) -> dict[str, Any]:
    """Return separate inventory fields; never change the network assessment."""
    if isinstance(max_age_hours, bool) or not isinstance(max_age_hours, (float, int)) \
            or not math.isfinite(max_age_hours) or max_age_hours <= 0:
        raise InventoryError("Age maximal de preuve strictement positif requis.")
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise InventoryError("Le temps de reference doit inclure un fuseau.")
    result = {"inventory_patch_status": "NOT_PROVIDED", "inventory_source": "",
              "inventory_observed_at": "", "inventory_reason": "Aucune preuve serveur correspondante.",
              "inventory_evidence_references": [], "inventory_trust_note": TRUST_NOTE}
    binding = _row_binding(row)
    if not inventory or not binding:
        return result
    matches = []
    for record in inventory["records"]:
        candidate = _record_binding(record)
        if candidate[:3] == binding[:3] and (not candidate[3] or candidate[3] == binding[3]):
            matches.append(record)
    if not matches:
        return result
    observations = [_validate_record(record, now, max_age_hours) for record in matches]
    states = [item[0] for item in observations]
    identities = {}
    conflict = False
    for _, _, details in observations:
        for identity, statuses in details.items():
            if identity in identities and identities[identity] != statuses:
                conflict = True
            identities[identity] = statuses
    if "PATCH_CONFIRMED" in states and "PATCH_MISSING_CONFIRMED" in states:
        conflict = True
    if conflict or "CONFLICT" in states:
        status, reason = "CONFLICT", "Preuves serveur contradictoires: reconciliation requise."
    elif "UNVERIFIED" in states:
        status, reason = "UNVERIFIED", "; ".join(item[1] for item in observations if item[0] == "UNVERIFIED")
    elif "STALE" in states:
        status, reason = "STALE", "Au moins une preuve correspondante depasse l'age maximal autorise."
    elif "PATCH_MISSING_CONFIRMED" in states:
        status, reason = "PATCH_MISSING_CONFIRMED", "Au moins un runtime actif atteste reste affecte."
    elif all(state == "PATCH_CONFIRMED" for state in states):
        # Two purportedly exhaustive snapshots with different runtime sets are
        # not one coherent statement of complete coverage.
        sets = {frozenset(item[2]) for item in observations}
        if len(sets) > 1:
            status, reason = "CONFLICT", "Les preuves exhaustives ne decrivent pas le meme ensemble de runtimes."
        else:
            status, reason = "PATCH_CONFIRMED", observations[0][1]
    else:
        status, reason = "PARTIAL", "La preuve serveur ne confirme pas les deux correctifs sur tous les backends."
    result.update({
        "inventory_patch_status": status, "inventory_reason": reason,
        "inventory_source": " | ".join(dict.fromkeys(str(item.get("source", "")) for item in matches)),
        "inventory_observed_at": " | ".join(dict.fromkeys(str(item.get("observed_at", "")) for item in matches)),
        "inventory_evidence_references": list(dict.fromkeys(str(item.get("evidence_reference", "")) for item in matches)),
        "inventory_records_count": len(matches),
        "inventory_instances": [{"id": key, "cves": dict(zip(CVES, value))} for key, value in identities.items()],
    })
    return result
