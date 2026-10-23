#!/usr/bin/env python3
"""Export local PHP2Shell XML or JSON results as one CSV row per target.

No scan or network connection is made. Detailed observations remain available
with --detailed; the default export contains cible, php, vulnerable, explication.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unicodedata
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET
from typing import Any

from runtime_inventory import InventoryError, assess_runtime, load_inventory


FIELDS = (
    "row_type", "ip", "hostname", "port", "protocol", "service", "state",
    "verdict", "versions", "fixed_versions", "priority", "remediation",
    "verification", "http_status", "reason", "reason_code", "next_action",
    "php_detected", "path", "scheme", "http_host", "tls_sni", "requests_made",
    "redirect_destinations", "redirect_evaluation_scope",
    "observed_at", "campaign_id", "source_xml", "inventory_patch_status",
    "inventory_source", "inventory_observed_at", "inventory_reason", "address_family", "scan_ports",
)
COMPACT_FIELDS = ("cible", "php", "vulnerable", "explication")
COMPACT_VERDICTS = ("OUI", "NON", "INDETERMINE")
MAX_COMPACT_EXPLANATION = 360
MAX_SUMMARY_PORTS = 10
SCRIPT_ID = "http-php2shell"
STATES = ("POTENTIALLY_VULNERABLE", "PATCHED_VERSION_ADVERTISED", "UNKNOWN")
PRIORITIES = {
    "POTENTIALLY_VULNERABLE": "PATCH_OR_VERIFY_BACKPORT",
    "PATCHED_VERSION_ADVERTISED": "CONFIRM_RUNTIME",
    "UNKNOWN": "VERIFY_RUNTIME",
}
VERDICTS = {
    "POTENTIALLY_VULNERABLE": "VULNERABLE PROBABLE (selon la version annoncee)",
    "PATCHED_VERSION_ADVERTISED": "VERSION CORRIGEE ANNONCEE",
    "UNKNOWN": "INDETERMINE - A VERIFIER",
}
REMEDIATIONS = {
    "POTENTIALLY_VULNERABLE": (
        "Mettre a jour PHP ou confirmer un correctif fournisseur couvrant les deux CVE. "
        "Redemarrer ou recreer les workers web apres mise a jour."
    ),
    "PATCHED_VERSION_ADVERTISED": (
        "Confirmer la version corrigee sur tous les runtimes et backends de l'application."
    ),
    "UNKNOWN": "Verifier le runtime PHP et son paquet/build cote serveur.",
}
VERIFY_RUNTIME = (
    "Verifier le PHP execute par les workers web, les backports et tous les backends; "
    "une banniere seule ne prouve pas la correction ou l'exploitabilite."
)


class ReportError(ValueError):
    """A local scan or report cannot be interpreted safely."""


def _scalar(parent: ET.Element, key: str, default: str = "") -> str:
    elements = [item for item in parent if item.get("key") == key]
    if len(elements) > 1:
        raise ValueError(f"duplicate structured field: {key}")
    if not elements:
        return default
    if elements[0].tag != "elem" or len(elements[0]):
        raise ValueError(f"non-scalar structured field: {key}")
    return elements[0].text or ""


def _array(parent: ET.Element, key: str) -> list[str]:
    tables = [item for item in parent if item.get("key") == key]
    if len(tables) > 1:
        raise ValueError(f"duplicate structured table: {key}")
    if not tables:
        return []
    if tables[0].tag != "table" or any(item.tag != "elem" or len(item) for item in tables[0]):
        raise ValueError(f"non-scalar item in structured table: {key}")
    return [item.text or "" for item in tables[0]]


def _unique(values: list[str]) -> list[str]:
    # Only deduplicate values inside one assessment, never hosts or endpoints.
    return list(dict.fromkeys(value for value in values if value))


def _host_identity(host: ET.Element) -> dict[str, str]:
    addresses = [item.get("addr", "") for item in host.findall("address")
                 if item.get("addrtype") in ("ipv4", "ipv6")]
    names = host.findall("./hostnames/hostname")
    # User-supplied DNS names identify the intended virtual host. A PTR name is
    # useful only when no user-supplied name is present in this host instance.
    selected = [item for item in names if item.get("type") == "user"] or names
    return {
        "ip": " | ".join(_unique(addresses)),
        "hostname": " | ".join(_unique([item.get("name", "") for item in selected])),
    }


def _port_identity(port: ET.Element) -> dict[str, str]:
    service = port.find("service")
    name = service.get("name", "") if service is not None else ""
    if service is not None and service.get("tunnel") == "ssl":
        name = "ssl/" + (name or "unknown")
    return {"port": port.get("portid", ""),
            "protocol": port.get("protocol", ""), "service": name,
            "service_method": service.get("method", "") if service is not None else ""}


def _details(parent: ET.Element, key: str) -> list[dict[str, Any]]:
    """Decode bounded structured NSE tables without saving response bodies."""
    tables = [item for item in parent if item.get("key") == key]
    if not tables:
        return []
    if len(tables) != 1 or tables[0].tag != "table":
        raise ValueError("invalid structured details")
    count = 0
    def decode(node: ET.Element, depth: int = 0) -> Any:
        nonlocal count
        count += 1
        if count > 10000 or depth > 12:
            raise ValueError("structured evidence limits exceeded")
        if node.tag == "elem" and not len(node):
            return node.text or ""
        if node.tag != "table":
            raise ValueError("invalid structured detail element")
        if not len(node):
            return []
        keyed = [child.get("key") is not None for child in node]
        if all(keyed):
            result = {}
            for child in node:
                if child.get("key") in result:
                    raise ValueError("duplicate structured detail key")
                result[child.get("key")] = decode(child, depth + 1)
            return result
        if any(keyed):
            raise ValueError("mixed structured detail keys")
        return [decode(child, depth + 1) for child in node]
    decoded = decode(tables[0])
    if not isinstance(decoded, list) or any(not isinstance(item, dict) for item in decoded):
        raise ValueError("structured detail list expected")
    return decoded


def _assessment(script: ET.Element) -> dict[str, Any]:
    if _scalar(script, "error"):
        raise ValueError("script reported an error")
    state = _scalar(script, "state")
    reason = _scalar(script, "reason")
    if state not in STATES or not reason.strip():
        raise ValueError("missing or unrecognized state/reason")
    if _scalar(script, "exploitability") != "NOT_TESTED":
        raise ValueError("missing or unexpected exploitability field")
    versions = _array(script, "versions")
    fixed_versions = _array(script, "fixed_versions")
    if state != "UNKNOWN" and not _unique(versions):
        raise ValueError("version-based state without any version")
    evidence = script.findall("./table[@key='evidence']/table")
    suspect = _scalar(script, "potentially_vulnerable_evidence").lower() in ("true", "yes", "1")
    for item in evidence:
        suspect = suspect or _scalar(item, "state") == "POTENTIALLY_VULNERABLE"
        fixed = _scalar(item, "fixed_version")
        if fixed:
            fixed_versions.append(fixed)
    if state == "PATCHED_VERSION_ADVERTISED" and suspect:
        raise ValueError("patched state contradicts potentially vulnerable evidence")
    priority = "VERIFY_PRIORITY" if state == "UNKNOWN" and suspect else PRIORITIES[state]
    remediation = _scalar(script, "remediation") or REMEDIATIONS[state]
    if state == "UNKNOWN" and suspect and not _scalar(script, "remediation"):
        remediation = (
            "Verifier en priorite les versions suspectes et les backports de chaque "
            "worker; les preuves sont insuffisantes ou contradictoires."
        )
    observations = _details(script, "observations")
    values = {
        "row_type": "ASSESSMENT", "state": state,
        "verdict": _scalar(script, "verdict") or VERDICTS[state],
        "versions": " | ".join(_unique(versions)),
        "fixed_versions": " | ".join(_unique(fixed_versions)),
        "priority": priority, "remediation": remediation,
        "verification": _scalar(script, "verification") or VERIFY_RUNTIME,
        "http_status": _scalar(script, "http_status"), "reason": reason,
        "reason_code": _scalar(script, "reason_code"),
        "next_action": _scalar(script, "next_action") or _scalar(script, "verification") or VERIFY_RUNTIME,
        "php_detected": _scalar(script, "php_detected", "UNKNOWN"),
        "path": _scalar(script, "path"), "scheme": _scalar(script, "scheme"),
        "http_host": _scalar(script, "http_host"), "tls_sni": _scalar(script, "tls_sni"),
        "requests_made": _scalar(script, "requests_made"),
        "elapsed_ms": _scalar(script, "elapsed_ms"),
        "budget_exhausted": _scalar(script, "budget_exhausted"),
        "traversal_complete": _scalar(script, "traversal_complete"),
        "traversal_reason_code": _scalar(script, "traversal_reason_code"),
        "script_version": _scalar(script, "script_version"),
        "evidence": _details(script, "evidence"),
        "observations": observations,
        "notes": _array(script, "notes"),
        "exploitability": "NOT_TESTED", "potentially_vulnerable_evidence": suspect,
    }
    redirect_destinations = _unassessed_redirect_destinations([values])
    values["redirect_destinations"] = " | ".join(redirect_destinations)
    values["redirect_evaluation_scope"] = (
        "HORS_PERIMETRE_DU_CONTROLE" if redirect_destinations else ""
    )
    vhost = _scalar(script, "vhost")
    if vhost:
        # The explicit Host/SNI name is the application actually assessed. The
        # original target name is still retained in the source Nmap XML.
        values["hostname"] = vhost
    return values


def _coverage(reason: str, reason_code: str = "SERVICE_NOT_ASSESSED") -> dict[str, str]:
    return {
        "row_type": "COVERAGE", "state": "NOT_ASSESSED",
        "verdict": "ABSENCE D'EVALUATION PHP2SHELL", "priority": "REVIEW_COVERAGE",
        "remediation": "Verifier la couverture du scan et qualifier le service si necessaire.",
        "verification": (
            "Cette ligne ne prouve ni presence de PHP, ni vulnerabilite, ni correction. "
            "Un service non web peut normalement ne pas etre evalue par ce NSE."
        ),
        "reason": reason, "reason_code": reason_code, "php_detected": "UNKNOWN",
    }


def parse_report(source: Path) -> list[dict[str, Any]]:
    """Read a completed XML scan and retain assessments plus coverage gaps."""
    try:
        root = ET.parse(source).getroot()
    except (ET.ParseError, OSError) as exc:
        raise ReportError(f"Impossible de lire un XML Nmap valide: {exc}") from exc
    if root.tag != "nmaprun":
        raise ReportError("Racine XML incorrecte: nmaprun attendu.")
    finished = root.findall("./runstats/finished")
    if len(finished) != 1 or finished[0].get("exit") != "success":
        raise ReportError(
            "Scan incomplet ou termine en erreur: runstats/finished exit=success requis. "
            "Aucun rapport de couverture complet ne peut etre produit."
        )
    observed_at = ""
    try:
        observed_at = datetime.fromtimestamp(int(finished[0].get("time", "")), timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        pass
    rows = []
    for host in root.findall("host"):
        host_identity = _host_identity(host)
        before = len(rows)
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if port.get("protocol") != "tcp" or state is None or state.get("state") != "open":
                continue
            scripts = [item for item in port.findall("script") if item.get("id") == SCRIPT_ID]
            if not scripts:
                values = _coverage("Port TCP ouvert sans resultat du script http-php2shell.")
            elif len(scripts) != 1:
                values = _coverage("Plusieurs resultats http-php2shell pour ce port; evaluation ambigue.")
            else:
                try:
                    values = _assessment(scripts[0])
                except ValueError:
                    values = _coverage(
                        "Resultat http-php2shell invalide ou en erreur; evaluation indisponible."
                    )
            row = {**host_identity, **_port_identity(port), **values,
                   "observed_at": observed_at, "source_xml": str(source)}
            if not row.get("scheme") and row["row_type"] == "ASSESSMENT":
                row["scheme"] = "https" if row["service"].startswith("ssl/") or row["service"] == "https" else "http"
            rows.append(row)
        if len(rows) == before:
            host_status = host.find("status")
            status = host_status.get("state", "unknown") if host_status is not None else "unknown"
            reason = (
                "Aucun port TCP ouvert represente; statut Nmap de l'hote: " + status
                + ". Un hote filtre, non joignable ou non teste n'est pas declare corrige."
            )
            rows.append({**host_identity, **_coverage(reason, "NO_OPEN_TCP_PORT"),
                         "observed_at": observed_at, "source_xml": str(source)})
    return rows


def _single_line(value: object) -> str:
    """Keep a compact record on one physical line, including in CSV exports."""
    text = str(value) if value is not None else ""
    return " ".join("".join(" " if unicodedata.category(char).startswith("C") else char
                            for char in text).split())


def _version_values(value: object) -> list[str]:
    values = value if isinstance(value, (list, tuple)) else str(value or "").split("|")
    return _unique([_single_line(item) for item in values])


def _true(value: object) -> bool:
    return str(value).lower() in ("true", "yes", "1")


def _redirect_observation_destination(observation: dict[str, Any]) -> str:
    """Return a redirect target that the NSE deliberately did not follow."""
    explicitly_outside = observation.get("redirect_scope") == "HORS_PERIMETRE_DU_CONTROLE"
    stopped_at_origin = (str(observation.get("redirect_followed", "")).lower() == "false"
                         and observation.get("redirect_reason") == "Redirect leaves the current origin.")
    if (observation.get("reason_code") != "REDIRECT_NOT_ASSESSED"
            and not explicitly_outside and not stopped_at_origin):
        return ""
    return _single_line(observation.get("redirect_to"))


def _observation_matches_path(candidate: dict[str, Any], request_target: str) -> bool:
    observations = candidate.get("observations")
    return isinstance(observations, list) and any(
        isinstance(observation, dict)
        and _single_line(observation.get("path")) == request_target
        for observation in observations
    )


def _redirect_assessment_index(
        rows: list[dict[str, Any]],
) -> dict[tuple[str, int, str, str], set[int]]:
    """Index exact requested URLs once so campaign correlation stays linear."""
    index: dict[tuple[str, int, str, str], set[int]] = {}
    for row in rows:
        if row.get("row_type") != "ASSESSMENT":
            continue
        scheme = _single_line(row.get("scheme")).lower()
        if scheme not in ("http", "https"):
            continue
        try:
            port = int(_single_line(row.get("port")))
        except ValueError:
            continue
        hostname = _single_line(row.get("hostname") or row.get("ip")).lower().rstrip(".")
        observations = row.get("observations")
        if not hostname or not isinstance(observations, list):
            continue
        for observation in observations:
            if not isinstance(observation, dict):
                continue
            request_target = _single_line(observation.get("path"))
            if request_target:
                index.setdefault((scheme, port, hostname, request_target), set()).add(id(row))
    return index


def _redirect_destination_was_assessed(
        row: dict[str, Any], destination_value: object,
        assessment_index: dict[tuple[str, int, str, str], set[int]],
) -> bool:
    """Tell whether the exact redirect URL was requested elsewhere in the campaign."""
    destination = _redirect_destination(destination_value)
    if destination is None:
        return False
    scheme, port, destination_name, request_target = destination
    return any(candidate_id != id(row) for candidate_id in assessment_index.get(
        (scheme, port, destination_name, request_target), ()))


def _redirect_destinations_by_coverage(
        rows: list[dict[str, Any]],
        assessment_index: dict[tuple[str, int, str, str], set[int]] | None = None,
) -> tuple[list[str], list[str]]:
    """Split recorded redirect URLs into unassessed and separately assessed targets."""
    unassessed, assessed = [], []
    for row in rows:
        observations = row.get("observations")
        if not isinstance(observations, list):
            continue
        for observation in observations:
            if not isinstance(observation, dict):
                continue
            destination = _redirect_observation_destination(observation)
            if not destination:
                continue
            bucket = (assessed if assessment_index is not None
                      and _redirect_destination_was_assessed(row, destination, assessment_index)
                      else unassessed)
            bucket.append(destination)
    return _unique(unassessed), _unique(assessed)


def _unassessed_redirect_destinations(
        rows: list[dict[str, Any]],
        assessment_index: dict[tuple[str, int, str, str], set[int]] | None = None,
) -> list[str]:
    """Return redirect targets not evaluated elsewhere in the same campaign."""
    return _redirect_destinations_by_coverage(rows, assessment_index)[0]


def _redirect_row_was_assessed_separately(row: dict[str, Any],
                                            assessment_index: dict[tuple[str, int, str, str], set[int]]
                                            | None) -> bool:
    if assessment_index is None:
        return False
    unassessed, assessed = _redirect_destinations_by_coverage([row], assessment_index)
    return bool(assessed) and not unassessed


# A missing NSE assessment on a positively identified non-web service is
# normal. Unknown, tcpwrapped and all HTTP variants deliberately remain gaps.
NON_WEB_SERVICES = frozenset({
    "ssh", "ftp", "ftp-data", "smtp", "smtps", "submission", "pop3", "pop3s",
    "imap", "imaps", "domain", "mysql", "postgresql", "ms-sql-s", "ms-wbt-server",
    "vnc", "redis", "ldap", "ldaps", "netbios-ssn", "microsoft-ds", "msrpc",
    "rpcbind", "nfs", "rsync", "telnet", "kerberos-sec", "ntp", "snmp", "amqp",
    "amqps", "mqtt", "mqtts", "memcached", "mongodb", "ajp13",
})
HTTP_GAP_CODES = frozenset({
    "NO_HTTP_RESPONSE", "AUTHENTICATION_REQUIRED", "HTTP_ACCESS_DENIED", "RATE_LIMITED",
    "REDIRECT_NOT_ASSESSED", "REDIRECT_LIMIT_REACHED", "REQUEST_BUDGET_EXHAUSTED",
    "CLOCK_CHANGED", "EVIDENCE_LIMIT_REACHED", "INVALID_ARGUMENT",
})
COMPACT_REASONS = {
    "DNS_ERROR": "Résolution DNS impossible",
    "DNS_FAMILY_ERROR": "Résolution DNS incomplète pour une famille IP",
    "NO_DNS_ADDRESS": "Aucune adresse IP résolue",
    "NO_PUBLIC_ADDRESS": "Aucune adresse IP publique globale ; adresses non globales exclues",
    "TARGET_NOT_ATTEMPTED": "Cible non testée",
    "ADDRESS_NOT_ATTEMPTED": "Une adresse IP résolue n'a pas été testée",
    "SCAN_TIMEOUT": "Délai du scan Nmap dépassé",
    "SCAN_FAILED": "Échec du scan Nmap",
    "SCAN_INCOMPLETE": "Scan Nmap incomplet",
    "SCAN_INTERRUPTED": "Scan Nmap interrompu",
    "SCAN_SKIPPED": "Scan Nmap non exécuté",
    "SCAN_NOT_ATTEMPTED": "Scan Nmap non exécuté",
    "INVALID_SCAN_XML": "Résultat Nmap incomplet ou invalide",
    "TARGET_MISSING_FROM_XML": "Cible absente du résultat Nmap",
    "NO_OPEN_TCP_PORT": "Aucun port TCP ouvert observé ; PHP non vérifié",
    "SERVICE_NOT_ASSESSED": "Service ouvert sans évaluation PHP exploitable",
    "NO_HTTP_RESPONSE": "Aucune réponse HTTP exploitable",
    "AUTHENTICATION_REQUIRED": "HTTP 401 : authentification requise",
    "HTTP_ACCESS_DENIED": "HTTP 403 : accès refusé",
    "RATE_LIMITED": "HTTP 429 : requêtes limitées",
    "REDIRECT_NOT_ASSESSED": "Destination de redirection non évaluée",
    "REDIRECT_LIMIT_REACHED": "Parcours des redirections incomplet",
    "REQUEST_BUDGET_EXHAUSTED": "Budget HTTP épuisé avant la fin des contrôles",
    "CLOCK_CHANGED": "Parcours HTTP interrompu par un changement d'horloge",
    "EVIDENCE_LIMIT_REACHED": "Observations trop nombreuses pour conclure",
    "INVALID_ARGUMENT": "Paramètres du test HTTP invalides",
    "CONFLICTING_VERSIONS": "Versions PHP contradictoires sur le même service",
    "UNRECOGNIZED_BUILD": "Build PHP non reconnu ; correctif à vérifier côté serveur",
    "PHP_VERSION_HIDDEN": "PHP détecté, mais sa version n'est pas annoncée",
    "PHP_NOT_IDENTIFIED": "PHP non identifié ; absence de vulnérabilité non établie",
}


def _non_web_coverage(row: dict[str, Any]) -> bool:
    service = str(row.get("service", "")).lower().removeprefix("ssl/")
    return (row.get("row_type") == "COVERAGE"
            and row.get("reason_code") == "SERVICE_NOT_ASSESSED"
            and row.get("service_method") == "probed"
            and row.get("inventory_patch_status") not in ("PATCH_MISSING_CONFIRMED", "CONFLICT")
            and service in NON_WEB_SERVICES)


def _http_gap(row: dict[str, Any]) -> bool:
    return (_true(row.get("budget_exhausted"))
            or str(row.get("traversal_complete", "")).lower() in ("false", "no", "0")
            or row.get("reason_code") in HTTP_GAP_CODES
            or row.get("traversal_reason_code") in HTTP_GAP_CODES)


def _suspect(row: dict[str, Any]) -> bool:
    evidence = row.get("evidence")
    return (row.get("state") == "POTENTIALLY_VULNERABLE"
            or _true(row.get("potentially_vulnerable_evidence"))
            or any(isinstance(item, dict) and item.get("state") == "POTENTIALLY_VULNERABLE"
                   for item in (evidence if isinstance(evidence, list) else [])))


def _compact_verdict(row: dict[str, Any]) -> str:
    proof = row.get("inventory_patch_status")
    if proof == "PATCH_MISSING_CONFIRMED":
        return "OUI"
    if row.get("row_type") != "ASSESSMENT" or proof == "CONFLICT" or _http_gap(row):
        return "INDETERMINE"
    if proof == "PATCH_CONFIRMED":
        return "NON"
    if _version_values(row.get("versions")):
        if row.get("state") == "POTENTIALLY_VULNERABLE":
            return "OUI"
        if row.get("state") == "PATCHED_VERSION_ADVERTISED" and not _suspect(row):
            return "NON"
    return "INDETERMINE"


def _redirect_destination(value: object) -> tuple[str, int, str, str] | None:
    """Return a comparison-safe destination without weakening URL identity."""
    try:
        destination = urlsplit(_single_line(value))
        scheme = destination.scheme.lower()
        port = destination.port or (443 if scheme == "https" else 80 if scheme == "http" else 0)
    except ValueError:
        return None
    if (scheme not in ("http", "https") or destination.username is not None
            or destination.password is not None or not destination.hostname or destination.fragment):
        return None
    path = destination.path or "/"
    query = destination.query
    # Query values are deliberately redacted by the NSE. Two redacted URLs
    # therefore never prove that the same resource was assessed.
    if "[redacted]" in query:
        return None
    request_target = path + (("?" + query) if query else "")
    return scheme, port, destination.hostname.lower().rstrip("."), request_target


def _observation_covers_path(candidate: dict[str, Any], request_target: str) -> bool:
    if _compact_verdict(candidate) == "INDETERMINE":
        return False
    if not _observation_matches_path(candidate, request_target):
        return False
    observations = candidate.get("observations")
    proof = candidate.get("inventory_patch_status")
    for observation in observations:
        if not isinstance(observation, dict) or _single_line(observation.get("path")) != request_target:
            continue
        if proof in ("PATCH_CONFIRMED", "PATCH_MISSING_CONFIRMED"):
            return True
        if (observation.get("state") in ("POTENTIALLY_VULNERABLE", "PATCHED_VERSION_ADVERTISED")
                and _version_values(observation.get("versions"))):
            return True
    return False


def _legacy_redirect_is_covered(row: dict[str, Any], rows: list[dict[str, Any]]) -> bool:
    """Reproduce the service-level v0.4.4-v0.4.6 compatibility rule."""
    if (row.get("row_type") != "ASSESSMENT"
            or row.get("reason_code") != "REDIRECT_NOT_ASSESSED"
            or _true(row.get("budget_exhausted"))
            or str(row.get("traversal_complete", "")).lower() in ("false", "no", "0")):
        return False
    observations = row.get("observations")
    if not isinstance(observations, list) or not observations:
        return False
    target = _single_line(row.get("hostname") or row.get("ip")).lower().rstrip(".")
    source_ip = _single_line(row.get("ip"))
    for observation in observations:
        if not isinstance(observation, dict) or observation.get("reason_code") != "REDIRECT_NOT_ASSESSED":
            return False
        try:
            destination = urlsplit(_single_line(observation.get("redirect_to")))
            scheme = destination.scheme.lower()
            port = destination.port or (443 if scheme == "https" else 80 if scheme == "http" else 0)
        except ValueError:
            return False
        if (scheme not in ("http", "https") or destination.username is not None
                or destination.password is not None or not destination.hostname
                or destination.hostname.lower().rstrip(".") != target):
            return False
        if not any(candidate is not row
                   and candidate.get("row_type") == "ASSESSMENT"
                   and _single_line(candidate.get("ip")) == source_ip
                   and _single_line(candidate.get("hostname") or candidate.get("ip")).lower().rstrip(".") == target
                   and _single_line(candidate.get("scheme")).lower() == scheme
                   and _single_line(candidate.get("port")) == str(port)
                   and _compact_verdict(candidate) != "INDETERMINE"
                   for candidate in rows):
            return False
    return True


def _redirect_is_covered(row: dict[str, Any], rows: list[dict[str, Any]]) -> bool:
    """Return true when every external-origin redirect was assessed separately.

    The NSE deliberately does not cross an origin boundary. A campaign can
    nevertheless cover a routine HTTP-to-HTTPS redirect through its separate
    scan of the destination service. Require the same target name, IP and exact
    request target so a redirect never hides an untested path or backend.
    """
    if (row.get("row_type") != "ASSESSMENT"
            or row.get("reason_code") != "REDIRECT_NOT_ASSESSED"
            or _true(row.get("budget_exhausted"))
            or str(row.get("traversal_complete", "")).lower() in ("false", "no", "0")):
        return False
    observations = row.get("observations")
    if not isinstance(observations, list) or not observations:
        return False
    target = _single_line(row.get("hostname") or row.get("ip")).lower().rstrip(".")
    source_ip = _single_line(row.get("ip"))
    for observation in observations:
        if not isinstance(observation, dict) or observation.get("reason_code") != "REDIRECT_NOT_ASSESSED":
            return False
        destination = _redirect_destination(observation.get("redirect_to"))
        if destination is None:
            return False
        scheme, port, destination_name, request_target = destination
        if destination_name != target:
            return False
        if not any(candidate is not row
                   and candidate.get("row_type") == "ASSESSMENT"
                   and _single_line(candidate.get("ip")) == source_ip
                   and _single_line(candidate.get("hostname") or candidate.get("ip")).lower().rstrip(".") == target
                   and _single_line(candidate.get("scheme")).lower() == scheme
                   and _single_line(candidate.get("port")) == str(port)
                   and _observation_covers_path(candidate, request_target)
                   for candidate in rows):
            return False
    return True


def _covered_redirect_is_navigation_only(row: dict[str, Any], rows: list[dict[str, Any]]) -> bool:
    """Suppress only the resolved navigation gap, never independent evidence."""
    if not _redirect_is_covered(row, rows):
        return False
    proof = row.get("inventory_patch_status")
    return proof in (None, "", "NOT_PROVIDED") and not _suspect(row)


def _short(value: object, limit: int = 150) -> str:
    text = _single_line(value)
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


def _endpoint_hint(row: dict[str, Any], rows: list[dict[str, Any]]) -> str:
    port, ip = _single_line(row.get("port")), _single_line(row.get("ip"))
    ips = {_single_line(item.get("ip")) for item in rows if item.get("ip")}
    if ip and (len(ips) > 1 or row.get("row_type") != "ASSESSMENT"):
        endpoint = ("[" + ip + "]") if ":" in ip else ip
        return " (" + _short(endpoint + (":" + port if port else ""), 75) + ")"
    return " (port " + _short(port, 12) + ")" if port else ""


def _unknown_reason(row: dict[str, Any],
                    assessment_index: dict[tuple[str, int, str, str], set[int]] | None = None) -> str:
    if row.get("inventory_patch_status") == "CONFLICT":
        return "Preuves serveur contradictoires ; vérifier le runtime"
    code = row.get("traversal_reason_code") or row.get("reason_code")
    if code == "REDIRECT_NOT_ASSESSED" and _redirect_row_was_assessed_separately(row, assessment_index):
        return "Destination de redirection évaluée séparément dans la campagne"
    if code in COMPACT_REASONS:
        return COMPACT_REASONS[code]
    if _true(row.get("budget_exhausted")) or str(row.get("traversal_complete", "")).lower() in ("false", "no", "0"):
        return "Parcours HTTP incomplet"
    if row.get("reason"):
        return _short(row["reason"])
    return "Version ou correctifs PHP impossibles à établir"


def _legacy_compact_explanation(rows: list[dict[str, Any]], verdicts: list[str], verdict: str,
                                assessment_index: dict[tuple[str, int, str, str], set[int]]
                                | None = None) -> str:
    if not rows:
        return "Aucun service HTTP évalué ; PHP et ses correctifs restent à vérifier."
    if verdict == "OUI":
        positive = [row for row, value in zip(rows, verdicts) if value == "OUI"]
        row = next((item for item in positive if item.get("inventory_patch_status") == "PATCH_MISSING_CONFIRMED"), positive[0])
        if row.get("inventory_patch_status") == "PATCH_MISSING_CONFIRMED":
            reason = "Correctif manquant attesté côté serveur" + _endpoint_hint(row, rows)
            reason += "; appliquer les correctifs PHP et redémarrer les workers."
        else:
            reason = "Version annoncée concernée" + _endpoint_hint(row, rows)
            fixed = _version_values(row.get("fixed_versions"))
            action = ("mettre à jour PHP vers " + _short(" / ".join(fixed), 60)
                      if fixed else "mettre à jour PHP")
            reason += "; " + action + " ou vérifier le correctif fournisseur."
        gaps = sum(value == "INDETERMINE" or _http_gap(item)
                   or item.get("row_type") != "ASSESSMENT" for item, value in zip(rows, verdicts))
        if gaps:
            reason += f" Contrôles incomplets : {gaps}."
        return reason
    if verdict == "NON":
        attested = [row for row in rows if row.get("inventory_patch_status") == "PATCH_CONFIRMED"]
        if len(attested) == len(rows):
            reason = "Correctifs attestés côté serveur sur les services évalués"
            if any(_suspect(row) for row in rows):
                reason += ", malgré la version annoncée"
            return reason + "."
        if attested:
            return "Versions corrigées annoncées ou correctifs attestés côté serveur sur les services évalués."
        return "Versions annoncées corrigées sur les services évalués ; runtime à confirmer côté serveur."
    unknown = [row for row, value in zip(rows, verdicts) if value == "INDETERMINE"]
    # Surface a concrete coverage failure before a generic hidden-version
    # observation, without expanding one line into a catalogue of endpoints.
    row = next((item for item in unknown if item.get("row_type") != "ASSESSMENT" or _http_gap(item)), unknown[0])
    reason = _unknown_reason(row, assessment_index) + _endpoint_hint(row, rows)
    if any(_suspect(item) for item in unknown):
        reason += "; version concernée observée, correctif à vérifier"
    if any(item.get("inventory_patch_status") == "PATCH_CONFIRMED" for item in rows):
        reason += "; correctifs attestés, couverture incomplète"
    elif any(item.get("inventory_patch_status") in ("STALE", "UNVERIFIED", "PARTIAL") for item in unknown):
        reason += "; preuve serveur inexploitable ou partielle"
    if len(unknown) > 1:
        reason += f"; {len(unknown)} contrôles indéterminés"
    return reason + "."


def _port_summary(rows: list[dict[str, Any]]) -> str:
    """Describe actual NSE results separately from open, unassessed ports.

    A requested scan port is not evidence of an HTTP assessment. Likewise,
    repeated addresses on the same port do not create additional port numbers.
    """
    assessed, unassessed = set(), set()
    for row in rows:
        value = str(row.get("port", ""))
        if (row.get("protocol") != "tcp" or not value.isascii()
                or not value.isdecimal() or len(value) > 5 or not 1 <= int(value) <= 65535):
            continue
        if row.get("row_type") == "ASSESSMENT":
            assessed.add(int(value))
        elif row.get("row_type") == "COVERAGE" and row.get("reason_code") == "SERVICE_NOT_ASSESSED":
            unassessed.add(int(value))

    def listing(ports):
        ordered = sorted(ports)
        text = ",".join(str(port) for port in ordered[:MAX_SUMMARY_PORTS])
        if len(ordered) > MAX_SUMMARY_PORTS:
            text += f" (+{len(ordered) - MAX_SUMMARY_PORTS} autres)"
        return text

    parts = []
    if assessed:
        parts.append("Ports évalués : " + listing(assessed) + ".")
    if unassessed:
        parts.append("Ports ouverts sans évaluation PHP : " + listing(unassessed) + ".")
    return " ".join(parts)


def _destination_listing(destinations: list[str]) -> str:
    displayed = [_short(destination, 100) for destination in destinations[:2]]
    listing = ", ".join(displayed)
    if len(destinations) > len(displayed):
        listing += f" (+{len(destinations) - len(displayed)} autre"
        listing += "s" if len(destinations) - len(displayed) > 1 else ""
        listing += ")"
    return listing


def _cross_host_first(destinations: list[str], rows: list[dict[str, Any]]) -> list[str]:
    """Keep alias-changing redirects visible before routine HTTP-to-HTTPS hops."""
    source_names = {
        _single_line(row.get("hostname") or row.get("ip")).lower().rstrip(".")
        for row in rows
    }

    def same_host(destination_value: str) -> bool:
        destination = _redirect_destination(destination_value)
        return destination is not None and destination[2] in source_names

    return sorted(destinations, key=same_host)


def _redirect_summary(rows: list[dict[str, Any]],
                      assessment_index: dict[tuple[str, int, str, str], set[int]]
                      | None = None) -> str:
    unassessed, assessed = _redirect_destinations_by_coverage(rows, assessment_index)
    # v0.5.0 companion validation preserves its original encounter order.
    if assessment_index is not None:
        unassessed = _cross_host_first(unassessed, rows)
        assessed = _cross_host_first(assessed, rows)
    parts = []
    if unassessed:
        label = "destination non évaluée" if len(unassessed) == 1 else "destinations non évaluées"
        parts.append(f"HORS PÉRIMÈTRE DU CONTRÔLE — {label} : {_destination_listing(unassessed)}.")
    if assessed:
        label = "destination évaluée séparément" if len(assessed) == 1 else "destinations évaluées séparément"
        parts.append(f"Dans la campagne — {label} : {_destination_listing(assessed)}.")
    return _short(" ".join(parts), 245)


def _compact_explanation(rows: list[dict[str, Any]], verdicts: list[str], verdict: str,
                         *, port_rows: list[dict[str, Any]] | None = None,
                         include_redirect_destinations: bool = True,
                         assessment_index: dict[tuple[str, int, str, str], set[int]]
                         | None = None) -> str:
    reason = _legacy_compact_explanation(rows, verdicts, verdict, assessment_index)
    ports = _port_summary(port_rows if port_rows is not None else rows)
    redirect = _redirect_summary(rows, assessment_index) if include_redirect_destinations else ""
    prefix = " ".join(part for part in (ports, redirect) if part)
    if not prefix:
        return _short(reason, MAX_COMPACT_EXPLANATION)
    # Keep coverage and out-of-scope destinations visible even when a supplied
    # reason is verbose.
    remaining = MAX_COMPACT_EXPLANATION - len(prefix) - 1
    return prefix if remaining <= 0 else prefix + " " + _short(reason, remaining)


def compact_rows(rows: list[dict[str, Any]], *, legacy_explanation: bool = False,
                 include_redirect_destinations: bool = True,
                 redirect_coverage: str = "campaign") -> list[dict[str, str]]:
    """Aggregate IPs and ports into four fields per hostname (or XML IP).

    OUI includes an affected advertised version and says so explicitly. NON
    requires every assessed web service to be corrected or attested, without
    silently discarding DNS, Nmap or HTTP coverage failures. Discovery status
    belongs to campaign details, not to an extra target or a PHP verdict.
    The legacy rendering is only needed to validate compact reports written
    before port summaries were added; all four fields are still compared.
    """
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ReportError("Lignes détaillées invalides : une liste d'objets est requise.")
    if redirect_coverage not in ("campaign", "current", "legacy", "none"):
        raise ReportError("Mode de couverture des redirections invalide.")
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if row.get("protocol") == "discovery":
            continue
        target = _single_line(row.get("hostname") or row.get("ip"))
        if not target:
            raise ReportError("Ligne sans cible : hostname ou ip requis pour le rapport compact.")
        groups.setdefault(target, []).append(row)
    assessment_index = _redirect_assessment_index(rows) if redirect_coverage == "campaign" else None
    output = []
    for target, group in groups.items():
        versions = _unique([version for row in group for version in _version_values(row.get("versions"))])
        relevant = [row for row in group if not _non_web_coverage(row)]
        if legacy_explanation or redirect_coverage == "none":
            conclusive = relevant
        elif redirect_coverage == "legacy":
            conclusive = [row for row in relevant if not _legacy_redirect_is_covered(row, relevant)]
        else:
            conclusive = [row for row in relevant if not _covered_redirect_is_navigation_only(row, relevant)]
        verdicts = [_compact_verdict(row) for row in conclusive]
        verdict = ("OUI" if "OUI" in verdicts else
                   "NON" if verdicts and all(value == "NON" for value in verdicts) else "INDETERMINE")
        if legacy_explanation:
            explanation = _legacy_compact_explanation(conclusive, verdicts, verdict)
        else:
            explanation = _compact_explanation(
                conclusive, verdicts, verdict, port_rows=relevant,
                include_redirect_destinations=include_redirect_destinations,
                assessment_index=assessment_index,
            )
        output.append({"cible": target, "php": " | ".join(versions) or "INCONNUE", "vulnerable": verdict,
                       "explication": _short(explanation, MAX_COMPACT_EXPLANATION)})
    return output


def _report_tree_roots(report: dict[str, Any]) -> list[str]:
    """Return explicit campaign roots without guessing public suffixes."""
    values = []
    discovery = report.get("discovery")
    if isinstance(discovery, dict) and isinstance(discovery.get("roots"), list):
        values.extend(discovery["roots"])
    campaign = report.get("campaign")
    scope = campaign.get("scope") if isinstance(campaign, dict) else None
    if isinstance(scope, dict) and isinstance(scope.get("domains"), list):
        values.extend(scope["domains"])
    return _unique([
        _single_line(value).lower().rstrip(".") for value in values
        if _single_line(value)
    ])


def _tree_result_label(label: str, row: dict[str, str] | None, count: int,
                       *, root: bool = False) -> str:
    if row is None:
        result = f"{label} [regroupement]"
    else:
        result = f"{label} [PHP {row['php']} | {row['vulnerable']}]"
    if root:
        result += f" — {count} cible" + ("s" if count != 1 else "")
    return result


def _tree_result_count(node: dict[str, Any]) -> int:
    return (1 if node.get("row") is not None else 0) + sum(
        _tree_result_count(child) for child in node["children"].values())


def _render_tree_children(node: dict[str, Any], prefix: str, lines: list[str]) -> None:
    children = sorted(node["children"].items(), key=lambda item: item[0])
    for index, (label, child) in enumerate(children):
        last = index == len(children) - 1
        lines.append(prefix + ("└── " if last else "├── ")
                     + _tree_result_label(label, child.get("row"), _tree_result_count(child)))
        _render_tree_children(child, prefix + ("    " if last else "│   "), lines)


def _report_tree_text(report: dict[str, Any], compact: list[dict[str, str]]) -> str:
    """Render compact results as a DNS hierarchy beneath explicit scope roots."""
    roots = _report_tree_roots(report)
    forest: dict[str, dict[str, Any]] = {
        root: {"row": None, "children": {}} for root in roots
    }
    for row in compact:
        target = row["cible"].lower().rstrip(".")
        matching = [root for root in roots if target == root or target.endswith("." + root)]
        root = max(matching, key=len) if matching else target
        node = forest.setdefault(root, {"row": None, "children": {}})
        if target == root:
            node["row"] = row
            continue
        relative = target[:-(len(root) + 1)]
        for label in reversed(relative.split(".")):
            node = node["children"].setdefault(label, {"row": None, "children": {}})
        node["row"] = row

    campaign = report.get("campaign")
    campaign_id = _single_line(campaign.get("campaign_id")) if isinstance(campaign, dict) else ""
    title = "Arborescence des résultats"
    if campaign_id:
        title += " — campagne " + campaign_id
    lines = [title, "Légende : [PHP version | OUI/NON/INDETERMINE] ; [regroupement] = branche DNS non évaluée.", ""]
    ordered_roots = [root for root in roots if root in forest]
    ordered_roots.extend(sorted(root for root in forest if root not in roots))
    for index, root in enumerate(ordered_roots):
        node = forest[root]
        lines.append(_tree_result_label(root, node.get("row"), _tree_result_count(node), root=True))
        _render_tree_children(node, "", lines)
        if index != len(ordered_roots) - 1:
            lines.append("")
    return "\n".join(lines) + "\n"


def _historical_compact_rows(details: dict[str, Any]) -> list[dict[str, str]] | None:
    """Render the exact compact contract associated with a stored tool version."""
    match = re.fullmatch(r"0\.(\d+)\.(\d+)", str(details.get("tool_version", "")))
    if not match:
        return None
    minor, patch = int(match.group(1)), int(match.group(2))
    if minor == 5 and patch == 0:
        return compact_rows(details["rows"], redirect_coverage="current")
    if minor != 4:
        return None
    rows = details["rows"]
    if patch <= 2:
        return compact_rows(rows, legacy_explanation=True, redirect_coverage="none")
    if patch == 3:
        return compact_rows(rows, include_redirect_destinations=False, redirect_coverage="none")
    if patch in (4, 5):
        return compact_rows(rows, include_redirect_destinations=False, redirect_coverage="legacy")
    if patch == 6:
        return compact_rows(rows, redirect_coverage="legacy")
    return None


def safe_cell(value: object) -> str:
    """Prevent CSV formula execution, including whitespace/control prefixes."""
    text = str(value) if value is not None else ""
    index = 0
    while index < len(text) and (text[index].isspace() or unicodedata.category(text[index]).startswith("C")):
        index += 1
    leading_control = bool(text) and unicodedata.category(text[0]).startswith("C")
    dangerous = index < len(text) and text[index] in "=+-@"
    return "'" + text if leading_control or dangerous else text


def _protect_source(destination: Path, source: Path) -> None:
    if destination.resolve() == source.resolve() or (
        destination.exists() and source.exists() and os.path.samefile(destination, source)
    ):
        raise ReportError("Le fichier de sortie doit etre different du fichier source.")


def _validate_compact(rows: object) -> list[dict[str, str]]:
    if not isinstance(rows, list):
        raise ReportError("Rapport compact invalide : une liste de cibles est requise.")
    seen = set()
    for row in rows:
        if (not isinstance(row, dict) or set(row) != set(COMPACT_FIELDS)
                or any(not isinstance(value, str) or not value or value != _single_line(value)
                       for value in row.values())
                or row.get("vulnerable") not in COMPACT_VERDICTS):
            raise ReportError("Rapport compact invalide : cible, php, vulnerable et explication sont requis, sur une ligne.")
        if row["cible"] in seen:
            raise ReportError("Rapport compact invalide : plusieurs lignes pour la même cible.")
        seen.add(row["cible"])
    return rows


def _validate_detailed(value: object) -> dict[str, Any]:
    if (not isinstance(value, dict) or str(value.get("schema_version")) != "1"
            or not isinstance(value.get("rows"), list)
            or any(not isinstance(row, dict) for row in value["rows"])):
        raise ReportError("Rapport détaillé invalide : schema_version='1' et rows=[objets] requis.")
    string_fields = ("hostname", "ip", "protocol", "service", "service_method", "row_type", "state", "versions",
                     "fixed_versions", "reason", "reason_code", "traversal_reason_code", "inventory_patch_status",
                     "redirect_destinations", "redirect_evaluation_scope")
    for row in value["rows"]:
        if set(COMPACT_FIELDS).issubset(row):
            raise ReportError("Rapport détaillé invalide : une ligne compacte ne contient pas les observations par service.")
        if any(key in row and not isinstance(row[key], str) for key in string_fields):
            raise ReportError("Ligne du rapport détaillé invalide : champs de résultat textuels requis.")
        if row.get("protocol") != "discovery" and not _single_line(row.get("hostname") or row.get("ip")):
            raise ReportError("Ligne du rapport détaillé sans cible : hostname ou ip requis.")
        if "port" in row and (isinstance(row["port"], bool) or not isinstance(row["port"], (str, int))):
            raise ReportError("Port invalide dans le rapport détaillé.")
    return value


def _read_json_report(path: Path) -> tuple[object, str]:
    try:
        def invalid_constant(value):
            raise ValueError("constante JSON invalide : " + value)
        digest = hashlib.sha256()
        with Path(path).open("rb") as binary:
            for chunk in iter(lambda: binary.read(1024 * 1024), b""):
                digest.update(chunk)
        with Path(path).open("r", encoding="utf-8-sig") as stream:
            value = json.load(stream, parse_constant=invalid_constant)
        return value, digest.hexdigest()
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        raise ReportError(f"Rapport JSON illisible ({path}): {exc}") from exc


def load_campaign_report(path: Path) -> dict[str, Any]:
    """Load legacy details or a compact report with its matching fixed companion.

    Comparisons and rechecks need service identities and evidence that the four
    display fields cannot recover. The companion must match the main report;
    no path from untrusted JSON is followed and no data is silently invented.
    """
    path = Path(path)
    value, _ = _read_json_report(path)
    if isinstance(value, dict):
        return _validate_detailed(value)
    compact = _validate_compact(value)
    companion = path.parent / "raw" / "report-details.json"
    try:
        details = _validate_detailed(_read_json_report(companion)[0])
    except ReportError as exc:
        raise ReportError(f"Rapport compact : compagnon détaillé requis et valide ({companion}): {exc}") from exc
    historical = _historical_compact_rows(details)
    expected = historical if historical is not None else compact_rows(details["rows"])
    if expected != compact:
        raise ReportError("Rapport compact incohérent avec raw/report-details.json ; conserver les fichiers de la même campagne.")
    return details


def write_report(rows: list[dict[str, Any]], destination: Path, source: Path, *, detailed: bool = False) -> None:
    """Atomically export CSV, protecting the source and all its aliases."""
    destination, source = Path(destination), Path(source)
    _protect_source(destination, source)
    if detailed:
        if rows and "cible" in rows[0]:
            raise ReportError("Les observations détaillées sont requises pour exporter le CSV technique.")
        _write_csv(rows, destination, FIELDS)
    else:
        compact = _validate_compact(rows) if rows and "cible" in rows[0] else compact_rows(rows)
        _write_csv(compact, destination, COMPACT_FIELDS)


CHANGE_FIELDS = ("change", "hostname", "ip", "port", "protocol", "path", "previous_state",
                 "current_state", "previous_versions", "current_versions", "previous_inventory_patch_status",
                 "current_inventory_patch_status", "reason")


def _atomic_text(destination: Path, write) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="", prefix=".php2shell-",
                                         suffix=".tmp", dir=destination.parent, delete=False) as stream:
            temporary = Path(stream.name)
            write(stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _write_csv(rows: list[dict[str, Any]], destination: Path, fields: tuple[str, ...]) -> None:
    def write(stream):
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: safe_cell(row.get(key, "")) for key in fields})
    _atomic_text(destination, write)


def _report_key(row: dict[str, Any]) -> tuple[str, ...]:
    # A campaign evaluates a service with a set of paths. A changed observed
    # path is itself compared; it must not make the old service disappear.
    return tuple(str(row.get(key, "")) for key in ("hostname", "ip", "port", "protocol"))


def compare_reports(current: dict[str, Any], previous: dict[str, Any]) -> list[dict[str, Any]]:
    """Compare observed services; missing observations never imply correction."""
    if not isinstance(previous, dict) or str(previous.get("schema_version")) != "1" \
            or not isinstance(previous.get("rows"), list):
        raise ReportError("Rapport precedent invalide: schema_version='1' et rows=[...] requis.")
    if any(not isinstance(row, dict) for row in previous["rows"]):
        raise ReportError("Lignes du rapport precedent invalides.")
    def index(rows):
        output = {}
        for row in rows:
            if not row.get("port"):
                continue
            key = _report_key(row)
            if key in output:
                raise ReportError("Plusieurs lignes pour le meme service dans une comparaison.")
            output[key] = row
        return output
    old, new = index(previous["rows"]), index(current["rows"])
    compared = ("row_type", "state", "versions", "reason_code", "path", "scheme", "php_detected",
                "inventory_patch_status", "service", "service_method")
    changes = []
    for key in sorted(old.keys() | new.keys()):
        before, after = old.get(key), new.get(key)
        identity = after or before
        change = {field: identity.get(field, "") for field in ("hostname", "ip", "port", "protocol", "path")}
        if before is None:
            change.update(change="NEW", reason="Service nouvellement represente dans cette campagne.")
        elif after is None:
            change.update(change="NO_LONGER_OBSERVED",
                          reason="Service absent des observations courantes; disparition ou couverture differente, correction non etablie.")
        elif all(before.get(field, "") == after.get(field, "") for field in compared):
            change.update(change="UNCHANGED", reason="Etat et preuves comparees inchanges.")
        else:
            change.update(change="CHANGED", reason="Etat, version, contexte de mesure ou preuve serveur modifies.")
        change.update(previous_state=(before or {}).get("state", ""), current_state=(after or {}).get("state", ""),
                      previous_versions=(before or {}).get("versions", ""), current_versions=(after or {}).get("versions", ""),
                      previous_inventory_patch_status=(before or {}).get("inventory_patch_status", ""),
                      current_inventory_patch_status=(after or {}).get("inventory_patch_status", ""))
        changes.append(change)
    return changes


def _safe_xml_path(base_dir: Path, value: object) -> Path:
    if not isinstance(value, str) or not value:
        raise ReportError("Chemin XML absent du manifeste.")
    candidate = (base_dir / value).resolve()
    if not candidate.is_relative_to(base_dir.resolve()):
        raise ReportError("Le XML doit rester dans le repertoire de campagne.")
    return candidate


def _campaign_coverage(hostname: str, endpoint: dict[str, Any] | None, reason: str,
                       code: str, campaign_id: str, observed_at: str) -> dict[str, Any]:
    endpoint = endpoint or {}
    return {"hostname": hostname, "ip": endpoint.get("ip", ""), **_coverage(reason, code),
            "campaign_id": campaign_id, "observed_at": observed_at,
            "source_xml": endpoint.get("xml", ""), "scan_status": endpoint.get("status", ""),
            "address_family": endpoint.get("family", ""), "scan_ports": endpoint.get("ports", "")}


def _discovery_report(manifest: dict, campaign_id: str, observed_at: str
                      ) -> tuple[dict | None, list[dict], dict]:
    """Reconcile passive-source processing without claiming exhaustive discovery."""
    discovery = manifest.get("discovery")
    if discovery is None:
        return None, [], {}
    if not isinstance(discovery, dict) or not isinstance(discovery.get("enabled"), bool):
        raise ReportError("Decouverte du manifeste invalide.")
    if not discovery["enabled"]:
        return dict(discovery), [], {}
    roots, queries = discovery.get("roots"), discovery.get("queries")
    if not isinstance(roots, list) or not roots or any(not isinstance(root, str) or not root for root in roots) \
            or len(set(roots)) != len(roots) or not isinstance(queries, list):
        raise ReportError("Racines et requetes de decouverte invalides.")
    skipped_roots = discovery.get("skipped_roots", [])
    if not isinstance(skipped_roots, list) or any(
            not isinstance(item, dict) or item.get("root") not in roots
            or item.get("reason") != "SUBDOMAINS_EXCLUDED_BY_OPERATOR" for item in skipped_roots):
        raise ReportError("Racines exclues de la decouverte invalides.")
    excluded_roots = {item["root"] for item in skipped_roots}
    if len(excluded_roots) != len(skipped_roots):
        raise ReportError("Racine exclue de la decouverte dupliquee.")
    source = str(discovery.get("source") or "source passive")
    rows, seen, completed = [], set(), 0

    def coverage(root: str, query: dict, code: str) -> dict:
        provider = str(query.get("source") or source)
        if not code.startswith("DISCOVERY_"):
            code = "DISCOVERY_" + code
        detail = str(query.get("error") or query.get("reason") or code)
        reason = f"Decouverte incomplete pour {root or 'le perimetre'} via {provider}: {detail}"
        action = "Relancer la decouverte ou completer les noms avec un export DNS/applicatif dans le perimetre autorise."
        row = _campaign_coverage(root, None, reason, code, campaign_id,
                                 str(query.get("finished_at") or discovery.get("finished_at") or observed_at))
        row.update(protocol="discovery", service=provider, port="", scan_status=str(query.get("status") or "PARTIAL"),
                   verdict="DECOUVERTE DES SOUS-DOMAINES INCOMPLETE", remediation=action, next_action=action,
                   verification="Cette ligne de decouverte ne prouve ni presence de PHP, ni vulnerabilite, ni correction.",
                   target_sources=[f"{provider}:{root}"], exploitability="NOT_TESTED")
        return row

    for query in queries:
        if not isinstance(query, dict) or not isinstance(query.get("root"), str) or query["root"] not in roots \
                or query["root"] in excluded_roots:
            raise ReportError("Requete de decouverte invalide ou hors des racines declarees.")
        identity = (query["root"], str(query.get("source") or source))
        if identity in seen:
            raise ReportError("Requete de decouverte dupliquee dans le manifeste.")
        seen.add(identity)
        if query.get("status") == "COMPLETED" and query.get("processing_complete") is True:
            completed += 1
        else:
            code = str(query.get("reason_code") or
                       (query.get("status") if query.get("status") != "COMPLETED" else "INCOMPLETE") or "INCOMPLETE")
            rows.append(coverage(query["root"], query, code))
    covered_roots = {root for root, _ in seen}
    unattempted = 0
    for root in roots:
        if root not in covered_roots and root not in excluded_roots:
            unattempted += 1
            rows.append(coverage(root, {"status": "SKIPPED"}, "NOT_ATTEMPTED"))
    complete = (discovery.get("status") == "COMPLETED" and discovery.get("processing_complete") is True
                and not rows)
    if not complete and not rows:
        rows.append(coverage("", discovery, str(discovery.get("reason_code") or "INCOMPLETE")))
    normalized = dict(discovery)
    normalized.update(processing_complete=complete, exhaustive=False)
    if not complete and discovery.get("status") == "COMPLETED":
        normalized["status"] = "PARTIAL"
    summary = {
        "discovery_status": normalized.get("status", "PARTIAL"),
        "discovery_processing_complete": complete, "discovery_exhaustive": False,
        "discovery_roots_total": len(roots), "discovery_queries_total": len(queries),
        "discovery_roots_excluded": len(excluded_roots), "discovery_queries_completed": completed,
        "discovery_queries_incomplete": len(queries) - completed,
        "discovery_queries_unattempted": unattempted, "discovery_coverage_rows": len(rows),
    }
    for field in ("candidates_count", "retained_count", "resolved_count", "unresolved_count"):
        value = discovery.get(field)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
            raise ReportError("Compteur de decouverte invalide: " + field)
        summary["discovery_" + field] = value
    return normalized, rows, summary


def build_campaign_report(manifest: dict, base_dir: Path, inventory: Path | None = None,
                          previous: Path | None = None, max_inventory_age_hours: float = 24) -> dict:
    """Reconcile every requested name with endpoint results and local evidence.

    Only successful, completed XML is admitted as assessment evidence. Missing
    or failed records are represented by explicit coverage rows. Inventory
    conclusions are separate from the network state and conditional on supplied
    evidence; no network connection is made by this function.
    """
    if not isinstance(manifest, dict) or str(manifest.get("schema_version")) != "1" \
            or not isinstance(manifest.get("targets"), list):
        raise ReportError("Manifeste invalide: schema_version='1' et targets=[...] requis.")
    base_dir = Path(base_dir)
    campaign_id = str(manifest.get("campaign_id", ""))
    observed_at = str(manifest.get("finished_at") or manifest.get("started_at") or "")
    discovery, discovery_rows, discovery_summary = _discovery_report(manifest, campaign_id, observed_at)
    try:
        # Freshness is judged at report generation, not an arbitrary historical
        # manifest date; an old scan cannot make an old runtime proof current.
        now = datetime.now(timezone.utc)
        inventory_data = load_inventory(Path(inventory)) if inventory is not None else None
        assess_runtime({}, None, now=now, max_age_hours=max_inventory_age_hours)
    except InventoryError as exc:
        raise ReportError(str(exc)) from exc
    rows, attempted_names, evaluated_names = [], set(), set()
    endpoint_count = attempted_count = completed_count = 0
    processing_complete = discovery_summary.get("discovery_processing_complete", True)
    seen_names = set()
    for target in manifest["targets"]:
        if not isinstance(target, dict) or not isinstance(target.get("hostname"), str) \
                or not target["hostname"] or not isinstance(target.get("endpoints", []), list):
            raise ReportError("Cible du manifeste invalide.")
        name = target["hostname"]
        if name in seen_names:
            raise ReportError("Nom de cible duplique dans le manifeste.")
        seen_names.add(name)
        endpoints = target.get("endpoints", [])
        if not endpoints:
            code = "DNS_ERROR" if target.get("dns_status") == "DNS_ERROR" else (
                "NO_DNS_ADDRESS" if target.get("dns_status") == "NO_ADDRESS" else (
                "NO_PUBLIC_ADDRESS" if target.get("dns_status") == "NO_PUBLIC_ADDRESS" else
                "TARGET_NOT_ATTEMPTED"))
            reason = target.get("dns_error") or "Aucune adresse du domaine n'a ete evaluee."
            rows.append(_campaign_coverage(name, None, str(reason), code, campaign_id, observed_at))
            processing_complete = False
            continue
        # One failed DNS family must remain visible even when the other family
        # resolved successfully. NO_ADDRESS is a normal lack of A/AAAA records.
        families = target.get("dns_families", {})
        if not isinstance(families, dict):
            raise ReportError("Resultats DNS par famille invalides.")
        if target.get("dns_status") == "RESOLVED":
            for family, dns in families.items():
                if isinstance(dns, dict) and dns.get("status") in ("ERROR", "TIMEOUT"):
                    detail = str(dns.get("error") or dns["status"])
                    rows.append(_campaign_coverage(name, {"family": family},
                                "Resolution DNS " + str(family) + " indisponible: " + detail,
                                "DNS_FAMILY_ERROR", campaign_id, observed_at))
                    processing_complete = False
        declared_addresses = target.get("addresses", [])
        if not isinstance(declared_addresses, list) or any(not isinstance(ip, str) for ip in declared_addresses):
            raise ReportError("Liste d'adresses du manifeste invalide.")
        endpoint_ips = [endpoint.get("ip") for endpoint in endpoints if isinstance(endpoint, dict)]
        for missing_ip in dict.fromkeys(ip for ip in declared_addresses if ip not in endpoint_ips):
            rows.append(_campaign_coverage(name, {"ip": missing_ip},
                        "Adresse resolue absente des executions planifiees.", "ADDRESS_NOT_ATTEMPTED", campaign_id, observed_at))
            processing_complete = False
        for endpoint in endpoints:
            if not isinstance(endpoint, dict) or not isinstance(endpoint.get("ip"), str):
                raise ReportError("Adresse du manifeste invalide.")
            endpoint_count += 1
            status = endpoint.get("status", "PLANNED")
            if status in ("RUNNING", "COMPLETED", "FAILED", "TIMEOUT", "INTERRUPTED"):
                attempted_names.add(name)
                attempted_count += 1
            stamp = str(endpoint.get("finished_at") or observed_at)
            if status != "COMPLETED" or endpoint.get("returncode", 0) != 0:
                code = {"TIMEOUT": "SCAN_TIMEOUT", "FAILED": "SCAN_FAILED", "RUNNING": "SCAN_INCOMPLETE",
                        "INTERRUPTED": "SCAN_INTERRUPTED", "SKIPPED": "SCAN_SKIPPED"}.get(
                            status, "SCAN_NOT_ATTEMPTED")
                rows.append(_campaign_coverage(name, endpoint, str(endpoint.get("error") or
                          "Execution de scan non terminee avec succes."), code, campaign_id, stamp))
                processing_complete = False
                continue
            try:
                xml = _safe_xml_path(base_dir, endpoint.get("xml"))
                parsed = parse_report(xml)
                # Each runner job targets one fixed IP and one Host/SNI. Reject
                # foreign records instead of silently attaching them to a name.
                foreign = [row for row in parsed if row.get("ip") != endpoint["ip"]]
                if foreign:
                    raise ReportError("Le XML contient une adresse differente de la cible du manifeste.")
                for row in parsed:
                    if row["row_type"] == "ASSESSMENT" and row.get("hostname") not in ("", name, endpoint["ip"]):
                        raise ReportError("Le XML annonce un hote virtuel different du manifeste.")
            except ReportError as exc:
                rows.append(_campaign_coverage(name, endpoint, str(exc), "INVALID_SCAN_XML", campaign_id, stamp))
                processing_complete = False
                continue
            completed_count += 1
            if not parsed:
                rows.append(_campaign_coverage(name, endpoint, "Le XML ne contient aucun enregistrement de la cible attendue.",
                                               "TARGET_MISSING_FROM_XML", campaign_id, stamp))
                processing_complete = False
                continue
            for row in parsed:
                row.update(hostname=name, campaign_id=campaign_id, observed_at=row.get("observed_at") or stamp,
                           source_xml=str(endpoint["xml"]), scan_status=status, target_sources=target.get("sources", []),
                           address_family=endpoint.get("family", ""), scan_ports=endpoint.get("ports", ""))
                if row["row_type"] == "ASSESSMENT":
                    evaluated_names.add(name)
                rows.append(row)
    rows.extend(discovery_rows)
    for row in rows:
        try:
            row.update(assess_runtime(row, inventory_data, now=now, max_age_hours=max_inventory_age_hours))
        except InventoryError as exc:
            raise ReportError(str(exc)) from exc
    counts = Counter(row["state"] for row in rows if row["row_type"] == "ASSESSMENT")
    runtime_counts = Counter(row["inventory_patch_status"] for row in rows if row.get("port"))
    targets = manifest["targets"]
    summary = {
        "targets_total": len(targets), "targets_resolved": sum(target.get("dns_status") == "RESOLVED" for target in targets),
        "targets_attempted": len(attempted_names), "targets_evaluated": len(evaluated_names),
        "endpoints_total": endpoint_count, "endpoints_attempted": attempted_count, "endpoints_completed": completed_count,
        "assessments": sum(counts.values()), "assessment_counts": dict(counts),
        "coverage_rows": sum(row["row_type"] == "COVERAGE" for row in rows),
        "inventory_counts": dict(runtime_counts), "processing_complete": processing_complete and manifest.get("status") == "COMPLETED",
        "excluded_candidates": len(manifest.get("excluded_candidates", [])),
        **discovery_summary,
    }
    result = {"schema_version": "1", "tool_version": str(manifest.get("tool_version") or "0.3.0"),
              "campaign": {key: manifest.get(key) for key in ("campaign_id", "started_at", "finished_at", "status", "profile", "ports", "address_families", "http", "limits", "scope")},
              "generated_at": now.isoformat(), "summary": summary, "rows": rows, "changes": [],
              "excluded_candidates": manifest.get("excluded_candidates", []),
              "limitations": [
                  "La couverture concerne les noms, adresses et ports explicitement traites; elle ne prouve pas l'inventaire des backends.",
                  "Une absence d'evaluation ou de signal reseau ne confirme pas l'application du correctif.",
                  "Les preuves serveur importees restent des attestations dont l'authenticite et l'exhaustivite sont a valider par l'operateur.",
              ]}
    if discovery is not None:
        result["discovery"] = discovery
        result["campaign"]["discovery"] = {key: value for key, value in discovery.items()
                                            if key not in ("queries", "candidates")}
        if discovery.get("enabled"):
            result["limitations"].append(
                "La decouverte passive observe des noms publies par la source; meme terminee sans erreur, "
                "elle ne prouve pas l'exhaustivite des sous-domaines. Aucun nom trouve ne signifie pas aucun sous-domaine."
            )
    if inventory_data:
        result["inventory"] = {key: inventory_data[key] for key in ("filename", "sha256", "trust_note")}
        result["inventory"]["max_age_hours"] = max_inventory_age_hours
    if previous is not None:
        old = load_campaign_report(Path(previous))
        _, previous_sha256 = _read_json_report(Path(previous))
        result["changes"] = compare_reports(result, old)
        result["comparison"] = {"filename": Path(previous).name, "sha256": previous_sha256,
                                "previous_campaign": old.get("campaign", {}),
                                "counts": dict(Counter(item["change"] for item in result["changes"]))}
    return result


def write_campaign_report(report: dict, output_dir: Path) -> None:
    """Write each artifact atomically; publish JSON last as completion marker."""
    output_dir = Path(output_dir)
    # Validate both forms before touching any existing artifact. Keep evidence
    # and service-level comparison data out of the operator's main reports.
    compact = compact_rows(_validate_detailed(report)["rows"])

    def write_details(stream):
        json.dump(report, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")

    def write_compact(stream):
        stream.write("[\n")
        for index, row in enumerate(compact):
            if index:
                stream.write(",\n")
            json.dump(row, stream, ensure_ascii=False, allow_nan=False)
        if compact:
            stream.write("\n")
        stream.write("]\n")

    _atomic_text(output_dir / "raw" / "report-details.json", write_details)
    _write_csv(compact, output_dir / "report.csv", COMPACT_FIELDS)
    _write_csv(report.get("changes", []), output_dir / "changes.csv", CHANGE_FIELDS)
    _atomic_text(output_dir / "report-tree.txt", lambda stream: stream.write(
        _report_tree_text(report, compact)))
    _atomic_text(output_dir / "report.json", write_compact)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="XML Nmap terminé ou rapport JSON existant")
    parser.add_argument("-o", "--output", required=True, type=Path, help="CSV UTF-8 a produire")
    parser.add_argument("--detailed", action="store_true", help="Exporter les observations techniques et la couverture (ancien CSV)")
    args = parser.parse_args(argv)
    try:
        # Sniff only a small prefix. JSON loading has its own bounded reader;
        # XML parsing still requires a completed, successful Nmap scan.
        with args.source.open("rb") as stream:
            prefix = stream.read(4096).lstrip(b"\xef\xbb\xbf \t\r\n")
        if args.source.suffix.lower() in (".json", ".jsonl") or prefix.startswith((b"[", b"{")):
            value, _ = _read_json_report(args.source)
            if isinstance(value, list):
                rows = _validate_compact(value)
                companion = args.source.parent / "raw" / "report-details.json"
                if companion.exists():
                    _protect_source(args.output, companion)
                if args.detailed:
                    rows = load_campaign_report(args.source)["rows"]
            else:
                rows = _validate_detailed(value)["rows"]
        else:
            rows = parse_report(args.source)
        write_report(rows, args.output, args.source, detailed=args.detailed)
    except (ReportError, OSError) as exc:
        print(f"Erreur: {exc}", file=sys.stderr)
        return 2
    print(f"Rapport: {args.output}")
    if not args.detailed:
        compact = rows if rows and "cible" in rows[0] else compact_rows(rows)
        counts = Counter(row["vulnerable"] for row in compact)
        print(f"Cibles: {len(compact)} — OUI: {counts['OUI']}, NON: {counts['NON']}, INDETERMINE: {counts['INDETERMINE']}")
        return 0
    counts = Counter(row["state"] for row in rows if row.get("row_type") == "ASSESSMENT")
    print(f"Evaluations PHP2Shell: {sum(counts.values())}")
    for state in STATES:
        print(f"  {state}: {counts[state]}")
    print(f"Lignes de couverture sans evaluation: {sum(row.get('row_type') == 'COVERAGE' for row in rows)}")
    print("COVERAGE / NOT_ASSESSED ne signifie pas vulnerable et ne signifie pas corrige.")
    print("Chaque entree hote du XML est conservee; les comptes ne sont pas des IP uniques.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
