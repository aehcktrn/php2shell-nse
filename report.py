#!/usr/bin/env python3
"""Export local PHP2Shell XML or JSON results as one CSV row per target.

No scan or network connection is made. Detailed observations remain available
with --detailed; the default export contains cible, php, vulnerable, explication.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
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
RENDERER_VERSION = "0.6.1"
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
        "discovered_paths": _array(script, "discovered_paths"),
        "crawl_truncated": _scalar(script, "crawl_truncated"),
        "crawl_gap_reason_code": _scalar(script, "crawl_gap_reason_code"),
        "crawl_gap_path": _scalar(script, "crawl_gap_path"),
        "collection_phase": _scalar(script, "collection_phase"),
        "candidate_paths": _array(script, "candidate_paths"),
        "candidates_examined": _scalar(script, "candidates_examined"),
        "candidate_count": _scalar(script, "candidate_count"),
        "enrichment_requests": _scalar(script, "enrichment_requests"),
        "private_plan_error": _scalar(script, "private_plan_error"),
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
    if _true(observation.get("managed_collection")) and observation.get("redirect_to"):
        return _single_line(observation.get("redirect_to"))
    explicitly_outside = observation.get("redirect_scope") == "HORS_PERIMETRE_DU_CONTROLE"
    stopped_at_origin = (str(observation.get("redirect_followed", "")).lower() == "false"
                         and observation.get("redirect_reason") == "Redirect leaves the current origin.")
    if (observation.get("reason_code") != "REDIRECT_NOT_ASSESSED"
            and not explicitly_outside and not stopped_at_origin):
        return ""
    return _single_line(observation.get("redirect_to"))


def _modern_redirect_row(row: dict[str, Any]) -> bool:
    return bool(row.get("collection_service_key")) and not row.get("_historical_redirect_semantics")


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
        observation: dict[str, Any] | None = None,
) -> bool:
    """Tell whether the exact redirect URL was requested elsewhere in the campaign."""
    if row.get("collection_service_key") and observation is not None:
        return _true(observation.get("redirect_evaluated"))
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
            covered = ((_modern_redirect_row(row) and _true(observation.get("redirect_evaluated")))
                       or (assessment_index is not None and _redirect_destination_was_assessed(
                           row, destination, assessment_index, observation)))
            bucket = assessed if covered else unassessed
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
    "HTTP_BUDGET_UNCERTAIN", "INPUT_UNAVAILABLE", "REDIRECT_LOOP", "CHAIN_LIMIT", "NO_HTTP_SERVICE",
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
    "HTTP_BUDGET_UNCERTAIN": "Quota réservé après interruption ; consommation HTTP exacte inconnue",
    "INPUT_UNAVAILABLE": "URL exacte impossible à restituer pour la reprise ; paramètres expurgés",
    "REDIRECT_LOOP": "Boucle de redirection détectée",
    "CHAIN_LIMIT": "Limite commune de chaîne de redirections atteinte",
    "NO_HTTP_SERVICE": "Service HTTP destinataire non disponible sur le port autorisé",
    "UNAUTHORIZED_PORT": "Port de destination absent des ports autorisés de la campagne",
    "OUTSIDE_AUTHORIZED_DOMAINS": "Nom de destination hors du périmètre DNS autorisé",
    "EXCLUDED_BY_OPERATOR": "Destination exclue par l'opérateur",
    "REDIRECT_PLAN_LIMIT": "Plafond de destinations de redirection atteint",
    "INVALID_REDIRECT_URL": "URL de redirection invalide ou non HTTP/HTTPS",
    "INVALID_REDIRECT_PORT": "Port de redirection invalide",
    "INVALID_REDIRECT_PATH": "Chemin de redirection invalide",
    "INVALID_REDIRECT_IDENTITY": "Identité de redirection incohérente",
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
    if row.get("row_type") != "ASSESSMENT":
        return "INDETERMINE"
    if proof == "PATCH_CONFIRMED":
        return "INDETERMINE" if _http_gap(row) else "NON"
    # One affected runtime exposed by any page is enough to classify the
    # service as vulnerable. Other hidden or blocked pages cannot turn that
    # positive evidence back into an indeterminate result.
    if _suspect(row) and _version_values(row.get("versions")):
        return "OUI"
    if proof == "CONFLICT" or _http_gap(row):
        return "INDETERMINE"
    if _version_values(row.get("versions")):
        if row.get("state") == "PATCHED_VERSION_ADVERTISED" and not _suspect(row):
            return "NON"
    return "INDETERMINE"


def _pre_v054_compact_verdict(row: dict[str, Any]) -> str:
    """Reproduce stored verdicts before affected evidence took precedence."""
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
    """Confirm that a path was reached on a conclusively versioned service.

    PHP version headers qualify the web service/runtime, not only the URL that
    happened to expose them. Still require the exact destination to have been
    requested, and never let evidence from another page erase a service-level
    HTTP gap such as a denial, timeout or incomplete traversal.
    """
    if _compact_verdict(candidate) == "INDETERMINE":
        return False
    if not _observation_matches_path(candidate, request_target):
        return False
    observations = candidate.get("observations")
    proof = candidate.get("inventory_patch_status")
    reached = False
    for observation in observations:
        if not isinstance(observation, dict) or _single_line(observation.get("path")) != request_target:
            continue
        reached = True
        if (observation.get("reason_code") in HTTP_GAP_CODES
                or str(observation.get("http_status", "")) in ("401", "403", "429")):
            return False
        if proof in ("PATCH_CONFIRMED", "PATCH_MISSING_CONFIRMED"):
            return True
        if (observation.get("state") in ("POTENTIALLY_VULNERABLE", "PATCHED_VERSION_ADVERTISED")
                and _version_values(observation.get("versions"))):
            return True
    return (reached
            and candidate.get("state") in ("POTENTIALLY_VULNERABLE", "PATCHED_VERSION_ADVERTISED")
            and bool(_version_values(candidate.get("versions"))))


def _pre_v054_observation_covers_path(candidate: dict[str, Any], request_target: str) -> bool:
    """Preserve the exact-page version rule used in stored v0.5.0-v0.5.3 reports."""
    if (_pre_v054_compact_verdict(candidate) == "INDETERMINE"
            or not _observation_matches_path(candidate, request_target)):
        return False
    for observation in candidate["observations"]:
        if not isinstance(observation, dict) or _single_line(observation.get("path")) != request_target:
            continue
        if candidate.get("inventory_patch_status") in ("PATCH_CONFIRMED", "PATCH_MISSING_CONFIRMED"):
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
                   and _pre_v054_compact_verdict(candidate) != "INDETERMINE"
                   for candidate in rows):
            return False
    return True


def _redirect_is_covered(row: dict[str, Any], rows: list[dict[str, Any]],
                         *, historical_semantics: bool = False) -> bool:
    """Return true when every external-origin redirect was assessed separately.

    The NSE deliberately does not cross an origin boundary. A campaign can
    nevertheless cover a routine HTTP-to-HTTPS redirect through its separate
    scan of the destination service. Require the same target name, IP and exact
    request target. Once that path has answered without a service-level gap,
    PHP evidence from another requested page qualifies the same web service.
    """
    if row.get("collection_service_key"):
        observations = row.get("observations", [])
        target = _single_line(row.get("hostname")).lower().rstrip(".")
        def same_name(observation):
            try:
                destination = urlsplit(_single_line(observation.get("redirect_to")))
                return (destination.hostname or "").lower().rstrip(".") == target
            except ValueError:
                return False
        return (not row.get("collection_gaps") and bool(observations)
                and all(isinstance(item, dict) and _true(item.get(
                    "redirect_conclusive" if _modern_redirect_row(row) else "redirect_evaluated"))
                        and same_name(item) for item in observations))
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
    covers_path = (_pre_v054_observation_covers_path if historical_semantics
                   else _observation_covers_path)
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
                   and covers_path(candidate, request_target)
                   for candidate in rows):
            return False
    return True


def _covered_redirect_is_navigation_only(row: dict[str, Any], rows: list[dict[str, Any]],
                                          *, historical_semantics: bool = False) -> bool:
    """Suppress only the resolved navigation gap, never independent evidence."""
    if not _redirect_is_covered(row, rows, historical_semantics=historical_semantics):
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
    if _modern_redirect_row(row) and not _version_values(row.get("versions")):
        observations = [item for item in row.get("observations", []) if isinstance(item, dict)]
        statuses = {_single_line(item.get("http_status")) for item in observations
                    if _single_line(item.get("http_status")).isdigit()
                    and not 300 <= int(_single_line(item.get("http_status"))) < 400}
        gap_statuses = {_single_line(item.get("http_status")) for item in row.get("collection_gaps", [])
                        if isinstance(item, dict) and _single_line(item.get("http_status")).isdigit()}
        if statuses == {"404"}:
            return "HTTP 404 : pages demandées introuvables ; version PHP non identifiée"
        if gap_statuses == {"404"}:
            return "HTTP 404 à la destination ; version PHP non identifiée"
    if code == "REDIRECT_NOT_ASSESSED" and _redirect_row_was_assessed_separately(row, assessment_index):
        if _modern_redirect_row(row):
            return "Destination de redirection visitée ; conclusion PHP indéterminée"
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
                                | None = None, *, historical_semantics: bool = False,
                                legacy_cause_order: bool = False) -> str:
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
        if not historical_semantics and any(item.get("inventory_patch_status") == "CONFLICT" for item in rows):
            reason += " Preuves serveur contradictoires ; le signal vulnérable reste prioritaire."
        if any(item.get("collection_original_reason_code") == "CONFLICTING_VERSIONS" for item in rows):
            reason += " Versions publiées contradictoires ; signal vulnérable conservé."
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
    primary = unknown
    if not historical_semantics and not legacy_cause_order:
        # A separately requested redirect destination can still be inconclusive.
        # Prefer its actual failure or hidden version over the navigation hop.
        primary = [item for item in unknown if not (
            (item.get("traversal_reason_code") or item.get("reason_code")) == "REDIRECT_NOT_ASSESSED"
            and item.get("inventory_patch_status") in (None, "", "NOT_PROVIDED")
            and not _suspect(item)
            and _redirect_row_was_assessed_separately(item, assessment_index)
        )] or unknown
    # Surface a concrete coverage failure before a generic hidden-version
    # observation, without expanding one line into a catalogue of endpoints.
    row = next((item for item in primary if item.get("row_type") != "ASSESSMENT" or _http_gap(item)), primary[0])
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
    parts = _redirect_coverage_summaries(rows, bounded=True)
    legacy_rows = [row for row in rows if not _modern_redirect_row(row)]
    unassessed, assessed = _redirect_destinations_by_coverage(legacy_rows, assessment_index)
    # v0.5.0 companion validation preserves its original encounter order.
    if assessment_index is not None:
        unassessed = _cross_host_first(unassessed, rows)
        assessed = _cross_host_first(assessed, rows)
    if unassessed:
        label = "destination non évaluée" if len(unassessed) == 1 else "destinations non évaluées"
        parts.append(f"HORS PÉRIMÈTRE DU CONTRÔLE — {label} : {_destination_listing(unassessed)}.")
    if assessed:
        label = "destination évaluée séparément" if len(assessed) == 1 else "destinations évaluées séparément"
        parts.append(f"Dans la campagne — {label} : {_destination_listing(assessed)}.")
    return _short(" ".join(parts), 245)


OUTSIDE_REDIRECT_SCOPES = frozenset({
    "OUTSIDE_AUTHORIZED_DOMAINS", "UNAUTHORIZED_PORT", "EXCLUDED_BY_OPERATOR", "NO_PUBLIC_ADDRESS",
})


def _redirect_coverage_summaries(rows: list[dict[str, Any]], *, bounded: bool = False) -> list[str]:
    """Report authorization, physical visits and PHP conclusions separately."""
    groups: dict[tuple[str, bool, bool, str, tuple[str, ...]], list[str]] = {}
    for row in rows:
        if not _modern_redirect_row(row):
            continue
        for observation in row.get("observations", []):
            if not isinstance(observation, dict):
                continue
            destination = _redirect_observation_destination(observation)
            if not destination:
                continue
            scope = _single_line(observation.get("redirect_scope") or "UNKNOWN")
            visited = _true(observation.get("redirect_evaluated"))
            conclusive = _true(observation.get("redirect_conclusive"))
            reason = _single_line(observation.get("redirect_coverage_reason"))
            raw_statuses = observation.get("redirect_destination_http_statuses", [])
            if not isinstance(raw_statuses, list):
                raw_statuses = [raw_statuses]
            causal_status = _single_line(observation.get("redirect_coverage_http_status"))
            statuses = tuple(sorted({_single_line(value) for value in raw_statuses + [causal_status]
                                     if _single_line(value).isdigit() and 100 <= int(_single_line(value)) <= 599}))
            key = scope, visited, conclusive, reason, statuses
            destinations = groups.setdefault(key, [])
            if destination not in destinations:
                destinations.append(destination)
    labels = {
        "PHP_NOT_IDENTIFIED": "PHP non identifié",
        "PHP_VERSION_HIDDEN": "version PHP non publiée",
        "AUTHENTICATION_REQUIRED": "authentification requise",
        "HTTP_ACCESS_DENIED": "accès refusé",
        "RATE_LIMITED": "requêtes limitées",
    }
    result = []
    ordered = sorted(groups.items(), key=lambda item: (
        0 if item[0][0] in OUTSIDE_REDIRECT_SCOPES else 1 if not item[0][1] else 2,
        item[0][2],
    ))
    for (scope, visited, conclusive, reason, statuses), destinations in ordered:
        outside = scope in OUTSIDE_REDIRECT_SCOPES
        prefix = "HORS PÉRIMÈTRE AUTORISÉ — " if outside else "DANS LE PÉRIMÈTRE — " if scope == "IN_SCOPE" else ""
        plural = len(destinations) != 1
        label = ("destinations " if plural else "destination ")
        label += ("VISITÉES" if plural else "VISITÉE") if visited else ("NON VISITÉES" if plural else "NON VISITÉE")
        details = []
        if statuses:
            details.append("HTTP " + "/".join(statuses))
        if conclusive:
            details.append("conclusion PHP établie")
        else:
            cause = labels.get(reason) or COMPACT_REASONS.get(reason)
            if visited and not outside and reason in OUTSIDE_REDIRECT_SCOPES:
                cause = "suite de la chaîne vers une destination hors périmètre"
            if cause:
                details.append(cause)
            elif visited:
                details.append("conclusion PHP indéterminée")
        listing = (_destination_listing(_cross_host_first(destinations, rows)) if bounded else
                   ", ".join(_cross_host_first(destinations, rows)))
        result.append(prefix + label + ((" ; " + " ; ".join(details)) if details else "")
                      + " : " + listing + ("." if bounded else ""))
    return result


def _compact_explanation(rows: list[dict[str, Any]], verdicts: list[str], verdict: str,
                         *, port_rows: list[dict[str, Any]] | None = None,
                         include_redirect_destinations: bool = True,
                         assessment_index: dict[tuple[str, int, str, str], set[int]]
                         | None = None, historical_semantics: bool = False,
                         legacy_cause_order: bool = False) -> str:
    reason = _legacy_compact_explanation(
        rows, verdicts, verdict, assessment_index, historical_semantics=historical_semantics,
        legacy_cause_order=legacy_cause_order)
    sources, phases = set(), set()
    for row in rows:
        if not row.get("collection_service_key"):
            continue
        for item in row.get("evidence", []):
            if isinstance(item, dict) and item.get("version"):
                source = str(item.get("source", ""))
                if source == "phpinfo-structured":
                    sources.add("diagnostic phpinfo structuré")
                elif source in ("server", "x-powered-by"):
                    sources.add("en-têtes HTTP")
                phase = str(item.get("collection_phase", ""))
                if phase in ("redirect", "links"):
                    phases.add("redirection exacte" if phase == "redirect" else "lien applicatif")
    if sources:
        reason += " Source publiée : " + " et ".join(sorted(sources))
        if phases:
            reason += " via " + " / ".join(sorted(phases))
        reason += "."
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
                 redirect_coverage: str = "campaign",
                 historical_semantics: bool = False,
                 legacy_cause_order: bool = False) -> list[dict[str, str]]:
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
            conclusive = [row for row in relevant if not _covered_redirect_is_navigation_only(
                row, relevant, historical_semantics=historical_semantics)]
        determine = _pre_v054_compact_verdict if historical_semantics else _compact_verdict
        verdicts = [determine(row) for row in conclusive]
        verdict = ("OUI" if "OUI" in verdicts else
                   "NON" if verdicts and all(value == "NON" for value in verdicts) else "INDETERMINE")
        if legacy_explanation:
            explanation = _legacy_compact_explanation(
                conclusive, verdicts, verdict, historical_semantics=historical_semantics,
                legacy_cause_order=legacy_cause_order)
        else:
            explanation = _compact_explanation(
                conclusive, verdicts, verdict, port_rows=relevant,
                include_redirect_destinations=include_redirect_destinations,
                assessment_index=assessment_index,
                historical_semantics=historical_semantics,
                legacy_cause_order=legacy_cause_order,
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


def _tree_result_label(label: str, row: dict[str, Any] | None, count: int,
                       *, root: bool = False) -> str:
    if row is None:
        result = f"{label} [regroupement]"
    else:
        verdict = {"OUI": "VULNERABLE", "NON": "NON-VULNERABLE"}.get(
            row["vulnerable"], row["vulnerable"])
        fields = [f"PHP {row['php']}", verdict]
        cause = _tree_result_cause(row)
        if cause:
            fields.append(cause)
        proofs = row.get("_tree_proofs")
        if isinstance(proofs, list) and proofs:
            fields.append("PREUVE " + _single_line(proofs[0]))
        result = f"{label} [{' | '.join(fields)}]"
    if root:
        result += f" — {count} cible" + ("s" if count != 1 else "")
    return result


def _tree_result_cause(row: dict[str, Any]) -> str:
    """Return a short operational cause without duplicating the full report."""
    if row.get("vulnerable") != "INDETERMINE":
        return ""
    causes = row.get("_tree_causes")
    if isinstance(causes, list) and causes:
        return " ; ".join(causes)
    explanation = row.get("explication", "")
    outside = "HORS PÉRIMÈTRE DU CONTRÔLE —"
    if outside in explanation:
        segment = explanation[explanation.index(outside):]
        for marker in (". Dans la campagne", ". Ports évalués", ". Ports ouverts",
                       ". Version", ". PHP", ". Aucune", ". Service", ". Résolution",
                       ". Échec", ". Délai", ". Scan", ". Budget", ". Parcours"):
            if marker in segment:
                segment = segment.split(marker, 1)[0]
        return _short(segment.rstrip("."), 170)
    causes = (
        ("HTTP 403", "HTTP 403"),
        ("HTTP 401", "HTTP 401"),
        ("HTTP 429", "HTTP 429"),
        ("Aucune adresse IP résolue", "SANS DNS"),
        ("Aucune adresse IP publique", "SANS IP PUBLIQUE"),
        ("Aucun port TCP ouvert", "AUCUN PORT WEB OUVERT"),
        ("Budget HTTP épuisé", "BUDGET HTTP ÉPUISÉ"),
        ("Délai du scan Nmap dépassé", "SCAN EXPIRÉ"),
        ("Échec du scan Nmap", "ÉCHEC NMAP"),
        ("Scan Nmap interrompu", "SCAN INTERROMPU"),
        ("Scan Nmap incomplet", "SCAN INCOMPLET"),
        ("Scan Nmap non exécuté", "SCAN NON EXÉCUTÉ"),
        ("Cible absente du résultat Nmap", "CIBLE ABSENTE DU RÉSULTAT NMAP"),
        ("Résultat Nmap incomplet ou invalide", "RÉSULTAT NMAP INVALIDE"),
        ("Destination de redirection non évaluée", "REDIRECTION NON COUVERTE"),
        ("Parcours des redirections incomplet", "REDIRECTION INCOMPLÈTE"),
        ("PHP détecté, mais sa version n'est pas annoncée", "VERSION PHP MASQUÉE"),
        ("PHP non identifié", "VERSION NON EXPOSÉE"),
        ("Aucune réponse HTTP exploitable", "AUCUNE RÉPONSE HTTP"),
        ("Service ouvert sans évaluation PHP exploitable", "SERVICE NON ÉVALUÉ"),
        ("Résolution DNS impossible", "ERREUR DNS"),
    )
    for marker, cause in causes:
        if marker in explanation:
            return cause
    if row.get("php") and row["php"] != "INCONNUE":
        return "VERSION VUE, COUVERTURE INCOMPLÈTE"
    return "CAUSE À VÉRIFIER"


def _tree_result_count(node: dict[str, Any]) -> int:
    return (1 if node.get("row") is not None else 0) + sum(
        _tree_result_count(child) for child in node["children"].values())


def _render_tree_children(node: dict[str, Any], prefix: str, lines: list[str]) -> None:
    children = sorted(node["children"].items(), key=lambda item: item[0])
    for index, (label, child) in enumerate(children):
        last = index == len(children) - 1
        lines.append(prefix + ("└── " if last else "├── ")
                     + _tree_result_label(label, child.get("row"), _tree_result_count(child)))
        child_prefix = prefix + ("    " if last else "│   ")
        _render_tree_extra_proofs(child.get("row"), child_prefix, lines)
        _render_tree_children(child, child_prefix, lines)


def _render_tree_extra_proofs(row: dict[str, Any] | None, prefix: str, lines: list[str]) -> None:
    """Keep each additional affected service/page visible below its DNS node."""
    proofs = row.get("_tree_proofs") if row is not None else None
    if isinstance(proofs, list):
        lines.extend(prefix + "PREUVE " + _single_line(proof) for proof in proofs[1:])


def _report_tree_forest(roots: list[str], rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Build a DNS hierarchy beneath explicit scope roots."""
    forest: dict[str, dict[str, Any]] = {
        root: {"row": None, "children": {}} for root in roots
    }
    for row in rows:
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
    return forest


def _render_tree_view(roots: list[str], rows: list[dict[str, Any]], empty: str) -> list[str]:
    """Render one filtered managerial view while preserving DNS grouping."""
    if not rows:
        return [empty]
    forest = _report_tree_forest(roots, rows)
    lines = []
    ordered_roots = [root for root in roots if root in forest and _tree_result_count(forest[root])]
    ordered_roots.extend(sorted(
        root for root in forest if root not in roots and _tree_result_count(forest[root])))
    for index, root in enumerate(ordered_roots):
        node = forest[root]
        lines.append(_tree_result_label(root, node.get("row"), _tree_result_count(node), root=True))
        _render_tree_extra_proofs(node.get("row"), "│   " if node["children"] else "    ", lines)
        _render_tree_children(node, "", lines)
        if index != len(ordered_roots) - 1:
            lines.append("")
    return lines


def _report_php_targets(report: dict[str, Any]) -> set[str]:
    """Return targets for which PHP was observed or attested, versioned or not."""
    targets = set()
    rows = report.get("rows")
    if not isinstance(rows, list):
        return targets
    for row in rows:
        if not isinstance(row, dict) or row.get("protocol") == "discovery":
            continue
        target = _single_line(row.get("hostname") or row.get("ip")).lower().rstrip(".")
        proof = _single_line(row.get("inventory_patch_status"))
        if (target and (row.get("php_detected") == "YES"
                        or bool(_version_values(row.get("versions")))
                        or proof in ("PATCH_CONFIRMED", "PATCH_MISSING_CONFIRMED"))):
            targets.add(target)
    return targets


def _report_indeterminate_causes(report: dict[str, Any]) -> dict[str, list[str]]:
    """Group identical causes across backends, retaining every reason and redirect."""
    rows = report.get("rows")
    if not isinstance(rows, list):
        return {}
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if not isinstance(row, dict) or row.get("protocol") == "discovery":
            continue
        target = _single_line(row.get("hostname") or row.get("ip")).lower().rstrip(".")
        if target:
            groups.setdefault(target, []).append(row)
    assessment_index = _redirect_assessment_index(rows)
    output = {}
    for target, group in groups.items():
        relevant = [row for row in group if not _non_web_coverage(row)]
        conclusive = [row for row in relevant
                      if not _covered_redirect_is_navigation_only(row, relevant)]
        causes = _redirect_coverage_summaries(conclusive)
        legacy_rows = [row for row in conclusive if not _modern_redirect_row(row)]
        unassessed, assessed = _redirect_destinations_by_coverage(legacy_rows, assessment_index)
        for destinations, prefix, singular, plural in (
            (unassessed, "HORS PÉRIMÈTRE DU CONTRÔLE", "destination non évaluée", "destinations non évaluées"),
            (assessed, "Dans la campagne", "destination évaluée séparément", "destinations évaluées séparément"),
        ):
            if destinations:
                label = singular if len(destinations) == 1 else plural
                causes.append(prefix + " — " + label + " : " + ", ".join(_cross_host_first(destinations, conclusive)))
        unknown = [row for row in conclusive if _compact_verdict(row) == "INDETERMINE"]
        navigation = {id(row) for row in unknown if (
            (row.get("traversal_reason_code") or row.get("reason_code")) == "REDIRECT_NOT_ASSESSED"
            and row.get("inventory_patch_status") in (None, "", "NOT_PROVIDED")
            and not _suspect(row)
            and _redirect_row_was_assessed_separately(row, assessment_index)
        )}
        actual = [row for row in unknown if id(row) not in navigation]
        grouped: dict[tuple[str, str], dict[str, set]] = {}
        for row in actual or unknown:
            cause = ("Statut PHP de la destination non établi" if id(row) in navigation
                     else _unknown_reason(row, assessment_index))
            key = cause, _single_line(row.get("crawl_gap_path"))
            endpoints = grouped.setdefault(key, {"ports": set(), "addresses": set()})
            port = _single_line(row.get("port"))
            if len(port) <= 5 and port.isascii() and port.isdecimal() and 1 <= int(port) <= 65535:
                endpoints["ports"].add(int(port))
            endpoints["addresses"].update(
                address.strip() for address in _single_line(row.get("ip")).split("|") if address.strip())
        for (cause, gap_path), endpoints in grouped.items():
            if gap_path:
                cause += " sur " + gap_path
            context = []
            ports = sorted(endpoints["ports"])
            if ports:
                context.append(("port " if len(ports) == 1 else "ports ") + ",".join(map(str, ports)))
            if len(endpoints["addresses"]) > 1:
                context.append(str(len(endpoints["addresses"])) + " adresses")
            if context:
                cause += " (" + " ; ".join(context) + ")"
            causes.append(cause)
        if not conclusive:
            causes.append("Aucun service HTTP évalué ; PHP et ses correctifs restent à vérifier")
        output[target] = causes
    return output


def _tree_endpoint(target: str, scheme: object, port: object, path: object) -> str:
    """Format a concise public endpoint without inventing missing fields."""
    scheme_text = _single_line(scheme).lower()
    port_text = _single_line(port)
    path_text = _single_line(path) or "/"
    host = ("[" + target + "]" if ":" in target and not (target.startswith("[") and target.endswith("]"))
            else target)
    if scheme_text not in ("http", "https"):
        endpoint = host
        if port_text:
            endpoint += ":" + port_text
        return endpoint + path_text
    default = (scheme_text == "http" and port_text == "80") or (scheme_text == "https" and port_text == "443")
    authority = host if default or not port_text else host + ":" + port_text
    return scheme_text + "://" + authority + path_text


def _report_vulnerability_proofs(report: dict[str, Any]) -> dict[str, list[str]]:
    """Keep the page/service evidence that made each target vulnerable."""
    proofs: dict[str, list[str]] = {}
    rows = report.get("rows")
    if not isinstance(rows, list):
        return proofs
    for row in rows:
        if not isinstance(row, dict) or _compact_verdict(row) != "OUI":
            continue
        target = _single_line(row.get("hostname") or row.get("ip")).lower().rstrip(".")
        if not target:
            continue
        target_proofs = proofs.setdefault(target, [])
        row_proofs = []
        evidence = row.get("evidence")
        if isinstance(evidence, list):
            for item in evidence:
                if not isinstance(item, dict) or item.get("state") != "POTENTIALLY_VULNERABLE":
                    continue
                endpoint = _tree_endpoint(
                    target, item.get("scheme") or row.get("scheme"),
                    item.get("port") or row.get("port"), item.get("path") or row.get("path"),
                )
                version = _single_line(item.get("version"))
                proof = endpoint + ((" — PHP " + version) if version else "")
                if proof not in row_proofs:
                    row_proofs.append(proof)
        if row.get("inventory_patch_status") == "PATCH_MISSING_CONFIRMED":
            endpoint = _tree_endpoint(target, row.get("scheme"), row.get("port"), row.get("path"))
            proof = endpoint + " — correctif manquant attesté"
            if proof not in row_proofs:
                row_proofs.append(proof)
        elif not row_proofs:
            endpoint = _tree_endpoint(target, row.get("scheme"), row.get("port"), row.get("path"))
            versions = _version_values(row.get("versions"))
            proof = endpoint + ((" — PHP " + " / ".join(versions)) if versions else "")
            row_proofs.append(proof)
        target_proofs.extend(proof for proof in row_proofs if proof not in target_proofs)
    return {target: values for target, values in proofs.items() if values}


def _report_tree_text(report: dict[str, Any], compact: list[dict[str, str]]) -> str:
    """Render inventory, PHP hosts, positives and explained gaps as DNS views."""
    roots = _report_tree_roots(report)
    causes = _report_indeterminate_causes(report)
    compact = [dict(row, _tree_causes=causes.get(row["cible"].lower().rstrip("."), []))
               for row in compact]

    campaign = report.get("campaign")
    campaign_id = _single_line(campaign.get("campaign_id")) if isinstance(campaign, dict) else ""
    title = "Synthèse arborescente des résultats"
    if campaign_id:
        title += " — campagne " + campaign_id
    discovery = report.get("discovery")
    discovery_enabled = isinstance(discovery, dict) and _true(discovery.get("enabled"))
    scope_note = (
        "Périmètre : noms Internet publiés par crt.sh et retenus sous les domaines fournis ; "
        "cet inventaire passif n'est pas exhaustif."
        if discovery_enabled else
        "Périmètre : cibles Internet fournies à l'outil ; cette vue ne prétend pas inventorier "
        "les sous-domaines non transmis."
    )
    inventory_title = ("INVENTAIRE INTERNET DÉCOUVERT" if discovery_enabled
                       else "INVENTAIRE DES CIBLES FOURNIES")
    lines = [
        title,
        scope_note,
        "Légende : [PHP version | VULNERABLE/NON-VULNERABLE/INDETERMINE | cause ou preuve éventuelle] ; [regroupement] = branche DNS non évaluée.",
        "Verdicts PHP2Shell selon les versions observées ; parcours représentatif des pages et backends.",
        "",
        f"1. {inventory_title} — {len(compact)} cible" + ("s" if len(compact) != 1 else ""),
    ]
    lines.extend(_render_tree_view(roots, list(compact), "Aucune cible retenue."))

    php_targets = _report_php_targets(report)
    php_rows = [row for row in compact if row["cible"].lower().rstrip(".") in php_targets]
    lines.extend(["", f"2. DOMAINES ET SOUS-DOMAINES HÉBERGEANT DU PHP — {len(php_rows)} hôte"
                  + ("s" if len(php_rows) != 1 else "")])
    lines.extend(_render_tree_view(
        roots, php_rows,
        "Aucun hôte PHP n'a pu être confirmé depuis les réponses Internet ou les preuves serveur fournies.",
    ))

    vulnerability_proofs = _report_vulnerability_proofs(report)
    vulnerable_rows = []
    for row in compact:
        if row["vulnerable"] != "OUI":
            continue
        rendered = dict(row)
        rendered["_tree_proofs"] = vulnerability_proofs.get(row["cible"].lower().rstrip("."), [])
        vulnerable_rows.append(rendered)
    lines.extend(["", f"3. ÉLÉMENTS VULNÉRABLES — {len(vulnerable_rows)} hôte"
                  + ("s" if len(vulnerable_rows) != 1 else "")])
    lines.extend(_render_tree_view(
        roots, vulnerable_rows,
        "Aucun élément vulnérable n'a été établi par les preuves observées dans cette campagne.",
    ))

    inconclusive_rows = [row for row in compact if row["vulnerable"] == "INDETERMINE"]
    lines.extend(["", f"4. ÉLÉMENTS NON CONCLUSIFS — {len(inconclusive_rows)} hôte"
                  + ("s" if len(inconclusive_rows) != 1 else "")])
    lines.extend(_render_tree_view(
        roots, inconclusive_rows,
        "Aucun élément non conclusif : toutes les cibles disposent d'un verdict établi.",
    ))
    return "\n".join(lines) + "\n"


def _historical_compact_rows(details: dict[str, Any]) -> list[dict[str, str]] | None:
    """Render the exact compact contract associated with a stored tool version."""
    match = re.fullmatch(r"0\.(\d+)\.(\d+)", str(details.get("tool_version", "")))
    if not match:
        return None
    minor, patch = int(match.group(1)), int(match.group(2))
    rows = details["rows"]
    if minor == 6 and patch == 0:
        # In 0.6.0 redirect_evaluated combined a physical visit and a PHP
        # conclusion. This marker exists only in the compatibility renderer;
        # current verdicts require redirect_conclusive explicitly.
        return compact_rows([{**row, "_historical_redirect_semantics": True}
                             if row.get("collection_service_key") else row for row in rows])
    if minor == 5 and patch <= 3:
        coverage = "current" if patch == 0 else "campaign"
        return compact_rows(rows, redirect_coverage=coverage, historical_semantics=True)
    if minor == 5 and patch == 4:
        return compact_rows(rows, legacy_cause_order=True)
    if minor == 5 and patch == 5:
        return compact_rows(rows)
    if minor != 4:
        return None
    if patch <= 2:
        return compact_rows(rows, legacy_explanation=True, redirect_coverage="none", historical_semantics=True)
    if patch == 3:
        return compact_rows(rows, include_redirect_destinations=False, redirect_coverage="none", historical_semantics=True)
    if patch in (4, 5):
        return compact_rows(rows, include_redirect_destinations=False, redirect_coverage="legacy", historical_semantics=True)
    if patch == 6:
        return compact_rows(rows, redirect_coverage="legacy", historical_semantics=True)
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


def _collection_identity(value: dict[str, Any]) -> tuple[str, str, str, str]:
    """Keep virtual hosts, pinned addresses, ports and schemes distinct."""
    return (_single_line(value.get("hostname")).lower().rstrip("."),
            _single_line(value.get("ip")), _single_line(value.get("port")),
            _single_line(value.get("scheme")).lower())


def _collection_counter(value: object) -> int:
    if isinstance(value, bool):
        return 0
    try:
        number = int(str(value))
    except (TypeError, ValueError):
        return 0
    return max(0, number)


def _collection_items(parts: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    """Retain every sample, including repeated observations of the same URL."""
    output = []
    for part in parts:
        for item in part.get(field, []):
            if isinstance(item, dict):
                copied = deepcopy(item)
                copied.setdefault("collection_phase", part.get("collection_phase", "base"))
                if field == "observations":
                    copied["managed_collection"] = True
                output.append(copied)
    return output


def _merge_collection_assessments(service: dict[str, Any], parts: list[dict[str, Any]],
                                  jobs: list[dict[str, Any]], gaps: list[dict[str, Any]],
                                  campaign_id: str, observed_at: str) -> dict[str, Any]:
    """Combine managed HTTP phases without manufacturing another service."""
    name, ip, port, scheme = _collection_identity(service)
    observations = _collection_items(parts, "observations")
    evidence = _collection_items(parts, "evidence")
    versions = _unique([version for part in parts for version in _version_values(part.get("versions"))])
    fixed = _unique([version for part in parts for version in _version_values(part.get("fixed_versions"))])
    suspect = any(_suspect(part) for part in parts)
    conflict = len(versions) > 1 or any(part.get("reason_code") == "CONFLICTING_VERSIONS" for part in parts)
    if conflict:
        state, reason_code = "UNKNOWN", "CONFLICTING_VERSIONS"
        reason = "Versions PHP publiées contradictoires ; toutes les preuves sont conservées."
    elif suspect and versions:
        state, reason_code = "POTENTIALLY_VULNERABLE", "AFFECTED_VERSION_ADVERTISED"
        reason = "Version PHP publiée concernée par les CVE recherchées."
    elif versions and any(part.get("state") == "PATCHED_VERSION_ADVERTISED" for part in parts) \
            and not any(part.get("state") == "UNKNOWN" and _version_values(part.get("versions"))
                        and part.get("reason_code") == "UNRECOGNIZED_BUILD" for part in parts):
        state, reason_code = "PATCHED_VERSION_ADVERTISED", "FIXED_VERSION_ADVERTISED"
        reason = "Version PHP publiée corrigée pour les CVE recherchées."
    else:
        state = "UNKNOWN"
        reason_code = ("UNRECOGNIZED_BUILD" if versions else
                       "PHP_VERSION_HIDDEN" if any(part.get("php_detected") == "YES" for part in parts)
                       else "PHP_NOT_IDENTIFIED")
        reason = COMPACT_REASONS.get(reason_code, "Version PHP impossible à établir.")
    latest = parts[-1] if parts else {}
    merged = {
        **{key: value for key, value in latest.items()
           if key not in ("evidence", "observations", "notes")},
        "hostname": name, "ip": ip, "port": port, "protocol": "tcp", "scheme": scheme,
        "service": "ssl/http" if scheme == "https" else "http", "row_type": "ASSESSMENT",
        "state": state, "reason": reason, "reason_code": reason_code,
        "verdict": VERDICTS[state], "priority": PRIORITIES[state], "remediation": REMEDIATIONS[state],
        "verification": VERIFY_RUNTIME, "next_action": VERIFY_RUNTIME,
        "versions": " | ".join(versions), "fixed_versions": " | ".join(fixed),
        "potentially_vulnerable_evidence": suspect,
        "php_detected": "YES" if versions or any(part.get("php_detected") == "YES" for part in parts) else "UNKNOWN",
        "evidence": evidence, "observations": observations,
        "notes": _unique([_single_line(note) for part in parts for note in part.get("notes", [])]),
        "requests_made": str(sum(_collection_counter(part.get("requests_made")) for part in parts)),
        "elapsed_ms": str(sum(_collection_counter(part.get("elapsed_ms")) for part in parts)),
        "campaign_id": campaign_id, "observed_at": str(latest.get("observed_at") or observed_at),
        "source_xml": " | ".join(_unique([str(part.get("source_xml") or "") for part in parts])),
        "exploitability": "NOT_TESTED", "traversal_complete": "true", "budget_exhausted": "false",
        "traversal_reason_code": "", "collection_service_key": str(service.get("service_key", "")),
        "collection_phase": "managed", "collection_parts": [
            {"phase": part.get("collection_phase", "base"), "versions": part.get("versions", ""),
             "requests_made": part.get("requests_made", "0"), "elapsed_ms": part.get("elapsed_ms", "0"),
             "source_xml": part.get("source_xml", "")} for part in parts],
        "collection_jobs": deepcopy(jobs), "collection_gaps": deepcopy(gaps),
        "collection_required_destinations": deepcopy(service.get("required_destinations", [])),
        "collection_redirect_results": deepcopy(service.get("redirect_results", [])),
        "collection_original_reason_code": reason_code,
        "collection_original_state": state,
    }
    # Redirect gaps are reconciled after all services have been merged. Other
    # failed or unfinished planned work remains explicit and cannot be cleared
    # by a reassuring version published on another page.
    for part in parts:
        code = part.get("traversal_reason_code") or part.get("reason_code")
        if _http_gap(part) and code != "REDIRECT_NOT_ASSESSED":
            merged["collection_gaps"].append({"reason_code": str(code or "REQUEST_BUDGET_EXHAUSTED"),
                                               "phase": part.get("collection_phase", "base")})
        if _true(part.get("private_plan_error")):
            merged["collection_gaps"].append({"reason_code": "INPUT_UNAVAILABLE",
                                               "phase": part.get("collection_phase", "base")})
    halted = service.get("halted_reason")
    if halted:
        merged["collection_gaps"].append({"reason_code": str(halted)})
    if not parts:
        merged.update(row_type="COVERAGE", state="NOT_ASSESSED", verdict="ABSENCE D'EVALUATION PHP2SHELL",
                      priority="REVIEW_COVERAGE")
        if not merged["collection_gaps"]:
            merged["collection_gaps"].append({"reason_code": "SCAN_NOT_ATTEMPTED", "phase": "base"})
    return merged


def _collection_observation_conclusive(row: dict[str, Any], observation: dict[str, Any]) -> bool:
    if (observation.get("reason_code") in HTTP_GAP_CODES
            or str(observation.get("http_status", "")) in ("401", "403", "429")
            or not str(observation.get("http_status", "")).isdigit()):
        return False
    if row.get("inventory_patch_status") in ("PATCH_CONFIRMED", "PATCH_MISSING_CONFIRMED"):
        return True
    return ((row.get("collection_original_state", row.get("state"))
             in ("POTENTIALLY_VULNERABLE", "PATCHED_VERSION_ADVERTISED") or _suspect(row))
            and bool(_version_values(row.get("versions"))))


def _reconcile_collection_gaps(rows: list[dict[str, Any]]) -> None:
    """Resolve exact managed redirects with their pinned destination addresses."""
    managed = [row for row in rows if row.get("collection_service_key")]
    index: dict[tuple[str, str], list[tuple[dict[str, Any], dict[str, Any]]]] = {}
    for row in managed:
        for observation in row.get("observations", []):
            identity = str(observation.get("path_identity", ""))
            if identity:
                index.setdefault((identity, row["ip"]), []).append((row, observation))
    destinations: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in managed:
        for destination in row.get("collection_required_destinations", []):
            if not isinstance(destination, dict):
                continue
            key = str(destination.get("source_service_key", "")), str(destination.get("path_identity", ""))
            destinations.setdefault(key, []).append(row)
    edge_cache: dict[int, bool] = {}

    def received(observation):
        status = str(observation.get("http_status", ""))
        return status.isdecimal() and 100 <= int(status) <= 599

    def append_gap(row, reason, path, identity, *, status="", evaluated=False):
        gap = {"reason_code": reason, "path": path, "path_identity": identity,
               "coverage_status": "VISITED_INDETERMINATE" if evaluated else "NOT_VISITED",
               "coverage_scope": "DESTINATION"}
        if status:
            gap["http_status"] = status
        marker = reason, identity, status
        if not any((item.get("reason_code"), item.get("path_identity"), item.get("http_status", "")) == marker
                   for item in row["collection_gaps"]):
            row["collection_gaps"].append(gap)

    def redirect_context(row, observation):
        identity = str(observation.get("redirect_identity", ""))
        matching = destinations.get((row["collection_service_key"], identity), [])
        recorded = [item for item in row.get("collection_redirect_results", [])
                    if isinstance(item, dict) and item.get("redirect_identity") == identity
                    and (not item.get("source_path_identity")
                         or item.get("source_path_identity") == observation.get("path_identity"))]
        addresses = _unique([str(address) for item in recorded for address in item.get("destination_ips", [])]) \
            or _unique([item["ip"] for item in matching]) or [row["ip"]]
        return identity, matching, recorded, addresses

    def request_result(row, observation, visiting):
        status = str(observation.get("http_status", ""))
        if status.isdigit() and 300 <= int(status) < 400 and status != "304":
            conclusive = edge_conclusive(row, observation, visiting)
            return (conclusive, "" if conclusive else observation.get("redirect_coverage_reason")
                    or "REDIRECT_NOT_ASSESSED", observation.get("redirect_coverage_http_status", ""))
        if _collection_observation_conclusive(row, observation):
            return True, "", status
        reason = {"401": "AUTHENTICATION_REQUIRED", "403": "HTTP_ACCESS_DENIED", "429": "RATE_LIMITED"}.get(status)
        if not reason:
            reason = (observation.get("reason_code") or row.get("collection_original_reason_code")
                      or "PHP_NOT_IDENTIFIED") if received(observation) else "NO_HTTP_RESPONSE"
        return False, str(reason), status if received(observation) else ""

    def destination_result(candidates, visiting, fallback_rows=()):
        results = [request_result(candidate, observation, visiting) for candidate, observation in candidates]
        if any(result[0] for result in results):
            return True, "", ""
        if not results:
            gap = next((gap for candidate in fallback_rows for gap in candidate.get("collection_gaps", [])
                        if gap.get("reason_code")), None)
            if gap is not None:
                return False, str(gap["reason_code"]), str(gap.get("http_status", ""))
        # Keep an actionable refusal rather than a generic missing-version
        # cause when repeated observations have different outcomes.
        return next((result for result in results if result[1] in (
            "AUTHENTICATION_REQUIRED", "HTTP_ACCESS_DENIED", "RATE_LIMITED")),
            results[0] if results else (False, "REDIRECT_NOT_ASSESSED", ""))

    def edge_conclusive(row, observation, visiting=frozenset()):
        marker = id(observation)
        if marker in edge_cache:
            return edge_cache[marker]
        if marker in visiting or len(visiting) >= 32:
            observation["redirect_coverage_reason"] = "REDIRECT_LOOP" if marker in visiting else "CHAIN_LIMIT"
            return False
        identity, matching, recorded, addresses = redirect_context(row, observation)
        observation["redirect_destination_ips"] = addresses
        blocked = next((str(item["reason_code"]) for item in recorded
                        if item.get("status") == "UNASSESSED" and item.get("reason_code")), "")
        candidates = {address: index.get((identity, address), []) for address in addresses}
        physical = bool(identity) and all(any(received(item) for _, item in candidates[address])
                                          for address in addresses)
        observation["redirect_evaluated"] = "true" if physical else "false"
        observation["redirect_destination_http_statuses"] = sorted({str(item["http_status"])
            for entries in candidates.values() for _, item in entries if received(item)}, key=int)
        outside = {"OUTSIDE_AUTHORIZED_DOMAINS", "EXCLUDED_BY_OPERATOR", "UNAUTHORIZED_PORT", "NO_PUBLIC_ADDRESS"}
        observation["redirect_scope"] = (blocked if blocked in outside else
            "IN_SCOPE" if recorded or matching else "UNKNOWN")
        outcomes = [destination_result(candidates[address], visiting | {marker},
                                       [candidate for candidate in matching if candidate["ip"] == address])
                    for address in addresses]
        covered = bool(identity) and not blocked \
            and bool(matching or any(candidates.values())) and all(result[0] for result in outcomes)
        edge_cache[marker] = covered
        observation["redirect_conclusive"] = "true" if covered else "false"
        failure = next((result for result in outcomes if not result[0]), (False, "REDIRECT_NOT_ASSESSED", ""))
        observation["redirect_coverage_reason"] = "" if covered else blocked or failure[1]
        observation["redirect_coverage_http_status"] = "" if covered else failure[2]
        return covered

    # Resolve complete navigation chains before deciding whether a 302 that
    # itself advertises PHP covers an upstream necessary destination.
    for row in managed:
        for observation in row.get("observations", []):
            if _redirect_observation_destination(observation):
                edge_conclusive(row, observation)
    for row in managed:
        for destination in row.get("collection_required_destinations", []):
            if not isinstance(destination, dict):
                continue
            identity = str(destination.get("path_identity", ""))
            exact = index.get((identity, row["ip"]), [])
            conclusive, reason, status = destination_result(exact, frozenset(), [row])
            if not conclusive:
                append_gap(row, str(destination.get("reason_code") or reason), destination.get("path", ""),
                           identity, status=status, evaluated=any(received(item) for _, item in exact))
    for row in managed:
        for observation in row.get("observations", []):
            identity = str(observation.get("redirect_identity", ""))
            destination = _redirect_observation_destination(observation)
            if not destination:
                continue
            if not identity:
                row["collection_gaps"].append({"reason_code": "INPUT_UNAVAILABLE"
                    if "[redacted]" in destination else "REDIRECT_NOT_ASSESSED", "path": destination})
                continue
            _, _, recorded, _ = redirect_context(row, observation)
            covered = edge_conclusive(row, observation)
            if not covered:
                code = observation.get("redirect_coverage_reason") or "REDIRECT_NOT_ASSESSED"
                append_gap(row, code, observation.get("redirect_to", ""), identity,
                           status=observation.get("redirect_coverage_http_status", ""),
                           evaluated=_true(observation.get("redirect_evaluated")))
        gaps = row["collection_gaps"]
        if gaps:
            uncertain = any(gap.get("reason_code") == "HTTP_BUDGET_UNCERTAIN" for gap in gaps)
            code = ("HTTP_BUDGET_UNCERTAIN" if uncertain else
                    str(gaps[0].get("reason_code") or "REQUEST_BUDGET_EXHAUSTED"))
            if uncertain:
                row["notes"].append("Quota réservé conservativement après interruption ; consommation exacte inconnue.")
            row["traversal_complete"], row["traversal_reason_code"] = "false", code
            row["budget_exhausted"] = "true" if any(gap.get("reason_code") in (
                "REQUEST_BUDGET_EXHAUSTED", "HTTP_BUDGET_UNCERTAIN")
                and gap.get("coverage_scope") != "DESTINATION" for gap in gaps) else "false"
            row["reason_code"] = code
            row["reason"] = COMPACT_REASONS.get(code, "Contrôle HTTP planifié non terminé.")
        row["redirect_destinations"] = " | ".join(_unassessed_redirect_destinations([row]))
        scopes = {item.get("redirect_scope", "UNKNOWN") for item in row.get("observations", [])
                  if item.get("redirect_to") and not _true(item.get("redirect_evaluated"))}
        row["redirect_evaluation_scope"] = ("HORS_PERIMETRE_DU_CONTROLE" if scopes & {
            "OUTSIDE_AUTHORIZED_DOMAINS", "EXCLUDED_BY_OPERATOR", "UNAUTHORIZED_PORT", "NO_PUBLIC_ADDRESS"}
            else "IN_SCOPE" if "IN_SCOPE" in scopes else "UNKNOWN" if scopes else "")


def merge_collection_rows(rows: list[dict[str, Any]], collection: dict[str, Any], base_dir: Path,
                          campaign_id: str = "", observed_at: str = "") -> list[dict[str, Any]]:
    """Load completed phase artifacts and replace Nmap-only service coverage."""
    if not isinstance(collection, dict) or str(collection.get("schema_version")) != "1" \
            or not isinstance(collection.get("services"), dict):
        raise ReportError("Journal de collecte HTTP invalide.")
    additions = []
    replacements = set()
    assessment_replacements = set()
    for key, service in collection["services"].items():
        if not isinstance(service, dict) or not isinstance(service.get("phase_jobs", []), list):
            raise ReportError("Service du journal HTTP invalide.")
        service = {**service, "service_key": str(key)}
        name, ip, port, scheme = identity = _collection_identity(service)
        if not name or not ip or scheme not in ("http", "https") or not port.isdecimal() \
                or not 1 <= int(port) <= 65535:
            raise ReportError("Identité de service HTTP invalide.")
        jobs, parts, gaps = service.get("phase_jobs", []), [], []
        for job in jobs:
            if not isinstance(job, dict) or job.get("phase") not in ("base", "redirect", "links"):
                raise ReportError("Phase du journal HTTP invalide.")
            if job.get("status") == "REUSED":
                continue
            if job.get("status") != "COMPLETED":
                code = ("REQUEST_BUDGET_EXHAUSTED" if job.get("status") == "BUDGET_EXHAUSTED"
                        else "INPUT_UNAVAILABLE" if job.get("status") == "INPUT_UNAVAILABLE"
                        else "SCAN_INTERRUPTED" if job.get("status") in ("RUNNING", "INTERRUPTED")
                        else "SCAN_FAILED" if job.get("status") == "FAILED" else "SCAN_NOT_ATTEMPTED")
                if job.get("error") == "HTTP_BUDGET_UNCERTAIN":
                    code = "HTTP_BUDGET_UNCERTAIN"
                gaps.append({"reason_code": str(job.get("reason_code") or code),
                             "phase": job["phase"], "job_id": job.get("job_id", "")})
                continue
            try:
                parsed = parse_report(_safe_xml_path(Path(base_dir), job.get("xml")))
                assessments = [part for part in parsed if part.get("row_type") == "ASSESSMENT"
                               and _collection_identity(part) == identity]
                if (len(assessments) != 1 or any(part.get("ip") != ip for part in parsed)
                        or not job.get("imported") and len(parsed) != 1):
                    raise ReportError("Le XML de collecte ne correspond pas au service épinglé.")
            except ReportError:
                gaps.append({"reason_code": "INVALID_SCAN_XML", "phase": job["phase"],
                             "job_id": job.get("job_id", "")})
                continue
            part = assessments[0]
            part.update(collection_phase=job["phase"], source_xml=str(job["xml"]))
            if job.get("imported"):
                for observation in part.get("observations", []):
                    path = _single_line(observation.get("path"))
                    if not observation.get("path_identity") and path.startswith("/") and "[redacted]" not in path:
                        authority = "[" + name + "]" if ":" in name else name
                        observation["path_identity"] = hashlib.sha256(
                            (scheme + "://" + authority + ":" + port + path).encode("utf-8")).hexdigest()
            parts.append(part)
        merged = _merge_collection_assessments(service, parts, jobs, gaps, campaign_id, observed_at)
        additions.append(merged)
        replacements.add((name, ip, port))
        assessment_replacements.add(identity)
    output = [row for row in rows if not (row.get("row_type") == "COVERAGE"
              and row.get("reason_code") == "SERVICE_NOT_ASSESSED"
              and (_single_line(row.get("hostname")).lower().rstrip("."), _single_line(row.get("ip")),
                   _single_line(row.get("port"))) in replacements)
              and not (row.get("row_type") == "ASSESSMENT"
                       and _collection_identity(row) in assessment_replacements)]
    output.extend(additions)
    _reconcile_collection_gaps(output)
    return output


def collection_metrics(rows: list[dict[str, Any]], collection: dict[str, Any],
                       budget_ledger: dict[str, Any] | None = None) -> dict[str, Any]:
    """Count distinct assessed services; phase gains are mutually exclusive."""
    managed = [row for row in rows if row.get("collection_service_key")]
    assessed = [row for row in managed if row.get("observations")]
    counts = Counter()
    for row in assessed:
        parts = row.get("collection_parts", [])
        phases = {str(part.get("phase")) for part in parts if _version_values(part.get("versions"))}
        for phase in ("base", "redirect", "links"):
            if phase in phases:
                counts["services_version_" + phase] += 1
                break
        records = [item for item in row.get("evidence", []) if isinstance(item, dict) and item.get("version")]
        if records and all(item.get("source") == "phpinfo-structured" for item in records):
            counts["services_version_diagnostic_only"] += 1
        if len(_version_values(row.get("versions"))) > 1:
            counts["services_conflicting_versions"] += 1
    for row in managed:
        if _true(row.get("budget_exhausted")) or any(
                gap.get("reason_code") in ("REQUEST_BUDGET_EXHAUSTED", "HTTP_BUDGET_UNCERTAIN")
                and gap.get("coverage_scope") != "DESTINATION"
                for gap in row.get("collection_gaps", [])):
            counts["services_budget_exhausted"] += 1
        for part in row.get("collection_parts", []):
            prefix = "base" if part.get("phase") == "base" else "additional"
            counts[prefix + "_get_requests"] += _collection_counter(part.get("requests_made"))
            counts[prefix + "_elapsed_ms"] += _collection_counter(part.get("elapsed_ms"))
    fields = ("services_version_base", "services_version_redirect", "services_version_links",
              "services_version_diagnostic_only", "services_conflicting_versions", "services_budget_exhausted",
              "base_get_requests", "additional_get_requests", "base_elapsed_ms", "additional_elapsed_ms")
    result = {field: counts[field] for field in fields}
    result.update(services_planned=len(managed), services_assessed=len(assessed),
                  services_with_version=sum(bool(_version_values(row.get("versions"))) for row in assessed),
                  total_get_requests=result["base_get_requests"] + result["additional_get_requests"],
                  total_elapsed_ms=result["base_elapsed_ms"] + result["additional_elapsed_ms"],
                  denominator="Services distincts effectivement observés : nom DNS, IP épinglée, port et protocole HTTP/HTTPS.")
    if isinstance(budget_ledger, dict):
        charged_requests = charged_ms = uncertain_requests = uncertain_ms = 0
        exhausted_keys = {row["collection_service_key"] for row in managed if _true(row.get("budget_exhausted"))}
        uncertain_services = 0
        for row in managed:
            record = budget_ledger.get(row.get("collection_service_key"), {})
            if not isinstance(record, dict):
                continue
            charged_requests += _collection_counter(record.get("charged_requests"))
            charged_ms += _collection_counter(record.get("charged_elapsed_ms"))
            maximum_requests = _collection_counter(record.get("max_requests"))
            maximum_ms = _collection_counter(record.get("budget_ms"))
            if ((maximum_requests and _collection_counter(record.get("charged_requests")) >= maximum_requests)
                    or (maximum_ms and _collection_counter(record.get("charged_elapsed_ms")) >= maximum_ms)):
                exhausted_keys.add(row["collection_service_key"])
            reservations = record.get("reservations", {})
            service_uncertain = False
            if isinstance(reservations, dict):
                for reservation in reservations.values():
                    if isinstance(reservation, dict) and reservation.get("status") == "RESERVED":
                        uncertain_requests += _collection_counter(reservation.get("requests"))
                        uncertain_ms += _collection_counter(reservation.get("budget_ms"))
                        service_uncertain = True
            uncertain_services += service_uncertain
        result.update(charged_get_quota=charged_requests, charged_elapsed_ms=charged_ms,
                      uncertain_get_quota=uncertain_requests, uncertain_elapsed_ms=uncertain_ms,
                      services_budget_uncertain=uncertain_services,
                      services_budget_exhausted=len(exhausted_keys))
    return result


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
    collection = manifest.get("http_collection")
    if collection is not None:
        rows = merge_collection_rows(rows, collection, base_dir, campaign_id, observed_at)
        target_metadata = {target["hostname"]: target for target in manifest["targets"]}
        for row in rows:
            if not row.get("collection_service_key"):
                continue
            target = target_metadata.get(row["hostname"], {})
            endpoint = next((item for item in target.get("endpoints", [])
                             if item.get("ip") == row.get("ip")), {})
            row.update(target_sources=deepcopy(target.get("sources", [])),
                       address_family=endpoint.get("family") or ("ipv6" if ":" in row["ip"] else "ipv4"),
                       scan_ports=endpoint.get("ports") or str(manifest.get("ports") or ""),
                       scan_status=endpoint.get("status") or "")
        evaluated_names.update(row["hostname"] for row in rows if row.get("row_type") == "ASSESSMENT")
        if collection.get("status") not in ("COMPLETED", "SKIPPED"):
            processing_complete = False
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
    if collection is not None:
        summary["collection_metrics"] = collection_metrics(rows, collection, manifest.get("http_services"))
    result = {"schema_version": "1", "tool_version": RENDERER_VERSION,
              "campaign": {key: manifest.get(key) for key in ("campaign_id", "started_at", "finished_at", "status", "profile", "ports", "address_families", "http", "limits", "scope")},
              "generated_at": now.isoformat(), "summary": summary, "rows": rows, "changes": [],
              "excluded_candidates": manifest.get("excluded_candidates", []),
              "limitations": [
                  "La couverture concerne les noms, adresses et ports explicitement traites; elle ne prouve pas l'inventaire des backends.",
                  "Une absence d'evaluation ou de signal reseau ne confirme pas l'application du correctif.",
                  "Les preuves serveur importees restent des attestations dont l'authenticite et l'exhaustivite sont a valider par l'operateur.",
              ]}
    result["campaign"]["scan_tool_version"] = str(manifest.get("tool_version") or "0.3.0")
    if collection is not None:
        result["campaign"]["http_collection"] = {
            "schema_version": collection["schema_version"], "status": collection.get("status", "PARTIAL"),
        }
        result["limitations"].extend(_single_line(item) for item in collection.get("limitations", [])
                                     if isinstance(item, str) and item)
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
    # Companion validation must identify the renderer that actually wrote the
    # compact artifact, even when re-exporting evidence from an older scan.
    report = {**report, "tool_version": RENDERER_VERSION}
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
