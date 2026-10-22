#!/usr/bin/env python3
"""Convert a completed Nmap PHP2Shell XML scan into an actionable CSV report.

This program only reads a local XML file. It does not run Nmap or contact hosts.
Each XML host instance is preserved, including virtual hosts sharing an IP.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import os
from pathlib import Path
import sys
import tempfile
import unicodedata
import xml.etree.ElementTree as ET


FIELDS = (
    "row_type", "ip", "hostname", "port", "protocol", "service", "state",
    "verdict", "versions", "fixed_versions", "priority", "remediation",
    "verification", "http_status", "reason",
)
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
    """The input does not establish a completed, usable Nmap scan."""


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
            "protocol": port.get("protocol", ""), "service": name}


def _assessment(script: ET.Element) -> dict[str, str]:
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
    values = {
        "row_type": "ASSESSMENT", "state": state,
        "verdict": _scalar(script, "verdict") or VERDICTS[state],
        "versions": " | ".join(_unique(versions)),
        "fixed_versions": " | ".join(_unique(fixed_versions)),
        "priority": priority, "remediation": remediation,
        "verification": _scalar(script, "verification") or VERIFY_RUNTIME,
        "http_status": _scalar(script, "http_status"), "reason": reason,
    }
    vhost = _scalar(script, "vhost")
    if vhost:
        # The explicit Host/SNI name is the application actually assessed. The
        # original target name is still retained in the source Nmap XML.
        values["hostname"] = vhost
    return values


def _coverage(reason: str) -> dict[str, str]:
    return {
        "row_type": "COVERAGE", "state": "NOT_ASSESSED",
        "verdict": "ABSENCE D'EVALUATION PHP2SHELL", "priority": "REVIEW_COVERAGE",
        "remediation": "Verifier la couverture du scan et qualifier le service si necessaire.",
        "verification": (
            "Cette ligne ne prouve ni presence de PHP, ni vulnerabilite, ni correction. "
            "Un service non web peut normalement ne pas etre evalue par ce NSE."
        ),
        "reason": reason,
    }


def parse_report(source: Path) -> list[dict[str, str]]:
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
            rows.append({**host_identity, **_port_identity(port), **values})
        if len(rows) == before:
            host_status = host.find("status")
            status = host_status.get("state", "unknown") if host_status is not None else "unknown"
            reason = (
                "Aucun port TCP ouvert represente; statut Nmap de l'hote: " + status
                + ". Un hote filtre, non joignable ou non teste n'est pas declare corrige."
            )
            rows.append({**host_identity, **_coverage(reason)})
    return rows


def safe_cell(value: object) -> str:
    """Prevent CSV formula execution, including whitespace/control prefixes."""
    text = str(value) if value is not None else ""
    index = 0
    while index < len(text) and (text[index].isspace() or unicodedata.category(text[index]).startswith("C")):
        index += 1
    leading_control = bool(text) and unicodedata.category(text[0]).startswith("C")
    dangerous = index < len(text) and text[index] in "=+-@"
    return "'" + text if leading_control or dangerous else text


def write_report(rows: list[dict[str, str]], destination: Path, source: Path) -> None:
    """Atomically write UTF-8 CSV without replacing the input XML."""
    if destination.resolve() == source.resolve() or (
        destination.exists() and source.exists() and os.path.samefile(destination, source)
    ):
        raise ReportError("Le fichier de sortie doit etre different du XML source.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="", prefix=".php2shell-report-",
            suffix=".csv", dir=destination.parent, delete=False,
        ) as stream:
            temporary = Path(stream.name)
            writer = csv.DictWriter(stream, fieldnames=FIELDS)
            writer.writeheader()
            for row in rows:
                writer.writerow({key: safe_cell(row.get(key, "")) for key in FIELDS})
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("xml", type=Path, help="XML Nmap d'un scan termine avec succes")
    parser.add_argument("-o", "--output", required=True, type=Path, help="CSV UTF-8 a produire")
    args = parser.parse_args(argv)
    try:
        rows = parse_report(args.xml)
        write_report(rows, args.output, args.xml)
    except (ReportError, OSError) as exc:
        print(f"Erreur: {exc}", file=sys.stderr)
        return 2
    counts = Counter(row["state"] for row in rows if row["row_type"] == "ASSESSMENT")
    print(f"Rapport: {args.output}")
    print(f"Evaluations PHP2Shell: {sum(counts.values())}")
    for state in STATES:
        print(f"  {state}: {counts[state]}")
    print(f"Lignes de couverture sans evaluation: {sum(row['row_type'] == 'COVERAGE' for row in rows)}")
    print("COVERAGE / NOT_ASSESSED ne signifie pas vulnerable et ne signifie pas corrige.")
    print("Chaque entree hote du XML est conservee; les comptes ne sont pas des IP uniques.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
