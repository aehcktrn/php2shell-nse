"""Crash-safe incremental campaign state with no external dependency."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import threading
from typing import Any

if os.name == "nt":
    import msvcrt
else:
    import fcntl


SCHEMA_VERSION = "1"
MAX_EVENT_BYTES = 64 * 1024 * 1024


class StateError(ValueError):
    """The local campaign state cannot be trusted or exclusively opened."""


class CampaignLock:
    """Hold a non-blocking process lock for one campaign directory."""

    def __init__(self, directory: Path):
        self.path = Path(directory) / ".campaign.lock"
        self.stream = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.stream = self.path.open("a+", encoding="ascii")
        try:
            if os.name == "nt":
                self.stream.seek(0, os.SEEK_END)
                if self.stream.tell() == 0:
                    self.stream.write("0")
                    self.stream.flush()
                self.stream.seek(0)
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError) as exc:
            self.stream.close()
            self.stream = None
            raise StateError("Cette campagne est déjà ouverte par un autre processus.") from exc
        self.stream.seek(0)
        self.stream.truncate()
        self.stream.write(str(os.getpid()) + "\n")
        self.stream.flush()

    def release(self) -> None:
        if self.stream is None:
            return
        try:
            if os.name == "nt":
                self.stream.seek(0)
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_UN)
        finally:
            self.stream.close()
            self.stream = None

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *_exc):
        self.release()

    def __del__(self):
        self.release()


class EventLedger:
    """Append small durable transitions and replay them over a manifest snapshot."""

    def __init__(self, directory: Path):
        self.path = Path(directory) / "state" / "events.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.bytes_written = 0
        self.events_written = 0

    def append(self, kind: str, key: str, value: dict[str, Any]) -> None:
        if kind not in ("dns", "endpoint", "discovery") or not isinstance(key, str) or not key:
            raise StateError("Événement de campagne invalide.")
        record = {"schema_version": SCHEMA_VERSION, "kind": kind, "key": key,
                  "value": value}
        encoded = (json.dumps(record, ensure_ascii=False, separators=(",", ":"),
                              allow_nan=False) + "\n").encode("utf-8")
        if len(encoded) > MAX_EVENT_BYTES:
            raise StateError("Événement de campagne trop volumineux.")
        with self._lock:
            descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                remaining = memoryview(encoded)
                while remaining:
                    written = os.write(descriptor, remaining)
                    if written <= 0:
                        raise OSError("écriture incomplète du journal")
                    remaining = remaining[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            self.bytes_written += len(encoded)
            self.events_written += 1

    def replay(self, manifest: dict[str, Any]) -> dict[str, Any]:
        result = copy.deepcopy(manifest)
        if not self.path.exists():
            return result
        targets = {target.get("hostname"): target for target in result.get("targets", [])
                   if isinstance(target, dict)}
        endpoints = {endpoint.get("task_id"): endpoint
                     for target in targets.values()
                     for endpoint in target.get("endpoints", [])
                     if isinstance(endpoint, dict) and endpoint.get("task_id")}
        discovery_events: dict[str, dict[str, Any]] = {}
        try:
            with self.path.open("rb") as stream:
                size = self.path.stat().st_size
                for raw in stream:
                    if len(raw) > MAX_EVENT_BYTES:
                        raise StateError("Événement de campagne trop volumineux.")
                    try:
                        event = json.loads(raw)
                    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
                        # A power loss can leave only the final append incomplete.
                        if stream.tell() == size and not raw.endswith(b"\n"):
                            break
                        raise StateError("Journal de campagne invalide.") from exc
                    if (not isinstance(event, dict) or event.get("schema_version") != SCHEMA_VERSION
                            or event.get("kind") not in ("dns", "endpoint", "discovery")
                            or not isinstance(event.get("key"), str)
                            or not isinstance(event.get("value"), dict)):
                        raise StateError("Journal de campagne invalide.")
                    kind, key, value = event["kind"], event["key"], event["value"]
                    if kind == "dns":
                        if key not in targets:
                            raise StateError("Événement DNS sans cible dans le manifeste.")
                        targets[key].update(value)
                    elif kind == "endpoint":
                        if key not in endpoints:
                            raise StateError("Événement endpoint sans tâche dans le manifeste.")
                        endpoints[key].update(value)
                    else:
                        if key not in result.get("discovery", {}).get("roots", []):
                            raise StateError("Événement de découverte hors du manifeste.")
                        discovery_events[key] = value
        except OSError as exc:
            raise StateError(f"Impossible de lire l'état incrémental: {exc}") from exc
        if discovery_events and isinstance(result.get("discovery"), dict):
            discovery = result["discovery"]
            query_order = list(discovery.get("roots", []))
            queries = []
            names: dict[str, list[str]] = {}
            for root in query_order:
                value = discovery_events.get(root)
                if value is None:
                    continue
                query = value.get("query")
                candidates = value.get("candidates", [])
                if (not isinstance(query, dict) or query.get("root") != root
                        or not isinstance(candidates, list)):
                    raise StateError("État de découverte invalide.")
                queries.append(query)
                source = "crt.sh:" + root
                for name in candidates:
                    if not isinstance(name, str):
                        raise StateError("Candidat de découverte invalide.")
                    names.setdefault(name, []).append(source)
            discovery["queries"] = queries
            discovery["candidates"] = [
                {"hostname": name, "sources": list(dict.fromkeys(sources))}
                for name, sources in sorted(names.items())
            ]
            discovery["candidates_count"] = len(names)
        return result
