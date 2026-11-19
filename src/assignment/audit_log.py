"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations
import time

from agents.security_boundary import contains_secret
from guardrails.output_guardrails import content_filter

import json
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")

def safe_log_text(text: str) -> str:
    redacted = content_filter(text)["redacted"]
    return "[REDACTED]" if contains_secret(redacted) else redacted

class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, tuple[float, str, str]] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        self._open[request_id or user_id] = (
            time.monotonic(),
            utc_now_iso(),
            safe_log_text(text),
        )

    
    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        key = request_id or user_id
        now = time.monotonic()
        started, timestamp, question = self._open.pop(
            key, (now, utc_now_iso(), "")
        )
        self.logs.append({
            "request_id": key,
            "user_id": user_id,
            "timestamp": timestamp,
            "input": question,
            "output": safe_log_text(text),
            "blocked": blocked,
            "layer": layer,
            "latency_ms": round((now - started) * 1000, 2),
        })

    def export_json(self, filepath: str | None = None):
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
