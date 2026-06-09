from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from findevil.audit.ledger import AuditLedger


class EvidenceVault:
    def __init__(
        self,
        evidence_dir: Path,
        workspace_dir: Path,
        ledger: AuditLedger,
    ) -> None:
        self.evidence_dir = Path(evidence_dir).resolve()
        self.workspace_dir = Path(workspace_dir).resolve()
        self.ledger = ledger
        self.file_hashes: dict[str, str] = {}
        self._initialized = False

    def _hash_file(self, path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def _rel_path(self, path: Path) -> str:
        return str(path.relative_to(self.evidence_dir))

    def initialize(self) -> None:
        if not self.evidence_dir.exists():
            raise FileNotFoundError(f"Evidence directory not found: {self.evidence_dir}")
        self.workspace_dir.mkdir(parents=True, exist_ok=True)

        for path in sorted(self.evidence_dir.rglob("*")):
            if path.is_file():
                file_hash = self._hash_file(path)
                rel_name = self._rel_path(path)
                self.file_hashes[rel_name] = file_hash
                self.ledger.append("evidence_hash", {
                    "file": rel_name,
                    "path": str(path),
                    "hash": file_hash,
                    "size": path.stat().st_size,
                })

        self._initialized = True
        self.ledger.append("case_event", {
            "action": "vault_initialized",
            "evidence_count": len(self.file_hashes),
        })

    def verify_integrity(self) -> bool:
        for path in self.evidence_dir.rglob("*"):
            if path.is_file():
                current_hash = self._hash_file(path)
                rel = self._rel_path(path)
                if self.file_hashes.get(rel) != current_hash:
                    return False
        return True

    def list_files(self) -> list[dict[str, Any]]:
        files = []
        for path in sorted(self.evidence_dir.rglob("*")):
            if path.is_file():
                rel = self._rel_path(path)
                files.append({
                    "name": path.name,
                    "path": str(path),
                    "size": path.stat().st_size,
                    "hash": self.file_hashes.get(rel, "unknown"),
                })
        return files

    def is_path_allowed(self, path: str) -> bool:
        # Reject paths containing traversal components before resolving
        if ".." in Path(path).parts:
            return False
        resolved = Path(path).resolve()
        # Allow paths under the actual evidence/workspace directories
        if str(resolved).startswith(str(self.evidence_dir)) or str(resolved).startswith(
            str(self.workspace_dir)
        ):
            return True
        # Allow paths under the conventional /evidence mount point
        norm = str(resolved)
        if norm.startswith("/evidence/") or norm == "/evidence":
            return True
        return False
