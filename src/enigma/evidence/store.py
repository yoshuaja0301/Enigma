"""Evidence store.

Keeps collected evidence in memory and, optionally, persists each artifact as a
sanitized JSON file. Only sanitized evidence ever reaches the store.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional, Union

from .collector import Evidence


class EvidenceStore:
    def __init__(self, directory: Optional[Union[str, Path]] = None) -> None:
        self._directory = Path(directory) if directory else None
        if self._directory is not None:
            self._directory.mkdir(parents=True, exist_ok=True)
        self._items: Dict[str, Evidence] = {}

    def save(self, evidence: Evidence) -> Optional[Path]:
        self._items[evidence.evidence_id] = evidence
        if self._directory is None:
            return None
        path = self._directory / f"{evidence.evidence_id}.json"
        with path.open("w", encoding="utf-8") as handle:
            json.dump(evidence.to_dict(), handle, indent=2, ensure_ascii=False)
        return path

    def get(self, evidence_id: str) -> Optional[Evidence]:
        return self._items.get(evidence_id)

    def all(self) -> List[Evidence]:
        return list(self._items.values())
